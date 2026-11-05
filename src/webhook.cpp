#include "webhook.hpp"

#include "decision_broker.hpp"
#include "enrichment.hpp"
#include "inspection.hpp"
#include "session_store.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace spider {
namespace {
std::optional<std::string> decode_content(const std::string& content) {
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (content.size() % 4) return std::nullopt;
    std::string decoded;
    for (std::size_t i = 0; i < content.size(); i += 4) {
        unsigned int value = 0;
        int padding = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const char ch = content[i + j];
            value <<= 6;
            if (ch == '=') {
                if (j < 2 || i + 4 != content.size()) return std::nullopt;
                ++padding;
            } else {
                const auto digit = alphabet.find(ch);
                if (padding || digit == std::string_view::npos) return std::nullopt;
                value |= static_cast<unsigned int>(digit);
            }
        }
        decoded += static_cast<char>((value >> 16) & 255);
        if (padding < 2) decoded += static_cast<char>((value >> 8) & 255);
        if (padding < 1) decoded += static_cast<char>(value & 255);
    }
    return decoded;
}
}

WebhookReply process_webhook(SessionStore& store, DecisionBroker& decisions,
                             const nlohmann::json& original_event,
                             std::optional<std::string_view> raw_payload,
                             EnrichmentEngine* enrichment, Inspection* inspection) {
    auto event = original_event;
    if (!event.is_object()) return {400, {{"error", "JSON object required"}}};

    const auto action = event.value("action", "");
    if(action == "tls-lifecycle") {
        // TLS events follow the same pinned setup ownership as TCP.
        try {
            const auto& observation = event.at("details").at("tls");
            const auto& envelope = observation.at("envelope");
            const auto id = event.at("id").get<std::string>();
            const auto phase = envelope.at("event").get<std::string>();
            const auto side = envelope.at("side").get<std::string>();
            const auto observation_limit = (phase == "client-hello" ? 512 : 256) * 1024;

            if(id.empty() || id.size() > 1024 || envelope.size() != 5 ||
               !envelope.at("version").is_number_integer() || envelope.at("version") != 1 ||
               envelope.at("connection_id") != id ||
               !envelope.at("attempt").is_number_unsigned() || envelope.at("attempt") == 0 ||
               (phase != "established" && phase != "failed" && phase != "client-hello" && phase != "start") ||
               (phase == "client-hello" && side != "client") ||
               (side != "client" && side != "server") || observation.dump().size() > observation_limit) {
                return {400, {{"error", "Invalid TLS observation"}}};
            }

            const auto decision = inspection ? inspection->tls_lifecycle(event) : nlohmann::json(nullptr);
            if(decision.is_null()) {
                return {503, {{"error", "TLS callback unavailable"}}};
            }

            nlohmann::json reply = {
                {"action", action},
                {"id", id},
                {"envelope", envelope},
                {"proceed", decision.at("proceed")}
            };
            if(phase == "client-hello") {
                reply["ignore_connection"] = decision.at("ignore_connection");
            }
            if((phase == "client-hello" || phase == "start") && decision.contains("upstream")) {
                reply["upstream"] = decision["upstream"];
            }

            return {200, std::move(reply)};
        } catch(const nlohmann::json::exception&) {
            return {400, {{"error", "Invalid TLS observation"}}};
        }
    }

    if(action == "server-lifecycle") {
        // Ordered transport observations are transient; dispatch only to addon
        // generations that already own the connection's setup.
        try {
            const auto& observation = event.at("details").at("server");
            const auto& envelope = observation.at("envelope");
            const auto id = event.at("id").get<std::string>();
            const auto phase = envelope.at("event").get<std::string>();
            if(id.empty() || id.size() > 1024 || envelope.size() != 4 ||
               !envelope.at("version").is_number_integer() || envelope.at("version") != 1 ||
               envelope.at("connection_id") != id ||
               !envelope.at("attempt").is_number_unsigned() || envelope.at("attempt") == 0 ||
               (phase != "connect" && phase != "connected" && phase != "error" && phase != "disconnected") ||
               observation.dump().size() > 8192) {
                return {400, {{"error", "Invalid server observation"}}};
            }

            const auto decision = inspection ? inspection->server_lifecycle(event) : nlohmann::json(nullptr);
            if(decision.is_null()) {
                return {503, {{"error", "Server callback unavailable"}}};
            }

            return {200, {
                {"action", action},
                {"id", id},
                {"envelope", envelope},
                {"proceed", decision.at("proceed")}
            }};
        } catch(const nlohmann::json::exception&) {
            return {400, {{"error", "Invalid server observation"}}};
        }
    }

    if(action == "http-connect") {
        // CONNECT is a transient decision exchange. In particular, rejected
        // Proxy-Authorization headers must never enter capture or GUI history.
        try {
            const auto& observation = event.at("details").at("http_connect");
            const auto& envelope = observation.at("envelope");
            const auto id = event.at("id").get<std::string>();
            const auto phase = envelope.at("event").get<std::string>();

            const bool valid = !id.empty() && id.size() <= 1024 && envelope.size() == 6 &&
                envelope.at("version").is_number_integer() && envelope["version"] == 1 &&
                envelope.at("delivery") == "http-connect" && envelope.at("connection_id") == id &&
                envelope.at("exchange_id").is_number_integer() && envelope["exchange_id"] == 1 &&
                envelope.at("mode") == "regular" &&
                (phase == "request" || phase == "connected" || phase == "error" || phase == "abort");

            if(!valid || observation.dump().size() > 370 * 1024) {
                return {400, {{"error", "Invalid CONNECT observation"}}};
            }

            if(phase == "request") {
                const auto& raw = observation.at("request_base64");
                if(!raw.is_string() || raw.get_ref<const std::string&>().size() > 10924)
                    return {400, {{"error", "Invalid CONNECT request"}}};
            }

            // Reuse setup rule selection without publishing a fake setup or
            // asking the GUI for a payload decision. Pinning happens below.
            auto selection = event;
            selection["action"] = "connection-start";
            (void)decisions.prepare(selection);
            event["traffic_rule"] = selection.value("traffic_rule", nlohmann::json::object());
            event["decision"] = selection.value("decision", nlohmann::json::object());

            auto decision = inspection ? inspection->http_connect(event) : nlohmann::json(nullptr);
            if(decision.is_null())
                return {503, {{"error", "CONNECT callback unavailable"}}};

            // Echo the original identity so the producer can reject stale replies.
            return {200, {
                {"action", action},
                {"id", id},
                {"envelope", envelope},
                {"decision", std::move(decision)}
            }};
        } catch(const nlohmann::json::exception&) {
            return {400, {{"error", "Invalid CONNECT observation"}}};
        }
    }

    if (action == "proxy-authentication") {
        // This is a transient control exchange, not a captured connection event.
        // Reject malformed metadata before any script sees credentials.
        try {
            const auto& auth = event.at("details").at("authentication");
            const auto text = [](const nlohmann::json& value, std::size_t maximum) {
                return value.is_string() && value.get_ref<const std::string&>().size() <= maximum &&
                       value.get_ref<const std::string&>().find('\0') == std::string::npos;
            };
            const bool valid_metadata = text(event.at("id"), 128) && event["id"] != "" &&
                auth.at("version").is_number_integer() && auth["version"] == 1 &&
                (auth.at("protocol") == "http-connect" || auth["protocol"] == "socks5") &&
                (auth.at("status") == "accepted" || auth["status"] == "rejected" || auth["status"] == "unavailable");
            const bool valid_identity = text(auth.at("username"), 255) &&
                text(auth.at("password"), 1024) && text(auth.at("identity"), 512) &&
                auth.at("groups").is_array() && auth["groups"].size() <= 64;
            const bool valid_peer = text(auth.at("peer").at("host"), 255) &&
                                    text(auth.at("peer").at("port"), 5);
            if (!valid_metadata || !valid_identity || !valid_peer) {
                return {400, {{"error", "Invalid authentication event"}}};
            }

            // CONNECT context is optional for older native-only producers.
            // Addon execution requires it; reject malformed supplied context here.
            if (auth.contains("http_connect")) {
                const auto& context = auth["http_connect"];
                if (auth["protocol"] != "http-connect" ||
                    !text(context.at("host"), 255) || context["host"] == "" ||
                    !context.at("port").is_number_integer() ||
                    context["port"] < 1 || context["port"] > 65535 ||
                    !text(context.at("request_base64"), 10924)) {
                    return {400, {{"error", "Invalid CONNECT authentication context"}}};
                }
            }

            for (const auto& group : auth["groups"]) {
                if (!text(group, 255)) return {400, {{"error", "Invalid authentication group"}}};
            }

            const bool allowed = inspection && inspection->authenticate(event);
            return {200, {{"action", action}, {"id", event["id"]}, {"version", 1},
                          {"decision", allowed ? "accept" : "reject"}}};
        } catch (const nlohmann::json::exception&) {
            return {400, {{"error", "Invalid authentication event"}}};
        }
    }

    constexpr std::array<std::string_view, 9> supported{
        "access-request", "connection-content", "connection-start", "connection-stop",
        "connection-info", "hostname-info", "info", "neighbor", "ping",
    };
    if (std::find(supported.begin(), supported.end(), action) == supported.end()) {
        return {422, {{"error", "unsupported action"}}};
    }

    if (action == "info") {
        return {200, {{"action", "info-response"},
                      {"protocols", {{"connection-content", {"sxbn-001"}}}}}};
    }
    const auto ticket = decisions.prepare(event);
    decisions.observe(event);
    if (action == "connection-stop" || action == "connection-start") decisions.heavy_traffic.stop(event.value("id", ""));
    if (action == "connection-content") {
        const auto& info = event["details"]["info"];
        std::size_t size = raw_payload ? raw_payload->size() : 0;
        if (!raw_payload && info.contains("content") && info["content"].is_string()) {
            const auto& encoded = info["content"].get_ref<const std::string&>();
            size = encoded.size() / 4 * 3;
            if (size && encoded.ends_with("=")) --size;
            if (size && encoded.ends_with("==")) --size;
        }
        const bool managed = event.contains("collections") ||
            event.value("traffic_rule", nlohmann::json::object()).value("mode", "") == "inspect" ||
            (inspection && inspection->has_enabled_scripts());
        const auto cutoff = inspection && inspection->translation_required(event) ? nlohmann::json(nullptr) :
            decisions.heavy_traffic.observe(event.value("id", ""), size, managed);
        if (!cutoff.is_null()) {
            if (ticket) {
                decisions.handle_message({{"type", "decision"}, {"decision_id", ticket->id}, {"action", "accept"}});
                (void)decisions.wait(ticket, event);
            }
            if (cutoff["first"].get<bool>()) {
                event["action"] = "connection-info";
                event["details"]["info"].erase("content");
                event["heavy_traffic"] = cutoff["notice"];
                event["decision"] = {{"state", "forgotten"}, {"reason", "heavy-traffic"}};
                store.apply(event);
            }
            return {200, {{"action", "not-interested"}}};
        }
    }
    if (raw_payload && action == "connection-content") event["details"]["info"]["content"] = base64_encode(*raw_payload);
    std::optional<std::string> decoded_content;
    if (!raw_payload && action == "connection-content") {
        const auto info = event.value("details", nlohmann::json::object()).value("info", nlohmann::json::object());
        if (info.contains("content") && info["content"].is_string()) {
            decoded_content = decode_content(info["content"].get<std::string>());
            if (decoded_content) raw_payload = *decoded_content;
        }
    }
    if (enrichment) enrichment->observe(event);
    const auto enrichments = enrichment && raw_payload
        ? enrichment->process(event, *raw_payload) : std::vector<SxbnEnvelope>{};
    auto script_result = nlohmann::json(nullptr);
    if (inspection) {
        auto inputs = nlohmann::json::array();
        for (const auto& item : enrichments) inputs.push_back({{"metadata", item.metadata}, {"content", base64_encode(item.payload)}});
        if (event.contains("collections")) {
            auto snapshot = event;
            if (raw_payload) snapshot["details"]["info"]["content"] = base64_encode(*raw_payload);
            auto context = store.session_detail(event.value("id", "")).value_or(nlohmann::json::object());
            context["hostname_context"] = nlohmann::json::object();
            const auto reverse = store.reverse_hostnames();
            const auto mappings = reverse.value("mappings", nlohmann::json::object());
            for (const auto& [address, mapping] : mappings.items()) {
                std::string error;
                const auto filter = SessionFilter::compile("host " + address, error);
                if (filter && filter->matches(event)) context["hostname_context"][address] = mapping;
            }
            inspection->collection.capture(snapshot, inputs, context);
        }
        script_result = inspection->automatic(event, inputs);
        if (!script_result.is_null()) {
            if (ticket) {
                decisions.handle_message({{"type", "decision"}, {"decision_id", ticket->id}, {"action", "accept"}});
                (void)decisions.wait(ticket, event);
            }
            event["inspection"] = script_result;
            event["inspection"].erase("replacement");
            event["inspection"].erase("replacement_reverse");
            event["inspection"].erase("connection_close");
            event["decision"] = {{"state", "backend-inspected"}, {"mode", "inspect"}};
        }
    }
    if (event.value("decision", nlohmann::json::object()).value("state", "") != "forgotten") {
        store.apply(event, raw_payload, enrichments);
    }
    if (action == "access-request") return {200, {{"access-response", "accept"}}};
    if (!script_result.is_null()) {
        if (action == "connection-start") {
            const bool rewrite = script_result.value("ok", false) &&
                                 script_result.value("rewrite_requested", false);
            nlohmann::json control = {{"rewrite", rewrite}};
            if(script_result.value("ok", false) && script_result.value("server_lifecycle", false)) {
                control["server_lifecycle"] = 1;
            }
            if(script_result.value("ok", false) && script_result.value("tls_lifecycle", false)) {
                control["tls_lifecycle"] = 1;
            }
            if(script_result.value("ok", false) && script_result.value("tls_start_server", false)) {
                control["tls_start_server"] = 1;
            }
            if(script_result.value("ok", false) && script_result.value("tls_start_client", false)) {
                control["tls_start_client"] = 1;
            }
            if(script_result.value("ok", false) && script_result.value("tls_clienthello", false)) {
                control["tls_clienthello"] = 1;
            }

            return {200, {{"action", "accept"}, {"control", std::move(control)}}};
        }

        if (script_result.value("translate_failed", false))
            return {503, {{"error", "Translate callback failed; strict connection must close"}}};
        if (script_result.value("ok", false) &&
            script_result.contains("connection_close")) {
            const auto& terminal = script_result["connection_close"];
            const auto control = event.value("details", nlohmann::json::object())
                .value("info", nlohmann::json::object())
                .value("webhook_control", nlohmann::json::object());
            const auto capability = control.find("connection-close");
            if (!terminal.is_object() || !terminal.contains("reason") ||
                !terminal["reason"].is_string() ||
                capability == control.end() || !capability->is_boolean() ||
                !capability->get<bool>()) {
                return {503, {{"error", "Invalid callback-local connection close"}}};
            }
            return {200, {
                {"action", "close"},
                {"control", {{"mode", "strict"}}},
                {"reason", terminal["reason"]},
            }};
        }
        if (script_result.value("translated", false) && script_result.value("ok", false)) {
            if (script_result.value("need_more", false))
                return {200, {{"action", "need-more"}, {"control", {{"mode", "strict"}}}}};

            nlohmann::json reply = {{"action", "replace"}, {"content", script_result["replacement"]},
                                    {"control", {{"mode", "strict"}}}};
            if (script_result.contains("replacement_reverse"))
                reply["content-reverse"] = script_result["replacement_reverse"];
            return {200, std::move(reply)};
        }
        if (script_result.value("ok", false) && script_result.value("need_more", false))
            return {200, {{"action", "need-more"}}};
        if (script_result.value("ok", false) && !script_result.value("replacement", nlohmann::json(nullptr)).is_null()) {
            // H1 commit can publish a resumed peer lane without H2 Translate.
            // Keep both native outputs in the same directional replacement.
            nlohmann::json reply = {{"action", "replace"}, {"content", script_result["replacement"]}};
            if (script_result.contains("replacement_reverse")) {
                reply["content-reverse"] = script_result["replacement_reverse"];
            }
            return {200, std::move(reply)};
        }
        return {200, {{"action", "unchanged"}}};
    }
    if (action == "connection-content") return decisions.wait(ticket, event);
    return {200, nlohmann::json::object()};
}

} // namespace spider
