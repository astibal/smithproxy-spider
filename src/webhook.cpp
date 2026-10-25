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
        const auto cutoff = decisions.heavy_traffic.observe(event.value("id", ""), size, managed);
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
            event["decision"] = {{"state", "backend-inspected"}, {"mode", "inspect"}};
        }
    }
    if (event.value("decision", nlohmann::json::object()).value("state", "") != "forgotten") {
        store.apply(event, raw_payload, enrichments);
    }
    if (action == "access-request") return {200, {{"access-response", "accept"}}};
    if (!script_result.is_null()) {
        if (script_result.value("ok", false) && script_result.value("need_more", false))
            return {200, {{"action", "need-more"}}};
        if (script_result.value("ok", false) && !script_result.value("replacement", nlohmann::json(nullptr)).is_null())
            return {200, {{"action", "replace"}, {"content", script_result["replacement"]}}};
        return {200, {{"action", "unchanged"}}};
    }
    if (action == "connection-content") return decisions.wait(ticket, event);
    return {200, nlohmann::json::object()};
}

} // namespace spider
