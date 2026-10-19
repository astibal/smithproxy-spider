#include "http_server.hpp"

#include "decision_broker.hpp"
#include "enrichment.hpp"
#include "session_store.hpp"
#include "smithproxy_manager.hpp"
#include "webhook.hpp"
#include "binary_envelope.hpp"
#include "websocket_hub.hpp"

#include <lmhttpd.hpp>
#include <microhttpd.h>
#include <nlohmann/json.hpp>

#include <charconv>
#include <cstring>
#include <memory>
#include <string_view>
#include <chrono>

namespace spider {
namespace {

struct RequestState final : lmh::ConnectionState {
    explicit RequestState(lmh::Controller& controller) : ConnectionState(controller) {}
    bool too_large{};
};

bool constant_time_equal(const std::string_view lhs, const std::string_view rhs) {
    const auto max_size = std::max(lhs.size(), rhs.size());
    unsigned char difference = static_cast<unsigned char>(lhs.size() ^ rhs.size());
    for (std::size_t i = 0; i < max_size; ++i) {
        const auto a = i < lhs.size() ? static_cast<unsigned char>(lhs[i]) : 0U;
        const auto b = i < rhs.size() ? static_cast<unsigned char>(rhs[i]) : 0U;
        difference = static_cast<unsigned char>(difference | (a ^ b));
    }
    return difference == 0;
}

class SpiderController final : public lmh::Controller {
public:
    SpiderController(const ServerConfig& config, SessionStore& store, SmithproxyManager& smithproxy,
                     DecisionBroker& decisions, EnrichmentEngine& enrichment,
                     WebSocketHub& websocket)
        : config_(config), store_(store), smithproxy_(smithproxy), decisions_(decisions),
          enrichment_(enrichment), websocket_(websocket) {}

    bool validPath(const char* path, const char* method) override {
        const std::string_view p(path);
        const std::string_view m(method);
        return (m == "GET" && (p == "/" || p == "/api/health" || p == "/api/ready" ||
                               p == "/api/status" || p == "/api/sessions" ||
                               p == "/api/diagnostics" ||
                               p == "/api/hostnames" ||
                               p == "/api/session-history" || p == "/api/session" ||
                               p == "/api/events" || p == "/api/events/ws")) ||
               (m == "OPTIONS" && p.starts_with("/api/")) ||
               (m == "DELETE" && p == "/api/session-history") ||
               (m == "POST" && p == "/api/config/smithproxy") ||
               (m == "POST" && p == callback_path());
    }

    lmh::ConnectionState* create_state() override { return new RequestState(*this); }

    int handleRequest(MHD_Connection* connection, const char* url, const char* method,
                      const char* upload_data, std::size_t* upload_data_size, void** ptr) override {
        if (*ptr == nullptr) {
            *ptr = create_state();
            return MHD_YES;
        }
        auto& state = *static_cast<RequestState*>(*ptr);

        if (*upload_data_size > 0) {
            if (state.request_data.size() + *upload_data_size > config_.max_body_bytes) {
                state.too_large = true;
            } else if (!state.too_large) {
                state.request_data.append(upload_data, *upload_data_size);
            }
            *upload_data_size = 0;
            return MHD_YES;
        }

        if (state.response_sent) return MHD_YES;
        ++requests_total_;
        last_request_at_ms_.store(unix_time_ms(), std::memory_order_relaxed);
        if (std::string_view(method) == "GET" && std::string_view(url) == "/api/events/ws") {
            state.response_sent = true;
            return websocket_.queue_upgrade(connection);
        }
        Response response;
        if (state.too_large) {
            response = json_response(413, {{"error", "request body too large"}});
        } else {
            response = route(connection, url, method, state.request_data);
        }
        response_bytes_.fetch_add(response.body.size(), std::memory_order_relaxed);
        if (std::string_view(method) == "POST" && std::string_view(url) == callback_path()) {
            ++callback_requests_;
            callback_bytes_.fetch_add(state.request_data.size(), std::memory_order_relaxed);
            if (response.status >= 400) ++callback_errors_;
        }
        return send(connection, state, std::move(response));
    }

private:
    struct Response {
        unsigned status{200};
        std::string type{"application/json"};
        std::string body;
    };

    static Response json_response(const unsigned status, const nlohmann::json& body) {
        return {status, "application/json", body.dump()};
    }

    static std::int64_t unix_time_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    bool authenticated(MHD_Connection* connection) const {
        if (config_.token.empty()) return true;
        const char* supplied = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Spider-Token");
        return supplied != nullptr && constant_time_equal(supplied, config_.token);
    }

    Response route(MHD_Connection* connection, const std::string_view url,
                   const std::string_view method, const std::string& body) {
        if (method == "GET" && url == "/") return json_response(200, {{"service", "smithproxy-spider"}});
        if (method == "OPTIONS") return {204, "text/plain", {}};
        if (method == "GET" && url == "/api/health") {
            return json_response(200, {{"status", "ok"}, {"revision", store_.revision()}});
        }
        // The unguessable callback path is a separate Smithproxy -> Spider
        // credential. Smithproxy cannot attach the browser API header.
        if (method == "POST" && url == callback_path()) {
            try {
                nlohmann::json event;
                std::string raw_payload;
                std::optional<std::string_view> payload_view;
                if (std::string_view(body).starts_with(sxbn_magic)) {
                    std::string error;
                    if (!decode_sxbn(body, event, raw_payload, error)) {
                        return json_response(400, {{"error", error}});
                    }
                    event["details"]["info"]["content"] = base64_encode(raw_payload);
                    payload_view = raw_payload;
                } else {
                    event = nlohmann::json::parse(body);
                }
                const auto reply = process_webhook(store_, decisions_, event,
                                                   payload_view, &enrichment_);
                return json_response(reply.status, reply.body);
            } catch (const nlohmann::json::exception&) {
                return json_response(400, {{"error", "invalid JSON"}});
            }
        }
        if (!authenticated(connection)) return json_response(401, {{"error", "unauthorized"}});
        if (method == "GET" && url == "/api/status") return json_response(200, store_.status());
        if (method == "GET" && url == "/api/diagnostics") {
            return json_response(200, {
                {"service", "smithproxy-spider"},
                {"generated_at_ms", unix_time_ms()},
                {"http", {{"requests", requests_total_.load(std::memory_order_relaxed)},
                          {"response_bytes", response_bytes_.load(std::memory_order_relaxed)},
                          {"last_request_at_ms", last_request_at_ms_.load(std::memory_order_relaxed)}}},
                {"callback_transport", {
                    {"requests", callback_requests_.load(std::memory_order_relaxed)},
                    {"bytes", callback_bytes_.load(std::memory_order_relaxed)},
                    {"errors", callback_errors_.load(std::memory_order_relaxed)},
                }},
                {"store", store_.diagnostics()},
                {"enrichment", enrichment_.diagnostics()},
                {"websocket", websocket_.diagnostics()},
            });
        }
        if (method == "GET" && url == "/api/ready") {
            auto status = store_.status();
            return json_response(status.value("ready", false) ? 200U : 503U, status);
        }
        if (method == "GET" && url == "/api/sessions") return json_response(200, store_.snapshot());
        if (method == "GET" && url == "/api/hostnames") return json_response(200, store_.reverse_hostnames());
        if (method == "GET" && url == "/api/session-history") {
            return json_response(200, store_.session_history());
        }
        if (method == "GET" && url == "/api/session") {
            const char* id = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");
            if (id == nullptr || *id == '\0') return json_response(400, {{"error", "id is required"}});
            const auto detail = store_.session_detail(id);
            return detail ? json_response(200, *detail)
                          : json_response(404, {{"error", "session not found"}});
        }
        if (method == "DELETE" && url == "/api/session-history") {
            return json_response(200, {{"removed", store_.clear_completed_sessions()}});
        }
        if (method == "GET" && url == "/api/events") {
            std::uint64_t after{};
            if (const char* value = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "after")) {
                std::from_chars(value, value + std::strlen(value), after);
            }
            return json_response(200, store_.events_after(after));
        }
        if (method == "POST" && url == "/api/config/smithproxy") {
            try {
                const auto request = nlohmann::json::parse(body);
                SmithproxyConfig client_config;
                client_config.api_url = request.value("url", "");
                client_config.api_key = request.value("api_key", "");
                client_config.callback_url = request.value("callback_url", config_.callback_url);
                client_config.verify_tls = request.value("verify_tls", true);
                if (client_config.api_url.empty() || client_config.api_key.empty()) {
                    return json_response(400, {{"error", "url and api_key are required"}});
                }
                while (client_config.api_url.size() > 1 && client_config.api_url.back() == '/') {
                    client_config.api_url.pop_back();
                }
                smithproxy_.configure(std::move(client_config));
                return json_response(202, {{"status", "connecting"}});
            } catch (const nlohmann::json::exception&) {
                return json_response(400, {{"error", "invalid configuration JSON"}});
            }
        }
        return json_response(404, {{"error", "not found"}});
    }

    static int send(MHD_Connection* connection, RequestState& state, Response response) {
        auto* wire = MHD_create_response_from_buffer(response.body.size(), response.body.data(), MHD_RESPMEM_MUST_COPY);
        if (wire == nullptr) return MHD_NO;
        MHD_add_response_header(wire, MHD_HTTP_HEADER_CONTENT_TYPE, response.type.c_str());
        MHD_add_response_header(wire, MHD_HTTP_HEADER_CACHE_CONTROL, "no-store");
        MHD_add_response_header(wire, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(wire, "Access-Control-Allow-Headers", "Content-Type, X-Spider-Token");
        MHD_add_response_header(wire, "Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        const auto result = MHD_queue_response(connection, response.status, wire);
        MHD_destroy_response(wire);
        state.response_sent = result == MHD_YES;
        return result;
    }

    const ServerConfig& config_;
    SessionStore& store_;
    SmithproxyManager& smithproxy_;
    DecisionBroker& decisions_;
    EnrichmentEngine& enrichment_;
    WebSocketHub& websocket_;
    std::atomic_uint64_t requests_total_{};
    std::atomic_uint64_t response_bytes_{};
    std::atomic_uint64_t callback_requests_{};
    std::atomic_uint64_t callback_bytes_{};
    std::atomic_uint64_t callback_errors_{};
    std::atomic_int64_t last_request_at_ms_{};

    [[nodiscard]] std::string callback_path() const {
        return config_.callback_token.empty() ? "/webhook" : "/webhook/" + config_.callback_token;
    }
};

} // namespace

int run_http_server(const ServerConfig& config, SessionStore& store,
                    SmithproxyManager& smithproxy, std::atomic_bool& stop) {
    DecisionBroker decisions;
    EnrichmentEngine enrichment;
    WebSocketHub websocket(config.token, [&decisions](const nlohmann::json& message)
                           -> std::optional<nlohmann::json> {
        if (message.value("type", "") == "auto-accept-rules") {
            return std::optional<nlohmann::json>{decisions.set_auto_accept_rules(message)};
        }
        if (message.value("type", "") == "auto-accept-rules-status-request") {
            return std::optional<nlohmann::json>{decisions.auto_accept_rule_status()};
        }
        if (message.value("type", "") == "traffic-rules") {
            return std::optional<nlohmann::json>{decisions.set_traffic_rules(message)};
        }
        if (message.value("type", "") == "traffic-rules-status-request") {
            return std::optional<nlohmann::json>{decisions.traffic_rule_status()};
        }
        decisions.handle_message(message);
        return std::nullopt;
    }, [&decisions] {
        decisions.handle_message({{"type", "live-edit"}, {"enabled", false}});
        decisions.handle_message({{"type", "script-available"}, {"available", false}});
    });
    store.set_event_sink([&websocket](const std::uint64_t revision,
                                     const nlohmann::json& event,
                                     const std::optional<std::string_view> raw_payload,
                                     const std::vector<SxbnEnvelope>& enrichments) {
        websocket.publish(revision, event, raw_payload, enrichments);
    }, true);
    lmh::WebServer server(config.port);
    server.options().bind_address = config.bind_address;
    server.options().configure_listen_socket = [](int socket) {
        int enabled = 1;
        return ::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0;
    };
    server.options().handler_should_terminate = [&stop] { return stop.load(); };
    server.options().thread_pool_size = 16;
    server.options().allow_upgrade = true;
    server.addController(std::make_shared<SpiderController>(config, store, smithproxy, decisions,
                                                            enrichment, websocket));
    const auto result = server.start() ? 0 : 1;
    store.set_event_sink({});
    websocket.stop();
    return result;
}

} // namespace spider
