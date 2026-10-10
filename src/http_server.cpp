#include "http_server.hpp"

#include "session_store.hpp"
#include "smithproxy_manager.hpp"
#include "webhook.hpp"

#include <lmhttpd.hpp>
#include <microhttpd.h>
#include <nlohmann/json.hpp>

#include <charconv>
#include <cstring>
#include <memory>
#include <string_view>

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
    SpiderController(const ServerConfig& config, SessionStore& store, SmithproxyManager& smithproxy)
        : config_(config), store_(store), smithproxy_(smithproxy) {}

    bool validPath(const char* path, const char* method) override {
        const std::string_view p(path);
        const std::string_view m(method);
        return (m == "GET" && (p == "/" || p == "/api/health" || p == "/api/ready" ||
                               p == "/api/status" || p == "/api/sessions" ||
                               p == "/api/session-history" || p == "/api/session" ||
                               p == "/api/events")) ||
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
        Response response;
        if (state.too_large) {
            response = json_response(413, {{"error", "request body too large"}});
        } else {
            response = route(connection, url, method, state.request_data);
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
                const auto reply = process_webhook(store_, nlohmann::json::parse(body));
                return json_response(reply.status, reply.body);
            } catch (const nlohmann::json::exception&) {
                return json_response(400, {{"error", "invalid JSON"}});
            }
        }
        if (!authenticated(connection)) return json_response(401, {{"error", "unauthorized"}});
        if (method == "GET" && url == "/api/status") return json_response(200, store_.status());
        if (method == "GET" && url == "/api/ready") {
            auto status = store_.status();
            return json_response(status.value("ready", false) ? 200U : 503U, status);
        }
        if (method == "GET" && url == "/api/sessions") return json_response(200, store_.snapshot());
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

    [[nodiscard]] std::string callback_path() const {
        return config_.callback_token.empty() ? "/webhook" : "/webhook/" + config_.callback_token;
    }
};

} // namespace

int run_http_server(const ServerConfig& config, SessionStore& store,
                    SmithproxyManager& smithproxy, std::atomic_bool& stop) {
    lmh::WebServer server(config.port);
    server.options().bind_address = config.bind_address;
    server.options().handler_should_terminate = [&stop] { return stop.load(); };
    server.addController(std::make_shared<SpiderController>(config, store, smithproxy));
    return server.start() ? 0 : 1;
}

} // namespace spider
