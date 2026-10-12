#include <sift/engine_server.hpp>

#include <sift/engine.hpp>
#include <binary_envelope.hpp>

#include <lmhttpd.hpp>
#include <microhttpd.h>

#include <chrono>
#include <memory>
#include <string_view>

namespace sift {
namespace {

struct RequestState final : lmh::ConnectionState {
    explicit RequestState(lmh::Controller& controller) : ConnectionState(controller) {}
    bool too_large{};
};

class Controller final : public lmh::Controller {
public:
    Controller(const ServerConfig& config, Runtime& runtime)
        : config_(config), runtime_(runtime) {}

    bool validPath(const char* path, const char* method) override {
        const std::string_view p(path);
        const std::string_view m(method);
        return (m == "GET" &&
                (p == "/api/health" || p == "/api/status" || p == "/api/stats")) ||
               (m == "POST" && p == config_.path);
    }

    lmh::ConnectionState* create_state() override { return new RequestState(*this); }

    int handleRequest(MHD_Connection* connection, const char* url, const char*,
                      const char* upload_data, std::size_t* upload_data_size,
                      void** ptr) override {
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

        unsigned status = 200;
        nlohmann::json reply;
        if (state.too_large) {
            status = 413;
            reply = {{"error", "request body too large"}};
        } else if (std::string_view(url) == "/api/health" ||
                   std::string_view(url) == "/api/status" ||
                   std::string_view(url) == "/api/stats") {
            reply = runtime_.status();
        } else {
            reply = process(state.request_data, status);
        }
        const auto body = reply.dump();
        auto* response = MHD_create_response_from_buffer(
            body.size(), const_cast<char*>(body.data()), MHD_RESPMEM_MUST_COPY);
        if (response == nullptr) return MHD_NO;
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
        const auto result = MHD_queue_response(connection, status, response);
        MHD_destroy_response(response);
        state.response_sent = result == MHD_YES;
        return result;
    }

private:
    nlohmann::json process(const std::string& body, unsigned& status) {
        const auto started = std::chrono::steady_clock::now();
        nlohmann::json event;
        std::string payload;
        if (std::string_view(body).starts_with(spider::sxbn_magic)) {
            std::string error;
            if (!spider::decode_sxbn(body, event, payload, error)) {
                status = 400;
                return {{"error", error}};
            }
        } else {
            event = nlohmann::json::parse(body, nullptr, false);
            if (event.is_discarded() || !event.is_object()) {
                status = 400;
                return {{"error", "invalid JSON"}};
            }
        }

        const auto action = event.value("action", "");
        if (action == "info") {
            return {{"action", "info-response"},
                    {"protocols", {{"connection-content", {"sxbn-001"}}}},
                    {"service", "sx-siftd"}};
        }
        if (action == "connection-stop") {
            runtime_.close(event.value("id", ""));
            return nlohmann::json::object();
        }
        if (action != "connection-content") {
            return nlohmann::json::object();
        }
        const auto details = event.value("details", nlohmann::json::object());
        const auto info = details.value("info", nlohmann::json::object());
        if (payload.empty() && info.contains("content")) {
            status = 422;
            return {{"error", "JSON/base64 fallback is not implemented yet"}};
        }
        const auto side_text = info.value("side", "L");
        const auto side = side_text.empty() ? 'L' : side_text.front();
        auto reply = verdict_json(runtime_.inspect(
            info.value("session", event.value("id", "")), side, payload));
        runtime_.record_engine_delay(std::chrono::steady_clock::now() - started);
        return reply;
    }

    const ServerConfig& config_;
    Runtime& runtime_;
};

} // namespace

int run_server(const ServerConfig& config, Runtime& runtime, std::atomic_bool& stop) {
    lmh::WebServer server(config.port);
    server.options().bind_address = config.bind;
    server.options().handler_should_terminate = [&stop] { return stop.load(); };
    server.options().thread_pool_size = 4;
    server.addController(std::make_shared<Controller>(config, runtime));
    return server.start() ? 0 : 1;
}

} // namespace sift
