#include "smithproxy_client.hpp"
#include "session_store.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <thread>
#include <utility>

namespace spider {
namespace {
std::size_t append_response(char* data, std::size_t size, std::size_t count, void* target) {
    const auto bytes = size * count;
    static_cast<std::string*>(target)->append(data, bytes);
    return bytes;
}
struct HttpResult { long status{}; std::string body; std::string error; };

HttpResult post_json(const std::string& url, const nlohmann::json& body, bool verify_tls) {
    HttpResult result;
    auto* curl = curl_easy_init();
    if (!curl) { result.error = "curl initialization failed"; return result; }
    auto* headers = curl_slist_append(nullptr, "Content-Type: application/json");
    const auto payload = body.dump();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_tls ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_tls ? 2L : 0L);
    const auto code = curl_easy_perform(curl);
    if (code == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status);
    else result.error = curl_easy_strerror(code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result;
}
} // namespace

SmithproxyClient::SmithproxyClient(SmithproxyConfig config, SessionStore& store)
    : config_(std::move(config)), store_(store) {}

void SmithproxyClient::publish_status(std::string state, std::string detail,
                                      nlohmann::json metadata) {
    auto event = nlohmann::json{{"action", "spider-smithproxy-status"},
                                {"state", std::move(state)},
                                {"detail", std::move(detail)},
                                {"api_url", config_.api_url}};
    if (metadata.is_object()) event.update(metadata);
    store_.apply(event);
}

bool SmithproxyClient::authorize() {
    const auto response = post_json(config_.api_url + "/api/authorize",
                                    {{"access_key", config_.api_key}}, config_.verify_tls);
    if (!response.error.empty()) { publish_status("error", "authorize: " + response.error); return false; }
    try {
        const auto json = nlohmann::json::parse(response.body);
        if (response.status != 200 || !json.contains("auth_token") || !json.contains("csrf_token")) {
            publish_status("error", "authorize rejected (HTTP " + std::to_string(response.status) + ")");
            return false;
        }
        auth_token_ = json.at("auth_token").get<std::string>();
        csrf_token_ = json.at("csrf_token").get<std::string>();
        publish_status("authorized");
        return true;
    } catch (const nlohmann::json::exception&) {
        publish_status("error", "authorize returned invalid JSON"); return false;
    }
}

bool SmithproxyClient::renew_webhook() {
    if (!legacy_webhook_api_) {
        auto params = nlohmann::json{{"url", config_.callback_url},
                                     {"tls_verify", config_.verify_tls},
                                     {"ttl_seconds", 60}};
        if (!lease_id_.empty()) params["lease_id"] = lease_id_;
        const auto response = post_json(config_.api_url + "/api/v2/webhook/lease",
            {{"auth_token", auth_token_}, {"csrf_token", csrf_token_}, {"params", std::move(params)}},
            config_.verify_tls);
        if (!response.error.empty()) {
            publish_status("error", "v2 lease: " + response.error);
            return false;
        }
        if (response.status == 404) {
            legacy_webhook_api_ = true;
            publish_status("authorized", "Smithproxy uses legacy webhook API");
        } else {
            try {
                const auto json = nlohmann::json::parse(response.body);
                if ((response.status == 200 || response.status == 201) && json.contains("lease_id")) {
                    lease_id_ = json.at("lease_id").get<std::string>();
                    publish_status("connected", response.status == 201
                        ? "owned webhook lease acquired" : "owned webhook lease renewed",
                        {{"webhook_api", "v2-owned"},
                         {"lease_expires_at", json.value("expires_at", std::int64_t{})}});
                    return true;
                }
                publish_status("error", "v2 webhook lease rejected (HTTP " +
                               std::to_string(response.status) + ")");
                return false;
            } catch (const nlohmann::json::exception&) {
                publish_status("error", "v2 lease returned invalid JSON");
                return false;
            }
        }
    }

    const nlohmann::json request = {
        {"auth_token", auth_token_}, {"csrf_token", csrf_token_},
        {"params", {{"rande_url", config_.callback_url}, {"rande_tls_verify", config_.verify_tls}}}
    };
    const auto response = post_json(config_.api_url + "/api/webhook/register", request, config_.verify_tls);
    if (!response.error.empty()) { publish_status("error", "register: " + response.error); return false; }
    try {
        const auto json = nlohmann::json::parse(response.body);
        const bool accepted = response.status == 200 && json.value("status", "") == "accepted";
        publish_status(accepted ? "connected" : "error",
                       accepted ? "webhook lease renewed" : "webhook registration rejected",
                       {{"webhook_api", "legacy"}});
        return accepted;
    } catch (const nlohmann::json::exception&) {
        publish_status("error", "register returned invalid JSON"); return false;
    }
}

void SmithproxyClient::release_webhook() {
    if (legacy_webhook_api_ || lease_id_.empty() || auth_token_.empty() || csrf_token_.empty()) return;
    const auto response = post_json(config_.api_url + "/api/v2/webhook/lease/release",
        {{"auth_token", auth_token_}, {"csrf_token", csrf_token_},
         {"params", {{"lease_id", lease_id_}}}}, config_.verify_tls);
    if (response.error.empty() && response.status == 200) lease_id_.clear();
}

void SmithproxyClient::run(std::atomic_bool& stop) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    publish_status("connecting");
    // The HTTP listener is started immediately after this worker. Give it a
    // bounded head start so a freshly registered callback is already routable.
    for (int i=0; i<2 && !stop.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    while (!stop.load()) {
        if ((auth_token_.empty() || csrf_token_.empty()) && !authorize()) {
            for (int i=0; i<50 && !stop.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        if (!renew_webhook()) { auth_token_.clear(); csrf_token_.clear(); }
        const auto ticks = std::max<std::int64_t>(1, config_.renew_interval.count()*10);
        for (std::int64_t i=0; i<ticks && !stop.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    release_webhook();
    publish_status("stopped");
    curl_global_cleanup();
}
} // namespace spider
