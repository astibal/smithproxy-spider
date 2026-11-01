#include "auth_broker.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <stdexcept>
#include <sys/un.h>

namespace spider {
namespace {
constexpr std::size_t maximum_reply = 16384;

bool bounded_text(const std::string& value, std::size_t limit) {
    return !value.empty() && value.size() <= limit && value.find('\0') == std::string::npos;
}

std::size_t receive_reply(char* data, std::size_t size, std::size_t count, void* context) noexcept {
    auto& reply = *static_cast<std::string*>(context);
    if (size != 1 || count > maximum_reply - reply.size()) {
        return 0;
    }

    // Exceptions must not cross curl's C callback boundary.
    try {
        reply.append(data, count);
        return count;
    } catch (...) {
        return 0;
    }
}
}

AuthBrokerClient::AuthBrokerClient(std::string socket_path, long timeout_ms)
    : socket_path_(std::move(socket_path)), timeout_ms_(timeout_ms) {
    if (socket_path_.empty() || socket_path_.front() != '/' ||
       socket_path_.size() >= sizeof(sockaddr_un::sun_path) ||
       socket_path_.find('\0') != std::string::npos || timeout_ms_ < 1 || timeout_ms_ > 10000) {
        throw std::invalid_argument("invalid authentication socket path or timeout");
    }

    static const auto initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (initialized != CURLE_OK) {
        throw std::runtime_error("cannot initialize authentication transport");
    }
}

AuthResult AuthBrokerClient::verify(std::string_view username, std::string_view password) const {
    if (username.empty() || username.size() > 255 || password.empty() || password.size() > 1024 ||
       username.find('\0') != std::string_view::npos || password.find('\0') != std::string_view::npos) {
        return {AuthStatus::rejected, {}, {}};
    }

    std::string body;
    try {
        body = nlohmann::json{{"version", 1}, {"username", username}, {"password", password}}.dump();
    } catch (...) {
        return {AuthStatus::rejected, {}, {}};
    }
    if (body.size() > 4096) {
        return {AuthStatus::rejected, {}, {}};
    }

    auto handle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(), curl_easy_cleanup);
    auto headers = std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)>(
        curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
    if (!handle || !headers) {
        return {};
    }

    // Every attempt connects to the configured Unix socket afresh. There is
    // no endpoint discovery, cached acceptance, redirect or TCP fallback.
    std::string reply;
    if (curl_easy_setopt(handle.get(), CURLOPT_URL, "http://localhost/v1/pap") != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_UNIX_SOCKET_PATH, socket_path_.c_str()) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_PROXY, "") != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT_MS, timeout_ms_) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT_MS, timeout_ms_) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_HTTPHEADER, headers.get()) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDS, body.data()) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size())) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, receive_reply) != CURLE_OK ||
       curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &reply) != CURLE_OK) {
        return {};
    }

    const auto transport = curl_easy_perform(handle.get());
    long status = 0;
    curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &status);
    if (transport != CURLE_OK || status != 200) {
        return {};
    }

    try {
        const auto value = nlohmann::json::parse(reply);
        if (!value.is_object() || !value.at("version").is_number_integer() || value.at("version") != 1) {
            return {};
        }
        const auto decision = value.at("status").get<std::string>();
        if (decision == "rejected") {
            return {AuthStatus::rejected, {}, {}};
        }
        if (decision != "accepted") {
            return {};
        }

        AuthResult result{AuthStatus::accepted, value.at("identity").get<std::string>(),
                          value.at("groups").get<std::vector<std::string>>()};
        if (!bounded_text(result.identity, 512) || result.groups.size() > 64) {
            return {};
        }
        for (const auto& group : result.groups) {
            if (!bounded_text(group, 255)) {
                return {};
            }
        }
        return result;
    } catch (...) {
        return {};
    }
}

} // namespace spider
