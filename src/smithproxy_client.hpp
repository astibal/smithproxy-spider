#pragma once

#include <atomic>
#include <chrono>
#include <string>

namespace spider {
class SessionStore;

struct SmithproxyConfig {
    std::string api_url;
    std::string api_key;
    std::string callback_url;
    bool verify_tls{true};
    std::chrono::seconds renew_interval{20};
};

class SmithproxyClient {
public:
    SmithproxyClient(SmithproxyConfig config, SessionStore& store);
    void run(std::atomic_bool& stop);
private:
    bool authorize();
    bool renew_webhook();
    void release_webhook();
    void publish_status(std::string state, std::string detail = {});
    SmithproxyConfig config_;
    SessionStore& store_;
    std::string auth_token_;
    std::string csrf_token_;
    std::string lease_id_;
    bool legacy_webhook_api_{};
};
} // namespace spider
