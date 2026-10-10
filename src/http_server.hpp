#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace spider {

class SessionStore;
class SmithproxyManager;

struct ServerConfig {
    std::uint16_t port{8080};
    std::string bind_address{"127.0.0.1"};
    std::string token;
    std::string callback_token;
    std::string callback_url;
    std::size_t max_body_bytes{1024 * 1024};
};

int run_http_server(const ServerConfig& config, SessionStore& store,
                    SmithproxyManager& smithproxy, std::atomic_bool& stop);

} // namespace spider
