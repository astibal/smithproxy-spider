#include "http_server.hpp"
#include "session_store.hpp"

#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
std::atomic_bool stop_requested{};
void stop_handler(int) { stop_requested.store(true); }
}

int main(int argc, char** argv) {
    spider::ServerConfig config;
    if (const char* token = std::getenv("SPIDER_TOKEN")) config.token = token;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--help") {
            std::cout << "Usage: smithproxy-spider [--port N] [--bind ADDRESS]\n"
                         "Authentication token is read from SPIDER_TOKEN.\n";
            return 0;
        }
        if (arg == "--port" && i + 1 < argc) {
            unsigned port{};
            const std::string_view value(argv[++i]);
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
            if (error != std::errc{} || end != value.data() + value.size() || port == 0 || port > 65535) {
                std::cerr << "Invalid port\n";
                return 2;
            }
            config.port = static_cast<std::uint16_t>(port);
        } else if (arg == "--bind" && i + 1 < argc) {
            config.bind_address = argv[++i];
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            return 2;
        }
    }

    std::signal(SIGINT, stop_handler);
    std::signal(SIGTERM, stop_handler);
    spider::SessionStore store;
    std::cout << "Spider listening on http://" << config.bind_address << ':' << config.port << '\n';
    return spider::run_http_server(config, store, stop_requested);
}

