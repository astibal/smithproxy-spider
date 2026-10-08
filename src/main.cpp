#include "http_server.hpp"
#include "session_store.hpp"
#include "smithproxy_client.hpp"

#include <openssl/rand.h>

#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <thread>

namespace {
std::atomic_bool stop_requested{};
void stop_handler(int) { stop_requested.store(true); }

std::string random_token() {
    unsigned char random[16];
    if (RAND_bytes(random, sizeof(random)) != 1) throw std::runtime_error("cannot generate callback token");
    constexpr char hex[] = "0123456789abcdef";
    std::string result(32, '0');
    for (std::size_t i=0; i<sizeof(random); ++i) {
        result[i*2] = hex[random[i] >> 4U];
        result[i*2+1] = hex[random[i] & 0x0fU];
    }
    return result;
}
}

int main(int argc, char** argv) {
    spider::ServerConfig config;
    spider::SmithproxyConfig smithproxy;
    if (const char* token = std::getenv("SPIDER_TOKEN")) config.token = token;
    if (const char* key = std::getenv("SPIDER_SMITHPROXY_KEY")) smithproxy.api_key = key;
    smithproxy.api_url = "https://127.0.0.1:55555";

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--help") {
            std::cout << "Usage: smithproxy-spider [options]\n"
                         "  --port N                     listen port (8080)\n"
                         "  --bind ADDRESS               listen address\n"
                         "  --smithproxy-url URL         Smithproxy API base URL\n"
                         "  --callback-url URL           callback base URL visible to Smithproxy\n"
                         "  --smithproxy-insecure        disable Smithproxy API TLS verification\n"
                         "API key is read from SPIDER_SMITHPROXY_KEY.\n";
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
        } else if (arg == "--smithproxy-url" && i + 1 < argc) {
            smithproxy.api_url = argv[++i];
        } else if (arg == "--callback-url" && i + 1 < argc) {
            smithproxy.callback_url = argv[++i];
        } else if (arg == "--smithproxy-insecure") {
            smithproxy.verify_tls = false;
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            return 2;
        }
    }

    std::signal(SIGINT, stop_handler);
    std::signal(SIGTERM, stop_handler);
    spider::SessionStore store;
    config.callback_token = random_token();
    if (smithproxy.callback_url.empty()) {
        smithproxy.callback_url = "http://127.0.0.1:" + std::to_string(config.port) + "/webhook";
    }
    smithproxy.callback_url += "/" + config.callback_token;
    std::cout << "Spider listening on http://" << config.bind_address << ':' << config.port << '\n';
    std::thread client;
    if (!smithproxy.api_key.empty()) {
        client = std::thread([&] { spider::SmithproxyClient(smithproxy, store).run(stop_requested); });
    } else {
        store.apply({{"action", "spider-smithproxy-status"}, {"state", "disabled"},
                     {"detail", "SPIDER_SMITHPROXY_KEY is not set"}});
    }
    const auto result = spider::run_http_server(config, store, stop_requested);
    stop_requested.store(true);
    if (client.joinable()) client.join();
    return result;
}
