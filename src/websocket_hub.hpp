#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <microhttpd.h>
#include <nlohmann/json.hpp>

namespace spider {

class WebSocketHub {
public:
    using MessageHandler = std::function<std::optional<nlohmann::json>(const nlohmann::json&)>;
    using EmptyHandler = std::function<void()>;

    explicit WebSocketHub(std::string token, MessageHandler handler = {}, EmptyHandler empty_handler = {});
    ~WebSocketHub();
    WebSocketHub(const WebSocketHub&) = delete;
    WebSocketHub& operator=(const WebSocketHub&) = delete;

    [[nodiscard]] bool can_upgrade(MHD_Connection* connection) const;
    int queue_upgrade(MHD_Connection* connection);
    void publish(std::uint64_t revision, const nlohmann::json& event);
    [[nodiscard]] nlohmann::json diagnostics() const;
    void stop();

private:
    struct Client;
    struct ReplayItem { std::uint64_t revision; std::string wire; };

    static void upgrade(void* cls, MHD_Connection*, void*, const char* extra_in,
                        std::size_t extra_in_size, MHD_socket socket,
                        MHD_UpgradeResponseHandle* handle);
    void run_client(const std::shared_ptr<Client>& client, std::string initial);
    void subscribe(const std::shared_ptr<Client>& client, std::uint64_t after, bool tail);
    void remove_client(const std::shared_ptr<Client>& client);
    void handle_message(const std::shared_ptr<Client>& client, std::string_view message);

    std::string token_;
    MessageHandler handler_;
    EmptyHandler empty_handler_;
    std::atomic_bool stopping_{};
    mutable std::mutex mutex_;
    std::condition_variable stopped_;
    std::size_t client_threads_{};
    std::vector<std::weak_ptr<Client>> clients_;
    std::deque<ReplayItem> replay_;
    std::size_t replay_bytes_{};
    std::uint64_t connections_total_{};
    std::uint64_t disconnects_total_{};
    std::uint64_t subscriptions_total_{};
    std::uint64_t gaps_total_{};
    std::uint64_t events_published_{};
    std::uint64_t events_evicted_{};
    std::uint64_t publish_bytes_{};
    std::uint64_t send_failures_{};
    std::uint64_t client_messages_{};
    std::int64_t last_connect_at_ms_{};
    std::int64_t last_disconnect_at_ms_{};
    std::int64_t last_publish_at_ms_{};
    std::int64_t last_subscribe_at_ms_{};
    static constexpr std::size_t max_replay_events_{10000};
    static constexpr std::size_t max_replay_bytes_{64U * 1024U * 1024U};
};

} // namespace spider
