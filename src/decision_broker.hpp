#pragma once

#include "webhook.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace spider {

class DecisionBroker {
public:
    struct Ticket;

    explicit DecisionBroker(std::chrono::milliseconds timeout = std::chrono::seconds(10));
    [[nodiscard]] std::shared_ptr<Ticket> prepare(nlohmann::json& event);
    [[nodiscard]] WebhookReply wait(const std::shared_ptr<Ticket>& ticket);
    void handle_message(const nlohmann::json& message);
    void observe(const nlohmann::json& event);
    [[nodiscard]] bool enabled() const;

private:
    struct Result { std::string action{"accept"}; std::string content; };
public:
    struct Ticket {
        std::string id;
        std::string session_id;
        std::condition_variable ready;
        bool decided{};
        Result result;
    };
private:
    void resolve_locked(const std::shared_ptr<Ticket>& ticket, Result result);
    void resolve_all_locked();

    const std::chrono::milliseconds timeout_;
    mutable std::mutex mutex_;
    bool enabled_{};
    std::uint64_t next_id_{};
    std::unordered_map<std::string, std::shared_ptr<Ticket>> pending_;
    std::unordered_set<std::string> accepted_sessions_;
};

} // namespace spider
