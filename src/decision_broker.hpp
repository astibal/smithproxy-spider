#pragma once

#include "session_filter.hpp"
#include "webhook.hpp"
#include "heavy_traffic.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

class DecisionBroker {
public:
    HeavyTraffic heavy_traffic;
    struct Ticket;

    explicit DecisionBroker(std::chrono::milliseconds timeout = std::chrono::seconds(10));
    [[nodiscard]] std::shared_ptr<Ticket> prepare(nlohmann::json& event);
    [[nodiscard]] WebhookReply wait(const std::shared_ptr<Ticket>& ticket,
                                    const nlohmann::json& event);
    void handle_message(const nlohmann::json& message);
    [[nodiscard]] nlohmann::json set_auto_accept_rules(const nlohmann::json& message);
    [[nodiscard]] nlohmann::json auto_accept_rule_status() const;
    [[nodiscard]] nlohmann::json set_traffic_rules(const nlohmann::json& message);
    [[nodiscard]] nlohmann::json traffic_rule_status() const;
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
    struct AutoAcceptRule {
        std::string id;
        std::string expression;
        SessionFilter filter;
        std::uint64_t matches{};
    };
    struct TrafficRule {
        std::string id;
        std::string kind;
        std::string value;
        std::string address;
        std::string mode;
        std::optional<SessionFilter> filter;
        std::uint64_t matches{};
    };
    void resolve_locked(const std::shared_ptr<Ticket>& ticket, Result result);
    void resolve_all_locked();

    const std::chrono::milliseconds timeout_;
    mutable std::mutex mutex_;
    bool enabled_{};
    bool script_available_{};
    bool bypass_all_{};
    std::uint64_t next_id_{};
    std::unordered_map<std::string, std::shared_ptr<Ticket>> pending_;
    std::unordered_set<std::string> accepted_sessions_;
    std::unordered_map<std::string, std::unordered_set<std::string>> session_classifications_;
    std::unordered_map<std::string, std::unordered_set<std::string>> hostnames_;
    std::vector<AutoAcceptRule> auto_accept_rules_;
    std::vector<TrafficRule> traffic_rules_;
};

} // namespace spider
