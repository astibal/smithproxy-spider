#pragma once

#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

struct Session {
    std::string id;
    std::string label;
    std::string state;
    std::uint64_t revision{};
    nlohmann::json last_event;
};

class SessionStore {
public:
    explicit SessionStore(std::size_t history_limit = 1000);

    void apply(const nlohmann::json& event);
    [[nodiscard]] nlohmann::json snapshot() const;
    [[nodiscard]] nlohmann::json events_after(std::uint64_t revision) const;
    [[nodiscard]] nlohmann::json status() const;
    [[nodiscard]] std::uint64_t revision() const;

private:
    struct EventRecord {
        std::uint64_t revision;
        nlohmann::json event;
    };

    static std::string session_label(const nlohmann::json& event);

    const std::size_t history_limit_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
    std::deque<EventRecord> history_;
    nlohmann::json smithproxy_status_{{"state", "starting"}};
    std::uint64_t callback_count_{};
    std::uint64_t last_callback_revision_{};
    std::int64_t last_callback_at_ms_{};
    std::string last_callback_action_;
    std::string last_callback_source_;
    std::uint64_t revision_{};
};

} // namespace spider
