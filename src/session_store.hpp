#pragma once

#include "binary_envelope.hpp"

#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

struct Session {
    std::string id;
    std::string label;
    std::string state;
    std::uint64_t revision{};
    std::int64_t started_at_ms{};
    std::int64_t updated_at_ms{};
    std::int64_t ended_at_ms{};
    nlohmann::json last_event;
    std::deque<nlohmann::json> events;
    std::unordered_set<std::string> sift_classifications;
};

class SessionStore {
public:
    explicit SessionStore(std::size_t history_limit = 1000,
                          std::size_t session_history_limit = 1000);

    std::uint64_t apply(const nlohmann::json& event,
                        std::optional<std::string_view> raw_payload = std::nullopt,
                        const std::vector<SxbnEnvelope>& enrichments = {});
    void set_event_sink(std::function<void(std::uint64_t, const nlohmann::json&,
                                           std::optional<std::string_view>,
                                           const std::vector<SxbnEnvelope>&)> sink,
                        bool replay_existing = false);
    [[nodiscard]] nlohmann::json snapshot() const;
    [[nodiscard]] nlohmann::json session_history() const;
    [[nodiscard]] std::optional<nlohmann::json> session_detail(const std::string& id) const;
    std::size_t clear_completed_sessions();
    [[nodiscard]] nlohmann::json events_after(std::uint64_t revision) const;
    [[nodiscard]] nlohmann::json status() const;
    [[nodiscard]] nlohmann::json diagnostics() const;
    [[nodiscard]] nlohmann::json reverse_hostnames() const;
    [[nodiscard]] std::uint64_t revision() const;

private:
    struct HostnameObservation {
        std::unordered_set<std::string> origins;
        std::unordered_set<std::string> types;
    };

    struct EventRecord {
        std::uint64_t revision;
        nlohmann::json event;
    };

    static std::string session_label(const nlohmann::json& event);
    static nlohmann::json session_json(const Session& session, bool include_events);
    void apply_hostname_info(const nlohmann::json& event);
    void prune_session_history();

    const std::size_t history_limit_;
    const std::size_t session_history_limit_;
    static constexpr std::size_t session_event_limit_{200};
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
    std::deque<std::string> session_order_;
    std::deque<EventRecord> history_;
    nlohmann::json smithproxy_status_{{"state", "starting"}};
    std::uint64_t callback_count_{};
    std::uint64_t last_callback_revision_{};
    std::int64_t last_callback_at_ms_{};
    std::string last_callback_action_;
    std::string last_callback_source_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, HostnameObservation>> reverse_hostnames_;
    std::uint64_t hostname_revision_{};
    std::uint64_t revision_{};
    std::uint64_t history_evicted_{};
    std::uint64_t session_events_evicted_{};
    std::uint64_t sessions_evicted_{};
    std::unordered_map<std::string, std::uint64_t> callbacks_by_action_;
    std::unordered_map<std::string, std::uint64_t> callbacks_by_source_;
    std::function<void(std::uint64_t, const nlohmann::json&,
                       std::optional<std::string_view>,
                       const std::vector<SxbnEnvelope>&)> event_sink_;
};

} // namespace spider
