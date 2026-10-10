#include "session_store.hpp"

#include <algorithm>
#include <chrono>

namespace spider {
namespace {
std::int64_t unix_time_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
} // namespace

SessionStore::SessionStore(const std::size_t history_limit,
                           const std::size_t session_history_limit)
    : history_limit_(std::max<std::size_t>(history_limit, 1)),
      session_history_limit_(std::max<std::size_t>(session_history_limit, 1)) {}

std::string SessionStore::session_label(const nlohmann::json& event) {
    const auto info = event.find("details");
    if (info == event.end() || !info->is_object()) return {};

    if (const auto direct = info->find("session"); direct != info->end() && direct->is_string()) {
        return direct->get<std::string>();
    }
    if (const auto nested = info->find("info"); nested != info->end() && nested->is_object()) {
        if (const auto session = nested->find("session"); session != nested->end() && session->is_string()) {
            return session->get<std::string>();
        }
    }
    return {};
}

void SessionStore::apply(const nlohmann::json& event) {
    const auto action = event.value("action", "");
    const auto id = event.value("id", "");
    auto stored_event = event;
    const auto received_at_ms = unix_time_ms();
    stored_event["spider_received_at_ms"] = received_at_ms;

    std::scoped_lock lock(mutex_);
    const auto rev = ++revision_;
    history_.push_back({rev, stored_event});
    while (history_.size() > history_limit_) history_.pop_front();

    if (action == "spider-smithproxy-status") {
        smithproxy_status_ = stored_event;
    } else {
        ++callback_count_;
        last_callback_revision_ = rev;
        last_callback_at_ms_ = received_at_ms;
        last_callback_action_ = action;
        last_callback_source_ = event.value("source", "");
    }

    if (id.empty()) return;

    auto [position, inserted] = sessions_.try_emplace(id);
    auto& session = position->second;
    if (inserted) {
        session_order_.push_back(id);
        session.started_at_ms = received_at_ms;
    }
    session.id = id;
    const auto label = session_label(event);
    if (!label.empty()) session.label = label;
    if (action == "connection-start") {
        session.state = "active";
        session.ended_at_ms = 0;
    } else if (action == "connection-stop") {
        session.state = "completed";
        session.ended_at_ms = received_at_ms;
    }
    if (session.state.empty()) session.state = "observed";
    session.revision = rev;
    session.updated_at_ms = received_at_ms;
    session.last_event = std::move(stored_event);
    session.events.push_back(session.last_event);
    while (session.events.size() > session_event_limit_) session.events.pop_front();
    prune_session_history();
}

nlohmann::json SessionStore::session_json(const Session& session, const bool include_events) {
    auto result = nlohmann::json{
        {"id", session.id},
        {"label", session.label},
        {"state", session.state},
        {"revision", session.revision},
        {"started_at_ms", session.started_at_ms},
        {"updated_at_ms", session.updated_at_ms},
        {"ended_at_ms", session.ended_at_ms},
        {"event_count", session.events.size()},
        {"last_event", session.last_event},
    };
    if (include_events) result["events"] = session.events;
    return result;
}

void SessionStore::prune_session_history() {
    auto completed_count = static_cast<std::size_t>(
        std::count_if(sessions_.begin(), sessions_.end(),
            [](const auto& entry) { return entry.second.state == "completed"; }));
    while (completed_count > session_history_limit_) {
        const auto removable = std::find_if(session_order_.begin(), session_order_.end(),
            [this](const std::string& id) {
                const auto entry = sessions_.find(id);
                return entry == sessions_.end() || entry->second.state == "completed";
            });
        if (removable == session_order_.end()) break;
        sessions_.erase(*removable);
        session_order_.erase(removable);
        --completed_count;
    }
}

nlohmann::json SessionStore::status() const {
    std::scoped_lock lock(mutex_);
    const auto state = smithproxy_status_.value("state", "starting");
    return {
        {"revision", revision_},
        {"ready", state == "connected"},
        {"smithproxy", smithproxy_status_},
        {"active_sessions", std::count_if(sessions_.begin(), sessions_.end(),
            [](const auto& entry) { return entry.second.state != "completed"; })},
        {"callbacks_received", callback_count_},
        {"last_callback_revision", last_callback_revision_},
        {"last_callback", {
            {"received_at_ms", last_callback_at_ms_},
            {"action", last_callback_action_},
            {"source", last_callback_source_},
        }},
    };
}

nlohmann::json SessionStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    auto rows = nlohmann::json::array();
    for (auto order = session_order_.rbegin(); order != session_order_.rend(); ++order) {
        const auto session = sessions_.find(*order);
        if (session != sessions_.end() && session->second.state != "completed") {
            rows.push_back(session_json(session->second, false));
        }
    }
    return {{"revision", revision_}, {"sessions", std::move(rows)}};
}

nlohmann::json SessionStore::session_history() const {
    std::scoped_lock lock(mutex_);
    auto rows = nlohmann::json::array();
    for (auto order = session_order_.rbegin(); order != session_order_.rend(); ++order) {
        if (const auto session = sessions_.find(*order); session != sessions_.end()) {
            rows.push_back(session_json(session->second, false));
        }
    }
    return {{"revision", revision_}, {"limit", session_history_limit_},
            {"sessions", std::move(rows)}};
}

std::optional<nlohmann::json> SessionStore::session_detail(const std::string& id) const {
    std::scoped_lock lock(mutex_);
    const auto session = sessions_.find(id);
    if (session == sessions_.end()) return std::nullopt;
    return std::optional<nlohmann::json>{session_json(session->second, true)};
}

std::size_t SessionStore::clear_completed_sessions() {
    std::scoped_lock lock(mutex_);
    std::size_t removed{};
    std::erase_if(session_order_, [this, &removed](const std::string& id) {
        const auto session = sessions_.find(id);
        if (session != sessions_.end() && session->second.state == "completed") {
            sessions_.erase(session);
            ++removed;
            return true;
        }
        return session == sessions_.end();
    });
    return removed;
}

nlohmann::json SessionStore::events_after(const std::uint64_t revision) const {
    std::scoped_lock lock(mutex_);
    auto events = nlohmann::json::array();
    for (const auto& record : history_) {
        if (record.revision > revision) {
            events.push_back({{"revision", record.revision}, {"event", record.event}});
        }
    }
    return {{"revision", revision_}, {"events", std::move(events)}};
}

std::uint64_t SessionStore::revision() const {
    std::scoped_lock lock(mutex_);
    return revision_;
}

} // namespace spider
