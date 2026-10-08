#include "session_store.hpp"

#include <algorithm>

namespace spider {

SessionStore::SessionStore(const std::size_t history_limit)
    : history_limit_(std::max<std::size_t>(history_limit, 1)) {}

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

    std::scoped_lock lock(mutex_);
    const auto rev = ++revision_;
    history_.push_back({rev, event});
    while (history_.size() > history_limit_) history_.pop_front();

    if (action == "spider-smithproxy-status") {
        smithproxy_status_ = event;
    } else {
        ++callback_count_;
        last_callback_revision_ = rev;
    }

    if (id.empty()) return;
    if (action == "connection-stop") {
        sessions_.erase(id);
        return;
    }

    auto& session = sessions_[id];
    session.id = id;
    const auto label = session_label(event);
    if (!label.empty()) session.label = label;
    session.state = action == "connection-start" ? "active" : session.state;
    if (session.state.empty()) session.state = "observed";
    session.revision = rev;
    session.last_event = event;
}

nlohmann::json SessionStore::status() const {
    std::scoped_lock lock(mutex_);
    const auto state = smithproxy_status_.value("state", "starting");
    return {
        {"revision", revision_},
        {"ready", state == "connected"},
        {"smithproxy", smithproxy_status_},
        {"active_sessions", sessions_.size()},
        {"callbacks_received", callback_count_},
        {"last_callback_revision", last_callback_revision_},
    };
}

nlohmann::json SessionStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    auto rows = nlohmann::json::array();
    for (const auto& [id, session] : sessions_) {
        rows.push_back({
            {"id", id},
            {"label", session.label},
            {"state", session.state},
            {"revision", session.revision},
            {"last_event", session.last_event},
        });
    }
    return {{"revision", revision_}, {"sessions", std::move(rows)}};
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
