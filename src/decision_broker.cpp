#include "decision_broker.hpp"

#include <vector>

namespace spider {

DecisionBroker::DecisionBroker(const std::chrono::milliseconds timeout) : timeout_(timeout) {}

std::shared_ptr<DecisionBroker::Ticket> DecisionBroker::prepare(nlohmann::json& event) {
    if (event.value("action", "") != "connection-content") return {};
    const auto session = event.value("id", "");
    std::scoped_lock lock(mutex_);
    if (!enabled_ || session.empty() || accepted_sessions_.contains(session)) return {};
    auto ticket = std::make_shared<Ticket>();
    ticket->id = "decision-" + std::to_string(++next_id_);
    ticket->session_id = session;
    pending_[ticket->id] = ticket;
    event["decision"] = {{"id", ticket->id}, {"state", "pending"},
                         {"timeout_ms", timeout_.count()}};
    return ticket;
}

WebhookReply DecisionBroker::wait(const std::shared_ptr<Ticket>& ticket) {
    if (!ticket) return {200, {{"action", "unchanged"}}};
    std::unique_lock lock(mutex_);
    if (!ticket->ready.wait_for(lock, timeout_, [&] { return ticket->decided; })) {
        pending_.erase(ticket->id);
        return {200, {{"action", "unchanged"}, {"decision", "timeout"}}};
    }
    pending_.erase(ticket->id);
    if (ticket->result.action == "discard") return {200, {{"action", "discard"}}};
    if (ticket->result.action == "replace") {
        return {200, {{"action", "replace"}, {"content", ticket->result.content}}};
    }
    return {200, {{"action", "unchanged"}}};
}

void DecisionBroker::resolve_locked(const std::shared_ptr<Ticket>& ticket, Result result) {
    if (ticket->decided) return;
    ticket->result = std::move(result);
    ticket->decided = true;
    ticket->ready.notify_all();
}

void DecisionBroker::resolve_all_locked() {
    for (const auto& [id, ticket] : pending_) resolve_locked(ticket, {});
}

void DecisionBroker::handle_message(const nlohmann::json& message) {
    const auto type = message.value("type", "");
    std::scoped_lock lock(mutex_);
    if (type == "live-edit") {
        enabled_ = message.value("enabled", false);
        if (!enabled_) {
            accepted_sessions_.clear();
            resolve_all_locked();
        }
        return;
    }
    if (type == "inspect-session") {
        accepted_sessions_.erase(message.value("session_id", ""));
        return;
    }
    if (type != "decision") return;
    const auto position = pending_.find(message.value("decision_id", ""));
    if (position == pending_.end()) return;
    const auto action = message.value("action", "accept");
    if (action == "accept-session") {
        const auto session = position->second->session_id;
        accepted_sessions_.insert(session);
        for (const auto& [id, ticket] : pending_) {
            if (ticket->session_id == session) resolve_locked(ticket, {});
        }
    } else if (action == "discard") {
        resolve_locked(position->second, {"discard", {}});
    } else if (action == "replace" && message.contains("content") && message["content"].is_string()) {
        resolve_locked(position->second, {"replace", message["content"].get<std::string>()});
    } else {
        resolve_locked(position->second, {});
    }
}

void DecisionBroker::observe(const nlohmann::json& event) {
    if (event.value("action", "") != "connection-stop") return;
    std::scoped_lock lock(mutex_);
    accepted_sessions_.erase(event.value("id", ""));
}

bool DecisionBroker::enabled() const {
    std::scoped_lock lock(mutex_);
    return enabled_;
}

} // namespace spider
