#include "decision_broker.hpp"

#include <algorithm>
#include <vector>

namespace spider {

DecisionBroker::DecisionBroker(const std::chrono::milliseconds timeout) : timeout_(timeout) {}

std::shared_ptr<DecisionBroker::Ticket> DecisionBroker::prepare(nlohmann::json& event) {
    if (event.value("action", "") != "connection-content") return {};
    const auto session = event.value("id", "");
    std::scoped_lock lock(mutex_);
    if (!enabled_ || session.empty() || accepted_sessions_.contains(session)) return {};
    for (auto& rule : auto_accept_rules_) {
        if (rule.filter.matches(event)) {
            ++rule.matches;
            event["decision"] = {{"state", "auto-accepted"}, {"rule_id", rule.id},
                                 {"filter", rule.expression}};
            return {};
        }
    }
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

nlohmann::json DecisionBroker::set_auto_accept_rules(const nlohmann::json& message) {
    std::vector<AutoAcceptRule> next;
    auto accepted = nlohmann::json::array();
    auto errors = nlohmann::json::array();
    if (const auto rules = message.find("rules"); rules != message.end() && rules->is_array()) {
        for (const auto& rule : *rules) {
            if (!rule.is_object() || !rule.value("enabled", true)) continue;
            const auto id = rule.value("id", "");
            const auto expression = rule.value("filter", "");
            std::string error;
            auto compiled = SessionFilter::compile(expression, error);
            if (id.empty()) {
                errors.push_back({{"id", id}, {"error", "rule id is empty"}});
            } else if (!compiled) {
                errors.push_back({{"id", id}, {"error", error}});
            } else {
                accepted.push_back(id);
                next.push_back({id, expression, std::move(*compiled)});
            }
        }
    }
    {
        std::scoped_lock lock(mutex_);
        for (auto& rule : next) {
            const auto previous = std::find_if(auto_accept_rules_.begin(), auto_accept_rules_.end(),
                [&rule](const AutoAcceptRule& existing) {
                    return existing.id == rule.id && existing.expression == rule.expression;
                });
            if (previous != auto_accept_rules_.end()) rule.matches = previous->matches;
        }
        auto_accept_rules_ = std::move(next);
    }
    auto status = auto_accept_rule_status();
    status["accepted"] = std::move(accepted);
    status["errors"] = std::move(errors);
    return status;
}

nlohmann::json DecisionBroker::auto_accept_rule_status() const {
    std::scoped_lock lock(mutex_);
    auto counts = nlohmann::json::array();
    for (const auto& rule : auto_accept_rules_) {
        counts.push_back({{"id", rule.id}, {"matches", rule.matches}});
    }
    return {{"type", "auto-accept-rules-status"}, {"counts", std::move(counts)}};
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
