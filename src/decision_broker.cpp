#include "decision_broker.hpp"

#include <algorithm>
#include <fnmatch.h>
#include <vector>

namespace spider {

DecisionBroker::DecisionBroker(const std::chrono::milliseconds timeout) : timeout_(timeout) {}

std::shared_ptr<DecisionBroker::Ticket> DecisionBroker::prepare(nlohmann::json& event) {
    if (event.value("action", "") != "connection-content") return {};
    event.erase("collections"); // only backend rules may select capture destinations
    const auto session = event.value("id", "");
    std::scoped_lock lock(mutex_);
    const auto focus_active = std::ranges::any_of(traffic_rules_,
        [](const TrafficRule& rule) { return rule.mode == "focus"; });
    TrafficRule* matched = nullptr;
    for (auto& rule : traffic_rules_) {
        const auto hostname_match = [&] {
            for (const auto& [address, names] : hostnames_) {
                const auto pattern = rule.kind == "hostname-suffix" ? "*." + rule.value : rule.value;
                if (!std::ranges::any_of(names, [&](const auto& name) {
                    return fnmatch(pattern.c_str(), name.c_str(), FNM_CASEFOLD) == 0 ||
                        (rule.kind == "hostname-suffix" && name == rule.value);
                })) continue;
                std::string error;
                auto filter = SessionFilter::compile("host " + address, error);
                if (filter && filter->matches(event)) return true;
            }
            return false;
        };
        const auto matches = rule.kind == "session" ? session == rule.value
            : (rule.kind == "hostname-glob" || rule.kind == "hostname-suffix")
            ? hostname_match()
            : rule.kind == "sift"
            ? session_classifications_[session].contains(rule.value)
            : rule.kind == "sift-glob"
            ? std::ranges::any_of(session_classifications_[session], [&](const auto& value) {
                  return fnmatch(rule.value.c_str(), value.c_str(), FNM_CASEFOLD) == 0;
              })
            : rule.filter && rule.filter->matches(event);
        if (matches) {
            if (rule.mode == "collect") {
                ++rule.matches;
                if (!event.contains("collections")) event["collections"] = nlohmann::json::array();
                event["collections"].push_back({{"id", rule.id}, {"endpoint", rule.value}});
                continue;
            }
            if (matched) continue;
            matched = &rule;
            ++rule.matches;
        }
    }
    if (bypass_all_) {
        event["decision"] = {{"state", "passed"}, {"reason", "bypass-all"}};
        return {};
    }
    if (matched && matched->mode == "forget") {
        // A collector still needs future callbacks; do not tell Smithproxy to stop them.
        event["decision"] = event.contains("collections")
            ? nlohmann::json{{"state", "passed"}, {"reason", "collection-retains-callbacks"}}
            : nlohmann::json{{"state", "forgotten"}, {"reason", "rule"}};
        return {};
    }
    if ((matched && matched->mode == "pass") || (!matched && focus_active)) {
        event["decision"] = {{"state", "passed"},
                             {"reason", matched ? "rule" : "focus-default"}};
        return {};
    }
    const auto inspect = matched && matched->mode == "inspect";
    if (matched) event["traffic_rule"] = {{"mode", matched->mode}, {"address", matched->address}};
    if ((!enabled_ && !(inspect && script_available_)) || session.empty() ||
        (accepted_sessions_.contains(session) && !inspect)) return {};
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
                         {"timeout_ms", timeout_.count()},
                         {"mode", inspect ? "inspect" : "live-edit"}};
    return ticket;
}

WebhookReply DecisionBroker::wait(const std::shared_ptr<Ticket>& ticket,
                                  const nlohmann::json& event) {
    if (!ticket) {
        const auto state = event.value("decision", nlohmann::json::object())
                               .value("state", "");
        if (state == "forgotten") return {200, {{"action", "not-interested"}}};
        return {200, {{"action", "unchanged"}}};
    }
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
    if (type == "script-available") {
        script_available_ = message.value("available", false);
        if (!script_available_) resolve_all_locked();
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

nlohmann::json DecisionBroker::set_traffic_rules(const nlohmann::json& message) {
    std::vector<TrafficRule> next;
    auto errors = nlohmann::json::array();
    if (const auto rules = message.find("rules"); rules != message.end() && rules->is_array()) {
        for (const auto& rule : *rules) {
            const auto id = rule.value("id", "");
            const auto kind = rule.value("kind", "address");
            const auto value = rule.value("value", "");
            const auto address = rule.value("address", "");
            auto mode = rule.value("mode", "");
            if (mode == "ignore") mode = "forget"; // migrate pre-FORGET clients
            std::string error;
            const auto sift_rule = kind == "sift" || kind == "sift-glob" ||
                (mode == "collect" && (kind == "session" || kind == "hostname-glob" || kind == "hostname-suffix"));
            const bool scope_filter = mode == "collect" && kind == "filter";
            auto filter = sift_rule ? std::optional<SessionFilter>{} : SessionFilter::compile(
                scope_filter ? value : "(src host " + address + " or dst host " + address + ")", error);
            if ((sift_rule || scope_filter ? value.empty() : address.empty()) ||
                (mode != "pass" && mode != "focus" && mode != "inspect" &&
                                    mode != "forget" && mode != "collect")) {
                errors.push_back({{"address", address}, {"error", "invalid address or mode"}});
            } else if (!sift_rule && !filter) {
                errors.push_back({{"address", address}, {"error", error}});
            } else {
                next.push_back({id.empty() ? mode + ":" + (sift_rule || scope_filter ? value : address) : id,
                                kind, sift_rule || scope_filter ? value : address, address, mode,
                                std::move(filter)});
            }
        }
    }
    if (!errors.empty()) {
        auto status = traffic_rule_status();
        status["errors"] = std::move(errors);
        return status;
    }
    {
        std::scoped_lock lock(mutex_);
        for (auto& rule : next) {
            const auto old = std::ranges::find_if(traffic_rules_, [&](const TrafficRule& existing) {
                return existing.id == rule.id && existing.kind == rule.kind &&
                       existing.value == rule.value && existing.address == rule.address &&
                       existing.mode == rule.mode;
            });
            if (old != traffic_rules_.end()) rule.matches = old->matches;
        }
        traffic_rules_ = std::move(next);
        bypass_all_ = message.value("bypass_all", false);
    }
    auto status = traffic_rule_status();
    status["errors"] = std::move(errors);
    return status;
}

nlohmann::json DecisionBroker::traffic_rule_status() const {
    std::scoped_lock lock(mutex_);
    auto rules = nlohmann::json::array();
    for (const auto& rule : traffic_rules_) {
        rules.push_back({{"id", rule.id}, {"kind", rule.kind}, {"value", rule.value},
                         {"address", rule.address},
                         {"mode", rule.mode}, {"matches", rule.matches}});
    }
    return {{"type", "traffic-rules-status"}, {"bypass_all", bypass_all_},
            {"rules", std::move(rules)}};
}

void DecisionBroker::observe(const nlohmann::json& event) {
    std::scoped_lock lock(mutex_);
    if (event.value("action", "") == "hostname-info") {
        const auto list = event.value("details", nlohmann::json::object())
            .value("info", nlohmann::json::object()).value("list", nlohmann::json::array());
        for (const auto& item : list) {
            if (!item.is_object() || !item.value("address", nlohmann::json::array()).is_array()) continue;
            auto name = item.value("hostname", "");
            if (name.empty()) continue;
            if (name.back() == '.') name.pop_back();
            for (const auto& address : item["address"])
                if (address.is_string() && hostnames_.size() < 10000) hostnames_[address.get<std::string>()].insert(name);
        }
    }
    const auto session = event.value("id", "");
    if (event.value("action", "") == "connection-stop") {
        accepted_sessions_.erase(session);
        session_classifications_.erase(session);
        return;
    }
    const auto classifications = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object())
        .value("classification", nlohmann::json::object())
        .value("sift", nlohmann::json::array());
    if (!classifications.is_array()) return;
    for (const auto& classification : classifications) {
        if (classification.is_string()) session_classifications_[session].insert(
            classification.get<std::string>());
    }
}

bool DecisionBroker::enabled() const {
    std::scoped_lock lock(mutex_);
    return enabled_;
}

} // namespace spider
