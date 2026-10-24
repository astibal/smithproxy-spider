#include "session_store.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <tuple>

namespace spider {
namespace {
std::int64_t unix_time_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string normalized_hostname(std::string hostname) {
    while (!hostname.empty() && hostname.back() == '.') hostname.pop_back();
    std::ranges::transform(hostname, hostname.begin(),
                           [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return hostname;
}

std::size_t hostname_levels(const std::string& hostname) {
    return hostname.empty() ? 0 : 1 + static_cast<std::size_t>(std::ranges::count(hostname, '.'));
}

std::size_t leaf_length(const std::string& hostname) {
    const auto separator = hostname.find('.');
    return separator == std::string::npos ? hostname.size() : separator;
}

bool preferred_hostname(const std::string& lhs, const std::string& rhs) {
    return std::tuple{hostname_levels(lhs), leaf_length(lhs), lhs.size(), lhs} <
           std::tuple{hostname_levels(rhs), leaf_length(rhs), rhs.size(), rhs};
}

const nlohmann::json* classification_array(
    const nlohmann::json& event, const std::string_view source) {
    const nlohmann::json* current = &event;
    for (const auto* key : {"details", "info", "classification"}) {
        if (!current->is_object()) return nullptr;
        const auto found = current->find(key);
        if (found == current->end()) return nullptr;
        current = &*found;
    }
    if (!current->is_object()) return nullptr;
    const auto found = current->find(source);
    if (found == current->end()) return nullptr;
    current = &*found;
    return current->is_array() ? current : nullptr;
}

void retain_classifications(std::unordered_set<std::string>& target,
                            const nlohmann::json* classifications) {
    if (classifications == nullptr) return;
    for (const auto& classification : *classifications) {
        if (classification.is_string() &&
            !classification.get_ref<const std::string&>().empty()) {
            target.insert(classification.get<std::string>());
        }
    }
}

std::string classification_status(
    const nlohmann::json& event, const std::string_view source) {
    const nlohmann::json* current = &event;
    for (const auto* key : {"details", "info", "classification"}) {
        if (!current->is_object()) return {};
        const auto found = current->find(key);
        if (found == current->end()) return {};
        current = &*found;
    }

    const auto found = current->find(source);
    return found != current->end() && found->is_string()
        ? found->get<std::string>() : std::string{};
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

std::uint64_t SessionStore::apply(const nlohmann::json& event,
                                  const std::optional<std::string_view> raw_payload,
                                  const std::vector<SxbnEnvelope>& enrichments) {
    const auto action = event.value("action", "");
    const auto id = event.value("id", "");
    auto stored_event = event;
    const auto received_at_ms = unix_time_ms();
    stored_event["spider_received_at_ms"] = received_at_ms;

    std::uint64_t rev{};
    std::function<void(std::uint64_t, const nlohmann::json&,
                       std::optional<std::string_view>,
                       const std::vector<SxbnEnvelope>&)> sink;
    {
        std::scoped_lock lock(mutex_);
        rev = ++revision_;
        history_.push_back({rev, stored_event});
        while (history_.size() > history_limit_) {
            history_.pop_front();
            ++history_evicted_;
        }

        if (action == "hostname-info") apply_hostname_info(event);

        if (action == "spider-smithproxy-status") {
            smithproxy_status_ = stored_event;
        } else {
            ++callback_count_;
            last_callback_revision_ = rev;
            last_callback_at_ms_ = received_at_ms;
            last_callback_action_ = action;
            last_callback_source_ = event.value("source", "");
            ++callbacks_by_action_[action.empty() ? "<empty>" : action];
            ++callbacks_by_source_[last_callback_source_.empty() ? "<empty>" : last_callback_source_];
        }

        if (!id.empty()) {
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
            session.last_event = stored_event;
            session.events.push_back(session.last_event);
            retain_classifications(
                session.sift_classifications, classification_array(event, "sift"));
            retain_classifications(
                session.lored_classifications, classification_array(event, "lored"));
            if (auto status = classification_status(event, "lored_status");
                !status.empty()) session.lored_status = std::move(status);
            while (session.events.size() > session_event_limit_) {
                session.events.pop_front();
                ++session_events_evicted_;
            }
            prune_session_history();
        }
        sink = event_sink_;
    }
    if (sink) sink(rev, stored_event, raw_payload, enrichments);
    return rev;
}

void SessionStore::apply_hostname_info(const nlohmann::json& event) {
    const nlohmann::json* list = nullptr;
    if (const auto details = event.find("details"); details != event.end() && details->is_object()) {
        if (const auto info = details->find("info"); info != details->end() && info->is_object()) {
            if (const auto found = info->find("list"); found != info->end()) list = &*found;
        }
    }
    if (list == nullptr || !list->is_array()) return;
    bool changed = false;
    for (const auto& item : *list) {
        if (!item.is_object() || !item.contains("hostname") || !item["hostname"].is_string() ||
            !item.contains("address") || !item["address"].is_array()) continue;
        const auto hostname = normalized_hostname(item["hostname"].get<std::string>());
        if (hostname.empty()) continue;
        const auto origin = item.contains("origin") && item["origin"].is_string()
                                ? item["origin"].get<std::string>() : std::string{};
        const auto type = item.contains("type") && item["type"].is_string()
                              ? item["type"].get<std::string>() : std::string{};
        for (const auto& address : item["address"]) {
            if (!address.is_string() || address.get_ref<const std::string&>().empty()) continue;
            auto& observations = reverse_hostnames_[address.get<std::string>()];
            const auto [position, inserted] = observations.try_emplace(hostname);
            changed |= inserted;
            if (!origin.empty()) changed |= position->second.origins.insert(origin).second;
            if (!type.empty()) changed |= position->second.types.insert(type).second;
        }
    }
    if (changed) ++hostname_revision_;
}

void SessionStore::set_event_sink(
                                  std::function<void(std::uint64_t, const nlohmann::json&,
                                                     std::optional<std::string_view>,
                                                     const std::vector<SxbnEnvelope>&)> sink,
                                  const bool replay_existing) {
    std::scoped_lock lock(mutex_);
    event_sink_ = std::move(sink);
    if (event_sink_ && replay_existing) {
        const std::vector<SxbnEnvelope> no_enrichments;
        for (const auto& record : history_) {
            event_sink_(record.revision, record.event, std::nullopt, no_enrichments);
        }
    }
}

nlohmann::json SessionStore::session_json(const Session& session, const bool include_events) {
    auto sift_classifications = std::vector<std::string>(
        session.sift_classifications.begin(), session.sift_classifications.end());
    std::ranges::sort(sift_classifications);
    auto lored_classifications = std::vector<std::string>(
        session.lored_classifications.begin(), session.lored_classifications.end());
    std::ranges::sort(lored_classifications);
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
        {"classification", {
            {"sift", std::move(sift_classifications)},
            {"lored", std::move(lored_classifications)},
            {"lored_status", session.lored_status},
        }},
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
        ++sessions_evicted_;
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
        {"hostname_revision", hostname_revision_},
        {"last_callback", {
            {"received_at_ms", last_callback_at_ms_},
            {"action", last_callback_action_},
            {"source", last_callback_source_},
        }},
    };
}

nlohmann::json SessionStore::diagnostics() const {
    std::scoped_lock lock(mutex_);
    std::size_t active{};
    std::size_t completed{};
    std::size_t observed{};
    for (const auto& [_, session] : sessions_) {
        if (session.state == "completed") ++completed;
        else if (session.state == "active") ++active;
        else ++observed;
    }
    nlohmann::json actions = nlohmann::json::object();
    for (const auto& [name, count] : callbacks_by_action_) actions[name] = count;
    nlohmann::json sources = nlohmann::json::object();
    for (const auto& [name, count] : callbacks_by_source_) sources[name] = count;
    return {
        {"revision", revision_},
        {"callbacks", {
            {"received", callback_count_},
            {"last_revision", last_callback_revision_},
            {"last_received_at_ms", last_callback_at_ms_},
            {"by_action", std::move(actions)},
            {"by_source", std::move(sources)},
        }},
        {"event_history", {
            {"retained", history_.size()}, {"limit", history_limit_},
            {"evicted", history_evicted_},
            {"oldest_revision", history_.empty() ? 0 : history_.front().revision},
            {"newest_revision", history_.empty() ? 0 : history_.back().revision},
        }},
        {"sessions", {
            {"retained", sessions_.size()}, {"active", active},
            {"observed", observed}, {"completed", completed},
            {"completed_limit", session_history_limit_},
            {"sessions_evicted", sessions_evicted_},
            {"events_per_session_limit", session_event_limit_},
            {"session_events_evicted", session_events_evicted_},
        }},
        {"hostnames", {{"revision", hostname_revision_}, {"addresses", reverse_hostnames_.size()}}},
    };
}

nlohmann::json SessionStore::reverse_hostnames() const {
    std::scoped_lock lock(mutex_);
    auto mappings = nlohmann::json::object();
    for (const auto& [address, observations] : reverse_hostnames_) {
        if (observations.empty()) continue;
        auto candidates = std::vector<std::string>{};
        candidates.reserve(observations.size());
        for (const auto& observation : observations) candidates.push_back(observation.first);
        std::ranges::sort(candidates, preferred_hostname);
        auto entries = nlohmann::json::array();
        for (const auto& hostname : candidates) {
            const auto& observation = observations.at(hostname);
            auto origins = std::vector<std::string>(observation.origins.begin(), observation.origins.end());
            auto types = std::vector<std::string>(observation.types.begin(), observation.types.end());
            std::ranges::sort(origins);
            std::ranges::sort(types);
            entries.push_back({{"hostname", hostname}, {"origins", std::move(origins)},
                               {"types", std::move(types)}});
        }
        mappings[address] = {{"preferred", candidates.front()}, {"candidates", std::move(candidates)},
                             {"entries", std::move(entries)}};
    }
    return {{"revision", hostname_revision_}, {"mappings", std::move(mappings)}};
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
