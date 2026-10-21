#pragma once
#include <array>
#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace spider {
// Bounded, per-connection admission guard. Times come from a monotonic backend clock.
class HeavyTraffic {
    using Clock = std::chrono::steady_clock;
    struct Bucket { std::int64_t tick{-1}; std::uint64_t messages{}, bytes{}; };
    struct Flow {
        Clock::time_point first, last;
        std::array<Bucket, 10> buckets{};
        std::optional<Clock::time_point> excessive;
        nlohmann::json stopped;
    };
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Flow> flows_;
    Clock::time_point sweep_{};
    nlohmann::json config_{{"enabled", false}, {"grace_seconds", 5}, {"messages_per_second", 200},
        {"bytes_per_second", 1048576}, {"sustain_seconds", 3}, {"include_managed", false}};
public:
    nlohmann::json status() const { std::scoped_lock lock(mutex_); return config_; }
    nlohmann::json configure(const nlohmann::json& request) {
        std::scoped_lock lock(mutex_);
        auto next = config_;
        for (const auto* name : {"enabled", "include_managed"}) if (request.contains(name)) {
            if (!request[name].is_boolean()) throw std::invalid_argument("Expected boolean setting");
            next[name] = request[name];
        }
        for (const auto* name : {"grace_seconds", "messages_per_second", "bytes_per_second", "sustain_seconds"})
            if (request.contains(name)) {
                if (!request[name].is_number_integer() || request[name] < 1 || request[name] > 1073741824)
                    throw std::invalid_argument("Invalid heavy traffic limit");
                next[name] = request[name];
            }
        if (next["grace_seconds"] < 5 || next["grace_seconds"] > 300 || next["sustain_seconds"] > 60)
            throw std::invalid_argument("Grace must be 5–300 s; sustain 1–60 s");
        config_ = next;
        // New settings start a fresh observation interval, never revoke a prior cutoff.
        std::erase_if(flows_, [](const auto& pair) { return pair.second.stopped.is_null(); });
        return config_;
    }
    void stop(const std::string& id) { std::scoped_lock lock(mutex_); flows_.erase(id); }
    nlohmann::json observe(const std::string& id, std::size_t bytes, bool managed,
                          Clock::time_point now = Clock::now()) {
        std::scoped_lock lock(mutex_);
        if (id.empty()) return nullptr;
        if (auto it = flows_.find(id); it != flows_.end() && !it->second.stopped.is_null())
            return {{"notice", it->second.stopped}, {"first", false}};
        if (!config_["enabled"].get<bool>() || (managed && !config_["include_managed"].get<bool>())) return nullptr;
        if (now - sweep_ > std::chrono::seconds(10)) {
            std::erase_if(flows_, [&](const auto& pair) { return now - pair.second.last > std::chrono::minutes(10); });
            sweep_ = now;
        }
        if (!flows_.contains(id) && flows_.size() >= 65536) return nullptr;
        auto [it, inserted] = flows_.try_emplace(id);
        auto& flow = it->second;
        if (inserted) flow.first = now;
        if (now - flow.last > std::chrono::seconds(1)) flow.excessive.reset();
        flow.last = now;
        // Do not count the grace interval towards the required sustained overload.
        if (now - flow.first < std::chrono::seconds(config_["grace_seconds"].get<int>())) return nullptr;
        const auto tick = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() / 100;
        auto& bucket = flow.buckets[static_cast<std::size_t>(tick % 10)];
        if (bucket.tick != tick) bucket = Bucket{tick, 0, 0};
        ++bucket.messages; bucket.bytes += bytes;
        std::uint64_t messages = 0, total = 0;
        for (const auto& entry : flow.buckets) if (entry.tick > tick - 10) { messages += entry.messages; total += entry.bytes; }
        const bool message_limit = messages > config_["messages_per_second"].get<std::uint64_t>();
        const bool byte_limit = total > config_["bytes_per_second"].get<std::uint64_t>();
        if (!message_limit && !byte_limit) { flow.excessive.reset(); return nullptr; }
        if (!flow.excessive) flow.excessive = now;
        if (now - *flow.excessive < std::chrono::seconds(config_["sustain_seconds"].get<int>())) return nullptr;
        flow.stopped = {{"reason", message_limit ? "messages/s" : "bytes/s"},
            {"messages_per_second", messages}, {"bytes_per_second", total}, {"limits", config_},
            {"stopped_at_ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()}};
        return {{"notice", flow.stopped}, {"first", true}};
    }
};
}
