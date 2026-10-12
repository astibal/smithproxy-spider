#include <sift/engine.hpp>

#include <algorithm>
#include <array>

namespace sift {
namespace {

struct FixedSignature {
    std::string_view name;
    std::string_view bytes;
};

// Bootstrap set. The full compiled-pack loader will replace this table; keeping
// it here makes the daemon and its stateful API independently testable first.
constexpr std::array fixed_signatures{
    FixedSignature{"protocol.amqp.v091", std::string_view{"AMQP\0\0\x09\x01", 8}},
    FixedSignature{"protocol.http2.preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
    FixedSignature{"protocol.ssh.banner", "SSH-"},
};

constexpr std::size_t timing_median_window = 4096;

void append_timing_sample(std::deque<std::uint64_t>& samples, const std::uint64_t value) {
    if (samples.size() == timing_median_window) samples.pop_front();
    samples.push_back(value);
}

double median_us(const std::deque<std::uint64_t>& samples) {
    if (samples.empty()) return 0.0;
    std::vector<std::uint64_t> ordered(samples.begin(), samples.end());
    const auto middle = ordered.begin() + static_cast<std::ptrdiff_t>(ordered.size() / 2);
    std::nth_element(ordered.begin(), middle, ordered.end());
    if (ordered.size() % 2 != 0) return static_cast<double>(*middle) / 1000.0;
    const auto lower = *std::max_element(ordered.begin(), middle);
    return (static_cast<double>(lower) + static_cast<double>(*middle)) / 2000.0;
}

} // namespace

Verdict Runtime::inspect(const std::string_view session, const char side,
                         const std::string_view payload) {
    const auto inspection_started = std::chrono::steady_clock::now();
    std::scoped_lock guard(lock_);
    auto [flow_it, inserted] = flows_.try_emplace(std::string(session));
    if (inserted) ++flows_seen_;
    auto& stream = side == 'R' || side == 'w' ? flow_it->second.right : flow_it->second.left;
    const auto old_size = stream.size();
    stream.append(payload);
    ++payloads_;
    bytes_ += payload.size();
    last_payload_size_ = payload.size();
    min_payload_size_ = std::min(min_payload_size_, static_cast<std::uint64_t>(payload.size()));
    max_payload_size_ = std::max(max_payload_size_, static_cast<std::uint64_t>(payload.size()));
    if (side == 'R' || side == 'w') {
        ++right_payloads_;
        right_bytes_ += payload.size();
    } else {
        ++left_payloads_;
        left_bytes_ += payload.size();
    }

    Verdict verdict;
    for (const auto& signature : fixed_signatures) {
        const auto position = stream.find(signature.bytes);
        if (position == std::string::npos || position + signature.bytes.size() <= old_size) continue;
        verdict.matches.push_back({std::string(signature.name), position,
                                   position + signature.bytes.size() - 1});
        ++matches_;
        ++signature_matches_[std::string(signature.name)];
    }
    if (!verdict.matches.empty()) ++matched_payloads_;
    ++accepted_;
    const auto elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - inspection_started).count());
    ++inspection_samples_;
    inspection_total_ns_ += elapsed;
    inspection_last_ns_ = elapsed;
    inspection_min_ns_ = std::min(inspection_min_ns_, elapsed);
    inspection_max_ns_ = std::max(inspection_max_ns_, elapsed);
    append_timing_sample(inspection_recent_ns_, elapsed);
    return verdict;
}

void Runtime::record_engine_delay(const std::chrono::nanoseconds elapsed) {
    const auto value = static_cast<std::uint64_t>(elapsed.count());
    std::scoped_lock guard(lock_);
    ++engine_delay_samples_;
    engine_delay_total_ns_ += value;
    engine_delay_last_ns_ = value;
    engine_delay_min_ns_ = std::min(engine_delay_min_ns_, value);
    engine_delay_max_ns_ = std::max(engine_delay_max_ns_, value);
    append_timing_sample(engine_delay_recent_ns_, value);
}

void Runtime::close(const std::string_view session) {
    std::scoped_lock guard(lock_);
    if (flows_.erase(std::string(session)) > 0) ++flows_closed_;
}

nlohmann::json Runtime::status() const {
    std::scoped_lock guard(lock_);
    auto signatures = nlohmann::json::object();
    for (const auto& signature : fixed_signatures) {
        const auto found = signature_matches_.find(std::string(signature.name));
        signatures[signature.name] = found == signature_matches_.end() ? 0 : found->second;
    }
    const auto uptime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_).count();
    const auto average_payload = payloads_ == 0 ? 0.0
        : static_cast<double>(bytes_) / static_cast<double>(payloads_);
    const auto ns_to_us = [](const std::uint64_t value) {
        return static_cast<double>(value) / 1000.0;
    };
    const auto average_inspection = inspection_samples_ == 0 ? 0.0
        : ns_to_us(inspection_total_ns_) / static_cast<double>(inspection_samples_);
    const auto average_engine_delay = engine_delay_samples_ == 0 ? 0.0
        : ns_to_us(engine_delay_total_ns_) / static_cast<double>(engine_delay_samples_);
    return {
        {"service", "sx-siftd"}, {"engine", "bootstrap-ng"}, {"uptime_ms", uptime},
        {"flows", {{"active", flows_.size()}, {"seen", flows_seen_},
                   {"closed", flows_closed_}}},
        {"traffic", {{"payloads", payloads_}, {"bytes", bytes_},
                     {"sides", {{"L", {{"payloads", left_payloads_}, {"bytes", left_bytes_}}},
                                {"R", {{"payloads", right_payloads_}, {"bytes", right_bytes_}}}}}}},
        {"payload_size_bytes", {{"last", last_payload_size_},
                                {"min", payloads_ == 0 ? 0 : min_payload_size_},
                                {"max", max_payload_size_}, {"average", average_payload}}},
        {"signatures", {{"matches", matches_}, {"matched_payloads", matched_payloads_},
                        {"by_name", std::move(signatures)}}},
        {"decisions", {{"accept", accepted_}, {"replace", 0}, {"discard", 0}}},
        {"timing", {{"inspection_us", {{"samples", inspection_samples_},
                                         {"last", ns_to_us(inspection_last_ns_)},
                                         {"min", inspection_samples_ == 0 ? 0.0 : ns_to_us(inspection_min_ns_)},
                                         {"max", ns_to_us(inspection_max_ns_)},
                                         {"median", median_us(inspection_recent_ns_)},
                                         {"median_samples", inspection_recent_ns_.size()},
                                         {"average", average_inspection}}},
                    {"engine_delay_us", {{"samples", engine_delay_samples_},
                                          {"last", ns_to_us(engine_delay_last_ns_)},
                                          {"min", engine_delay_samples_ == 0 ? 0.0 : ns_to_us(engine_delay_min_ns_)},
                                          {"max", ns_to_us(engine_delay_max_ns_)},
                                          {"median", median_us(engine_delay_recent_ns_)},
                                          {"median_samples", engine_delay_recent_ns_.size()},
                                          {"average", average_engine_delay}}},
                    {"round_trip_us", nullptr},
                    {"round_trip_status", "requires Smithproxy/broker telemetry"}}}
    };
}

nlohmann::json verdict_json(const Verdict& verdict) {
    auto matches = nlohmann::json::array();
    for (const auto& match : verdict.matches) {
        matches.push_back({{"signature", match.signature}, {"begin", match.begin},
                           {"end", match.end}});
    }
    return {{"action", verdict.action}, {"matches", std::move(matches)},
            {"engine", "sx-siftd"}};
}

} // namespace sift
