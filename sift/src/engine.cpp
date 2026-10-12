#include <sift/engine.hpp>

#include <algorithm>
#include <array>
#include <hs/hs.h>

namespace sift {
namespace {

using Matcher = bool (*)(std::string_view, std::string_view);

struct BootstrapSignature {
    std::string_view name;
    Matcher matches;
};

bool starts_with(const std::string_view value, const std::string_view prefix) {
    return value.starts_with(prefix);
}

bool at(const std::string_view value, const std::size_t offset,
        const std::string_view bytes) {
    return value.size() >= offset + bytes.size() && value.substr(offset, bytes.size()) == bytes;
}

bool either_at(const std::string_view left, const std::string_view right,
               const std::size_t offset, const std::string_view bytes) {
    return at(left, offset, bytes) || at(right, offset, bytes);
}

bool http_request(const std::string_view left, std::string_view) {
    constexpr std::array<std::string_view, 12> methods{
        "OPTIONS ", "GET ", "HEAD ", "POST ", "PUT ", "DELETE ",
        "CONNECT ", "PATCH ", "PROPFIND ", "PROPPATCH ", "TRACE ", "UPDATE "};
    return std::any_of(methods.begin(), methods.end(),
                       [left](const std::string_view method) { return starts_with(left, method); });
}

bool tls_hello(const std::string_view stream, const unsigned char handshake_type) {
    if (stream.size() < 11 || static_cast<unsigned char>(stream[0]) != 0x16 ||
        static_cast<unsigned char>(stream[1]) != 0x03 ||
        (static_cast<unsigned char>(stream[2]) & 0xf0U) != 0 ||
        static_cast<unsigned char>(stream[5]) != handshake_type) return false;
    const auto record_length = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(stream[3]) << 8U) |
        static_cast<unsigned char>(stream[4]));
    const auto handshake_length = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(stream[6]) << 16U) |
        (static_cast<unsigned char>(stream[7]) << 8U) |
        static_cast<unsigned char>(stream[8]));
    return record_length >= 4 && handshake_length + 4U <= record_length;
}

bool ssh_banner(const std::string_view stream) {
    const auto position = stream.find("SSH-");
    return position != std::string_view::npos && position <= 255 &&
           (position == 0 || stream[position - 1] == '\n');
}

bool memcached_ascii(const std::string_view left, std::string_view) {
    constexpr std::array<std::string_view, 15> commands{
        "get ", "gets ", "set ", "add ", "replace ", "append ", "prepend ",
        "cas ", "delete ", "incr ", "decr ", "touch ", "stats\r", "version\r",
        "flush_all"};
    return std::any_of(commands.begin(), commands.end(),
                       [left](const std::string_view command) { return starts_with(left, command); });
}

// Bootstrap subset of smithproxy-signature-pack. The compiled-pack loader will
// replace this table; these rules preserve direction and multi-clause flow semantics.
constexpr std::array bootstrap_signatures{
    BootstrapSignature{"protocol.http1.request", http_request},
    BootstrapSignature{"protocol.http1.response", [](std::string_view, const std::string_view r) { return starts_with(r, "HTTP/"); }},
    BootstrapSignature{"protocol.http2.prior-knowledge", [](const std::string_view l, std::string_view) { return starts_with(l, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); }},
    BootstrapSignature{"security.tls.client-hello", [](const std::string_view l, std::string_view) { return tls_hello(l, 1); }},
    BootstrapSignature{"security.tls.server-hello", [](std::string_view, const std::string_view r) { return tls_hello(r, 2); }},
    BootstrapSignature{"protocol.ssh.banner-both", [](const std::string_view l, const std::string_view r) { return ssh_banner(l) && ssh_banner(r); }},
    BootstrapSignature{"protocol.smb1.netbios", [](const std::string_view l, const std::string_view r) { return either_at(l, r, 4, std::string_view{"\xffSMB", 4}); }},
    BootstrapSignature{"protocol.smb2.netbios", [](const std::string_view l, const std::string_view r) { return either_at(l, r, 4, std::string_view{"\xfeSMB", 4}); }},
    BootstrapSignature{"protocol.smb3.encrypted", [](const std::string_view l, const std::string_view r) { return either_at(l, r, 4, std::string_view{"\xfdSMB", 4}); }},
    BootstrapSignature{"protocol.postgresql.sslrequest", [](const std::string_view l, const std::string_view r) { return starts_with(l, std::string_view{"\0\0\0\x08\x04\xd2\x16\x2f", 8}) && !r.empty() && (r[0] == 'S' || r[0] == 'N'); }},
    BootstrapSignature{"protocol.rfb.banner-both", [](const std::string_view l, const std::string_view r) { return starts_with(l, "RFB ") && starts_with(r, "RFB "); }},
    BootstrapSignature{"protocol.sip.dialog", [](const std::string_view l, const std::string_view r) { return (starts_with(l, "REGISTER ") || starts_with(l, "INVITE ") || starts_with(l, "BYE ") || starts_with(l, "OPTIONS ")) && starts_with(r, "SIP/2.0"); }},
    BootstrapSignature{"protocol.bittorrent.handshake", [](const std::string_view l, const std::string_view r) { return either_at(l, r, 0, std::string_view{"\x13" "BitTorrent protocol", 20}); }},
    BootstrapSignature{"protocol.amqp.v091", [](const std::string_view l, std::string_view) { return starts_with(l, std::string_view{"AMQP\0\0\x09\x01", 8}); }},
    BootstrapSignature{"protocol.amqp.v10", [](const std::string_view l, std::string_view) { return starts_with(l, std::string_view{"AMQP\0\x01\0\0", 8}); }},
    BootstrapSignature{"protocol.amqp.sasl", [](const std::string_view l, std::string_view) { return starts_with(l, std::string_view{"AMQP\x03\x01\0\0", 8}); }},
    BootstrapSignature{"protocol.ajp13.ping", [](const std::string_view l, std::string_view) { return starts_with(l, std::string_view{"\x12\x34\0\x01\x0a", 5}); }},
    BootstrapSignature{"protocol.ajp13.cpong", [](std::string_view, const std::string_view r) { return starts_with(r, std::string_view{"AB\0\x01\x09", 5}); }},
    BootstrapSignature{"protocol.memcached.ascii", memcached_ascii},
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
    const auto engine_started = std::chrono::steady_clock::now();
    std::scoped_lock guard(lock_);
    auto [flow_it, inserted] = flows_.try_emplace(std::string(session));
    if (inserted) ++flows_seen_;
    auto& stream = side == 'R' || side == 'w' ? flow_it->second.right : flow_it->second.left;
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
    for (const auto& signature : bootstrap_signatures) {
        if (flow_it->second.matches.contains(std::string(signature.name)) ||
            !signature.matches(flow_it->second.left, flow_it->second.right)) continue;
        flow_it->second.matches.emplace(signature.name);
        verdict.matches.push_back({std::string(signature.name), 0,
                                   stream.empty() ? 0 : stream.size() - 1});
        ++matches_;
        ++signature_matches_[std::string(signature.name)];
    }
    if (!verdict.matches.empty()) ++matched_payloads_;
    ++accepted_;
    const auto elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - engine_started).count());
    ++engine_delay_samples_;
    engine_delay_total_ns_ += elapsed;
    engine_delay_last_ns_ = elapsed;
    engine_delay_min_ns_ = std::min(engine_delay_min_ns_, elapsed);
    engine_delay_max_ns_ = std::max(engine_delay_max_ns_, elapsed);
    append_timing_sample(engine_delay_recent_ns_, elapsed);
    return verdict;
}

void Runtime::record_total_delay(const std::chrono::nanoseconds elapsed) {
    const auto value = static_cast<std::uint64_t>(elapsed.count());
    std::scoped_lock guard(lock_);
    ++total_delay_samples_;
    total_delay_total_ns_ += value;
    total_delay_last_ns_ = value;
    total_delay_min_ns_ = std::min(total_delay_min_ns_, value);
    total_delay_max_ns_ = std::max(total_delay_max_ns_, value);
    append_timing_sample(total_delay_recent_ns_, value);
}

void Runtime::close(const std::string_view session) {
    std::scoped_lock guard(lock_);
    if (flows_.erase(std::string(session)) > 0) ++flows_closed_;
}

nlohmann::json Runtime::status() const {
    std::scoped_lock guard(lock_);
    auto signatures = nlohmann::json::object();
    for (const auto& signature : bootstrap_signatures) {
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
    const auto average_engine_delay = engine_delay_samples_ == 0 ? 0.0
        : ns_to_us(engine_delay_total_ns_) / static_cast<double>(engine_delay_samples_);
    const auto average_total_delay = total_delay_samples_ == 0 ? 0.0
        : ns_to_us(total_delay_total_ns_) / static_cast<double>(total_delay_samples_);
    return {
        {"service", "sx-siftd"}, {"engine", "bootstrap-ng"},
        {"scanner", {{"name", "hyperscan"}, {"version", hs_version()}}},
        {"uptime_ms", uptime},
        {"flows", {{"active", flows_.size()}, {"seen", flows_seen_},
                   {"closed", flows_closed_}}},
        {"traffic", {{"payloads", payloads_}, {"bytes", bytes_},
                     {"sides", {{"L", {{"payloads", left_payloads_}, {"bytes", left_bytes_}}},
                                {"R", {{"payloads", right_payloads_}, {"bytes", right_bytes_}}}}}}},
        {"payload_size_bytes", {{"last", last_payload_size_},
                                {"min", payloads_ == 0 ? 0 : min_payload_size_},
                                {"max", max_payload_size_}, {"average", average_payload}}},
        {"signatures", {{"loaded", bootstrap_signatures.size()},
                        {"matches", matches_}, {"matched_payloads", matched_payloads_},
                        {"by_name", std::move(signatures)}}},
        {"decisions", {{"accept", accepted_}, {"replace", 0}, {"discard", 0}}},
        {"timing", {{"engine_delay_us", {{"samples", engine_delay_samples_},
                                          {"last", ns_to_us(engine_delay_last_ns_)},
                                          {"min", engine_delay_samples_ == 0 ? 0.0 : ns_to_us(engine_delay_min_ns_)},
                                          {"max", ns_to_us(engine_delay_max_ns_)},
                                          {"median", median_us(engine_delay_recent_ns_)},
                                          {"median_samples", engine_delay_recent_ns_.size()},
                                          {"average", average_engine_delay}}},
                    {"total_delay_us", {{"samples", total_delay_samples_},
                                         {"last", ns_to_us(total_delay_last_ns_)},
                                         {"min", total_delay_samples_ == 0 ? 0.0 : ns_to_us(total_delay_min_ns_)},
                                         {"max", ns_to_us(total_delay_max_ns_)},
                                         {"median", median_us(total_delay_recent_ns_)},
                                         {"median_samples", total_delay_recent_ns_.size()},
                                         {"average", average_total_delay}}},
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
