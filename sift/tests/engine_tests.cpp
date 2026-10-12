#include <sift/engine.hpp>
#include <binary_envelope.hpp>

#include <algorithm>
#include <cstdio>
#include <iostream>

namespace {
int failures{};
void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

bool has_match(const sift::Verdict& verdict, const std::string_view signature) {
    return std::any_of(verdict.matches.begin(), verdict.matches.end(),
                       [signature](const sift::Match& match) {
                           return match.signature == signature;
                       });
}
}

int main() {
    sift::Runtime runtime;
    auto first = runtime.inspect("flow-1", 'L', "PRI * HTTP/2.0\r\n");
    check(first.matches.empty(), "fragment must remain pending");
    auto second = runtime.inspect("flow-1", 'L', "\r\nSM\r\n\r\n");
    check(second.matches.size() == 1, "fragmented HTTP/2 preface must match");
    check(second.matches.front().signature == "protocol.http2.prior-knowledge", "wrong match");

    const auto live_stats = runtime.status();
    check(live_stats.at("flows").at("active") == 1, "active flow not counted");
    check(live_stats.at("traffic").at("payloads") == 2, "payloads not counted");
    check(live_stats.at("signatures").at("by_name").at("protocol.http2.prior-knowledge") == 1,
          "signature count missing");
    check(live_stats.at("signatures").at("loaded") == 19,
          "loaded signature count is wrong");
    check(live_stats.at("timing").at("engine_delay_us").at("samples") == 2,
          "engine timing samples missing");
    runtime.record_total_delay(std::chrono::microseconds(125));
    const auto timed_stats = runtime.status();
    check(timed_stats.at("timing").at("total_delay_us").at("samples") == 1,
          "total delay timing samples missing");
    check(timed_stats.at("timing").at("total_delay_us").at("last") == 125.0,
          "total delay timing value is wrong");
    check(timed_stats.at("timing").at("total_delay_us").at("median") == 125.0,
          "total delay median is wrong");
    check(timed_stats.at("timing").at("engine_delay_us").at("median_samples") == 2,
          "engine median sample count is wrong");

    runtime.close("flow-1");
    const auto closed_stats = runtime.status();
    check(closed_stats.at("flows").at("active") == 0, "closed flow retained");
    check(closed_stats.at("flows").at("closed") == 1, "closed flow not counted");

    const std::string metadata = R"({"action":"connection-content","id":"x","details":{"info":{"session":"x","side":"L","payload_length":8}}})";
    char prefix[26]{};
    std::snprintf(prefix, sizeof(prefix), "SXBN001:%08X:%08X",
                  static_cast<unsigned>(metadata.size()), 8U);
    std::string wire(prefix, 25);
    wire += metadata;
    wire.append("AMQP\0\0\x09\x01", 8);
    nlohmann::json event;
    std::string payload;
    std::string error;
    check(spider::decode_sxbn(wire, event, payload, error), "SXBN decode failed");
    check(payload.size() == 8, "SXBN payload lost");
    check(runtime.inspect("x", 'L', payload).matches.size() == 1, "AMQP did not match");

    check(has_match(runtime.inspect("http1", 'L', "GET / HTTP/1.1\r\n"),
                    "protocol.http1.request"), "HTTP/1 request did not match");
    check(has_match(runtime.inspect("smb2", 'R', std::string_view{"\0\0\0\0\xfeSMB", 8}),
                    "protocol.smb2.netbios"), "SMB2 did not match");
    check(runtime.inspect("ssh", 'L', "SSH-2.0-client\r\n").matches.empty(),
          "one-sided SSH banner matched too early");
    check(has_match(runtime.inspect("ssh", 'R', "SSH-2.0-server\r\n"),
                    "protocol.ssh.banner-both"), "bidirectional SSH did not match");
    check(has_match(runtime.inspect("ajp", 'L', std::string_view{"\x12\x34\0\x01\x0a", 5}),
                    "protocol.ajp13.ping"), "AJP ping did not match");
    check(has_match(runtime.inspect("memcache", 'L', "get key\r\n"),
                    "protocol.memcached.ascii"), "memcached ASCII did not match");
    return failures == 0 ? 0 : 1;
}
