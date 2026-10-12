#include <sift/engine.hpp>
#include <binary_envelope.hpp>

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
}

int main() {
    sift::Runtime runtime;
    auto first = runtime.inspect("flow-1", 'L', "PRI * HTTP/2.0\r\n");
    check(first.matches.empty(), "fragment must remain pending");
    auto second = runtime.inspect("flow-1", 'L', "\r\nSM\r\n\r\n");
    check(second.matches.size() == 1, "fragmented HTTP/2 preface must match");
    check(second.matches.front().signature == "protocol.http2.preface", "wrong match");

    const auto live_stats = runtime.status();
    check(live_stats.at("flows").at("active") == 1, "active flow not counted");
    check(live_stats.at("traffic").at("payloads") == 2, "payloads not counted");
    check(live_stats.at("signatures").at("by_name").at("protocol.http2.preface") == 1,
          "signature count missing");
    check(live_stats.at("timing").at("inspection_us").at("samples") == 2,
          "inspection timing samples missing");
    runtime.record_engine_delay(std::chrono::microseconds(125));
    const auto timed_stats = runtime.status();
    check(timed_stats.at("timing").at("engine_delay_us").at("samples") == 1,
          "engine delay timing samples missing");
    check(timed_stats.at("timing").at("engine_delay_us").at("last") == 125.0,
          "engine delay timing value is wrong");

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
    return failures == 0 ? 0 : 1;
}
