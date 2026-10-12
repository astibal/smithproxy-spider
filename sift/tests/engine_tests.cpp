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

    runtime.close("flow-1");
    check(runtime.status().at("flows") == 0, "closed flow retained");

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
