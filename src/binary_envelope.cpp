#include "binary_envelope.hpp"

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace spider {

std::string base64_encode(const std::string_view input) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve((input.size() + 2) / 3 * 4);
    for (std::size_t offset = 0; offset < input.size(); offset += 3) {
        const auto a = static_cast<std::uint8_t>(input[offset]);
        const auto b = offset + 1 < input.size()
            ? static_cast<std::uint8_t>(input[offset + 1]) : 0U;
        const auto c = offset + 2 < input.size()
            ? static_cast<std::uint8_t>(input[offset + 2]) : 0U;
        const auto value = (static_cast<unsigned>(a) << 16U) |
                           (static_cast<unsigned>(b) << 8U) | c;
        output.push_back(alphabet[(value >> 18U) & 63U]);
        output.push_back(alphabet[(value >> 12U) & 63U]);
        output.push_back(offset + 1 < input.size() ? alphabet[(value >> 6U) & 63U] : '=');
        output.push_back(offset + 2 < input.size() ? alphabet[value & 63U] : '=');
    }
    return output;
}

namespace {

bool decode_envelope(const std::string_view wire, const std::size_t offset,
                     SxbnEnvelope& envelope, std::size_t& consumed,
                     std::string& error) {
    constexpr std::size_t prefix_size = 25;
    const auto remaining = wire.substr(offset);
    if (remaining.size() < prefix_size || !remaining.starts_with(sxbn_magic)) {
        error = "missing SXBN001 envelope";
        return false;
    }
    if (remaining[16] != ':') {
        error = "invalid SXBN length separator";
        return false;
    }
    std::uint32_t json_size{};
    std::uint32_t payload_size{};
    const auto json_first = remaining.data() + sxbn_magic.size();
    const auto json_last = remaining.data() + 16;
    const auto payload_first = remaining.data() + 17;
    const auto payload_last = remaining.data() + prefix_size;
    const auto parsed_json = std::from_chars(json_first, json_last, json_size, 16);
    const auto parsed_payload = std::from_chars(payload_first, payload_last, payload_size, 16);
    if (parsed_json.ec != std::errc{} || parsed_json.ptr != json_last) {
        error = "invalid SXBN JSON length";
        return false;
    }
    if (parsed_payload.ec != std::errc{} || parsed_payload.ptr != payload_last) {
        error = "invalid SXBN payload length";
        return false;
    }
    const auto body_size = static_cast<std::uint64_t>(json_size) + payload_size;
    if (body_size > remaining.size() - prefix_size) {
        error = "truncated SXBN envelope";
        return false;
    }
    try {
        envelope.metadata = nlohmann::json::parse(
            remaining.begin() + static_cast<std::ptrdiff_t>(prefix_size),
            remaining.begin() + static_cast<std::ptrdiff_t>(prefix_size + json_size));
    } catch (const nlohmann::json::exception&) {
        error = "invalid SXBN JSON metadata";
        return false;
    }
    if (!envelope.metadata.is_object()) {
        error = "SXBN metadata must be an object";
        return false;
    }
    envelope.payload.assign(remaining.data() + prefix_size + json_size, payload_size);
    consumed = prefix_size + static_cast<std::size_t>(body_size);
    return true;
}

} // namespace

std::string encode_sxbn(const nlohmann::json& metadata, const std::string_view payload) {
    const auto json = metadata.dump();
    if (json.size() > std::numeric_limits<std::uint32_t>::max() ||
        payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("SXBN envelope field exceeds 32-bit length");
    }
    std::array<char, 26> prefix{};
    std::snprintf(prefix.data(), prefix.size(), "SXBN001:%08X:%08X",
                  static_cast<unsigned>(json.size()), static_cast<unsigned>(payload.size()));
    std::string wire(prefix.data(), 25);
    wire.reserve(25 + json.size() + payload.size());
    wire += json;
    wire.append(payload);
    return wire;
}

bool decode_sxbn_chain(const std::string_view wire,
                       std::vector<SxbnEnvelope>& envelopes, std::string& error) {
    envelopes.clear();
    if (wire.empty()) {
        error = "empty SXBN chain";
        return false;
    }
    std::size_t offset{};
    while (offset < wire.size()) {
        SxbnEnvelope envelope;
        std::size_t consumed{};
        if (!decode_envelope(wire, offset, envelope, consumed, error)) {
            envelopes.clear();
            return false;
        }
        envelopes.push_back(std::move(envelope));
        offset += consumed;
    }
    return true;
}

bool decode_sxbn(const std::string& body, nlohmann::json& event,
                 std::string& payload, std::string& error) {
    std::vector<SxbnEnvelope> envelopes;
    if (!decode_sxbn_chain(body, envelopes, error)) return false;
    if (envelopes.size() != 1) {
        error = "callback requires exactly one SXBN envelope";
        return false;
    }
    event = std::move(envelopes.front().metadata);
    payload = std::move(envelopes.front().payload);
    if (event.value("action", "") != "connection-content") {
        error = "SXBN is only valid for connection-content";
        return false;
    }
    auto& info = event["details"]["info"];
    if (!info.is_object() || info.contains("content")) {
        error = "invalid SXBN connection-content metadata";
        return false;
    }
    if (info.value("payload_length", payload.size()) != payload.size()) {
        error = "SXBN payload length mismatch";
        return false;
    }
    info["payload_encoding"] = "sxbn-001";
    info["payload_length"] = payload.size();
    return true;
}

bool decode_sxbn(const std::string& body, nlohmann::json& event, std::string& error) {
    std::string payload;
    if (!decode_sxbn(body, event, payload, error)) return false;
    event["details"]["info"]["content"] = base64_encode(payload);
    return true;
}

} // namespace spider
