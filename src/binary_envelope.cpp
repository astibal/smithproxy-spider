#include "binary_envelope.hpp"

#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <string_view>

namespace spider {
namespace {

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

} // namespace

bool decode_sxbn(const std::string& body, nlohmann::json& event,
                 std::string& payload, std::string& error) {
    constexpr std::size_t prefix_size = 25;
    if (body.size() < prefix_size || !std::string_view(body).starts_with(sxbn_magic)) {
        error = "missing SXBN001 envelope";
        return false;
    }
    if (body[16] != ':') {
        error = "invalid SXBN length separator";
        return false;
    }
    std::uint32_t json_size{};
    std::uint32_t payload_size{};
    const auto json_first = body.data() + sxbn_magic.size();
    const auto json_last = body.data() + 16;
    const auto payload_first = body.data() + 17;
    const auto payload_last = body.data() + prefix_size;
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
    const auto content_size = static_cast<std::uint64_t>(json_size) + payload_size;
    if (content_size != body.size() - prefix_size) {
        error = "SXBN envelope length mismatch";
        return false;
    }
    try {
        event = nlohmann::json::parse(body.begin() + static_cast<std::ptrdiff_t>(prefix_size),
                                      body.begin() + static_cast<std::ptrdiff_t>(prefix_size + json_size));
    } catch (const nlohmann::json::exception&) {
        error = "invalid SXBN JSON metadata";
        return false;
    }
    if (!event.is_object() || event.value("action", "") != "connection-content") {
        error = "SXBN is only valid for connection-content";
        return false;
    }
    auto& info = event["details"]["info"];
    if (!info.is_object() || info.contains("content")) {
        error = "invalid SXBN connection-content metadata";
        return false;
    }
    const auto payload_offset = prefix_size + json_size;
    if (info.value("payload_length", payload_size) != payload_size) {
        error = "SXBN payload length mismatch";
        return false;
    }
    info["payload_encoding"] = "sxbn-001";
    info["payload_length"] = payload_size;
    payload.assign(body.data() + static_cast<std::ptrdiff_t>(payload_offset), payload_size);
    return true;
}

bool decode_sxbn(const std::string& body, nlohmann::json& event, std::string& error) {
    std::string payload;
    if (!decode_sxbn(body, event, payload, error)) return false;
    event["details"]["info"]["content"] = base64_encode(payload);
    return true;
}

} // namespace spider
