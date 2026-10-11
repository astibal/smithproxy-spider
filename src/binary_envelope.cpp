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

bool decode_sxbn(const std::string& body, nlohmann::json& event, std::string& error) {
    constexpr std::size_t prefix_size = 16;
    if (body.size() < prefix_size || !std::string_view(body).starts_with(sxbn_magic)) {
        error = "missing SXBN001 envelope";
        return false;
    }
    std::uint32_t json_size{};
    const auto first = body.data() + sxbn_magic.size();
    const auto last = body.data() + prefix_size;
    const auto parsed = std::from_chars(first, last, json_size, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != last || json_size > body.size() - prefix_size) {
        error = "invalid SXBN JSON length";
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
    const auto payload_size = body.size() - payload_offset;
    if (info.value("payload_length", payload_size) != payload_size) {
        error = "SXBN payload length mismatch";
        return false;
    }
    info["payload_encoding"] = "sxbn-001";
    info["payload_length"] = payload_size;
    info["content"] = base64_encode(std::string_view(body).substr(payload_offset));
    return true;
}

} // namespace spider
