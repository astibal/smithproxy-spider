#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

inline constexpr std::string_view sxbn_magic{"SXBN001:"};

struct SxbnEnvelope {
    nlohmann::json metadata;
    std::string payload;
};

[[nodiscard]] std::string encode_sxbn(const nlohmann::json& metadata,
                                      std::string_view payload = {});
[[nodiscard]] bool decode_sxbn_chain(std::string_view wire,
                                     std::vector<SxbnEnvelope>& envelopes,
                                     std::string& error);
[[nodiscard]] std::string base64_encode(std::string_view input);

[[nodiscard]] bool decode_sxbn(const std::string& body, nlohmann::json& event,
                               std::string& error);
[[nodiscard]] bool decode_sxbn(const std::string& body, nlohmann::json& event,
                               std::string& payload, std::string& error);

} // namespace spider
