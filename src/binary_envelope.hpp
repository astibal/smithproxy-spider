#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace spider {

inline constexpr std::string_view sxbn_magic{"SXBN001:"};

[[nodiscard]] bool decode_sxbn(const std::string& body, nlohmann::json& event,
                               std::string& error);
[[nodiscard]] bool decode_sxbn(const std::string& body, nlohmann::json& event,
                               std::string& payload, std::string& error);

} // namespace spider
