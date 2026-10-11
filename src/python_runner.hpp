#pragma once

#include <nlohmann/json_fwd.hpp>

namespace spider {

[[nodiscard]] nlohmann::json run_python_script(const nlohmann::json& request);

} // namespace spider
