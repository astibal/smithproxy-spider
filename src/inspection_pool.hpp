#pragma once
#include <memory>
#include <string>
#include <nlohmann/json.hpp>

namespace spider {
// Owned by one deployment generation. Never shared with another script/version.
class InspectionPool {
public:
    enum class Lifetime {
        Rotating,
        Generation,
    };

    InspectionPool(std::string source, std::string storage,
                   Lifetime lifetime = Lifetime::Rotating,
                   std::string script_api = "spider",
                   nlohmann::json addon_options = nlohmann::json::array(),
                   bool network_enabled = false,
                   std::string hook = "content");
    ~InspectionPool();
    void warm();
    void retire();
    nlohmann::json run(nlohmann::json request, int timeout_ms);
    nlohmann::json status() const;
    nlohmann::json take_shutdown_report();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
