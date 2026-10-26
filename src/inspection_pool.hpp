#pragma once
#include <memory>
#include <string>
#include <nlohmann/json.hpp>

namespace spider {
// Owned by one deployment generation. Never shared with another script/version.
class InspectionPool {
public:
    InspectionPool(std::string source, std::string storage);
    ~InspectionPool();
    void warm();
    void retire();
    nlohmann::json run(nlohmann::json request, int timeout_ms);
    nlohmann::json status() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
