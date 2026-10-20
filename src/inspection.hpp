#pragma once
#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>

namespace spider {
class Inspection {
public:
    nlohmann::json configure(const nlohmann::json& request);
    nlohmann::json status() const;
    nlohmann::json run(nlohmann::json request);
    nlohmann::json automatic(const nlohmann::json& event, const nlohmann::json& enrichments);
private:
    mutable std::mutex mutex_;
    std::string source_;
    std::string scope_{"rules"};
    bool enabled_{};
    std::uint64_t revision_{}, runs_{}, errors_{};
    nlohmann::json recent_ = nlohmann::json::array();
    std::atomic_uint running_{};
};
}
