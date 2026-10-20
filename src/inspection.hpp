#pragma once
#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include "collection.hpp"

namespace spider {
class Inspection {
public:
    explicit Inspection(std::filesystem::path collection_root = {}) : collection(std::move(collection_root)) {}
    nlohmann::json configure(const nlohmann::json& request);
    nlohmann::json status() const;
    nlohmann::json run(nlohmann::json request);
    nlohmann::json automatic(const nlohmann::json& event, const nlohmann::json& enrichments);
    Collection collection;
private:
    mutable std::mutex mutex_;
    std::string source_;
    std::string scope_{"rules"};
    bool enabled_{};
    bool chain_mode_{};
    std::uint64_t revision_{}, runs_{}, errors_{};
    nlohmann::json recent_ = nlohmann::json::array();
    nlohmann::json chain_ = nlohmann::json::array();
    std::uint64_t next_script_id_{};
    std::atomic_uint running_{};
};
}
