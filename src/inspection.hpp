#pragma once
#include <atomic>
#include <mutex>
#include <map>
#include <memory>
#include <set>
#include <chrono>
#include <nlohmann/json.hpp>
#include "collection.hpp"

namespace spider {
class InspectionPool;
class Inspection {
public:
    explicit Inspection(std::filesystem::path collection_root = {});
    nlohmann::json configure(const nlohmann::json& request);
    nlohmann::json status() const;
    bool has_enabled_scripts() const {
        std::scoped_lock lock(mutex_);
        if (!chain_mode_) return enabled_;
        for (const auto& item : chain_) if (item.value("enabled", false)) return true;
        return false;
    }
    nlohmann::json run(nlohmann::json request);
    nlohmann::json language(nlohmann::json request);
    nlohmann::json automatic(const nlohmann::json& event, const nlohmann::json& enrichments);
    Collection collection;
private:
    struct Instance {
        nlohmann::json state = nlohmann::json::object();
        std::chrono::steady_clock::time_point used = std::chrono::steady_clock::now();
        std::size_t bytes{2};
        nlohmann::json holds = nlohmann::json::object(); // L/R typed Parts checkpoints
    };
    struct Runtime {
        std::shared_ptr<InspectionPool> pool;
        std::timed_mutex serial;
        std::atomic_uint waiting{}, active{}, instances{};
        std::atomic_bool retired{};
        std::atomic_uint64_t rejected{}, state_bytes{};
        std::map<std::string, Instance> states; // guarded by serial
        unsigned consecutive_errors{}, consecutive_slow{};
    };
    nlohmann::json run_instance(const nlohmann::json& item, const nlohmann::json& event,
                               const nlohmann::json& enrichments, int remaining, bool hold_allowed);
    nlohmann::json run_request(nlohmann::json request, const std::shared_ptr<InspectionPool>& pool);
    void expire_instances(Runtime& runtime, int idle_seconds) const;
    void clear_flow(const std::string& id);
    std::map<std::string, std::shared_ptr<Runtime>> runtimes_;
    std::shared_ptr<InspectionPool> legacy_pool_;
    std::filesystem::path storage_root_;
    nlohmann::json notifications_ = nlohmann::json::array();
    std::uint64_t next_notification_{};
    std::set<std::string> closed_flows_;
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
    std::atomic_uint analyzing_{};
};
}
