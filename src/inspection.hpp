#pragma once
#include <atomic>
#include <mutex>
#include <map>
#include <memory>
#include <set>
#include <vector>
#include <chrono>
#include <nlohmann/json.hpp>
#include "collection.hpp"

namespace spider {
class InspectionPool;
class Inspection {
public:
    nlohmann::json server_lifecycle(const nlohmann::json& event);
    nlohmann::json http_connect(const nlohmann::json& event);
    bool authenticate(const nlohmann::json& event);
    explicit Inspection(std::filesystem::path collection_root = {});
    nlohmann::json configure(const nlohmann::json& request);
    nlohmann::json status() const;
    bool has_enabled_scripts() const {
        std::scoped_lock lock(mutex_);
        if (!chain_mode_) return enabled_;
        for (const auto& item : chain_) {
            if (item.value("enabled", false) && item.value("hook", "content") == "content") return true;
        }
        return false;
    }
    nlohmann::json run(nlohmann::json request);
    nlohmann::json language(nlohmann::json request);
    nlohmann::json content_view(const nlohmann::json& request);
    nlohmann::json automatic(const nlohmann::json& event, const nlohmann::json& enrichments);
    bool translation_required(const nlohmann::json& event) const;
    Collection collection;
private:
    struct Instance {
        nlohmann::json state = nlohmann::json::object();
        std::chrono::steady_clock::time_point used = std::chrono::steady_clock::now();
        std::size_t bytes{2};
        nlohmann::json holds = nlohmann::json::object(); // L/R typed Parts checkpoints
        nlohmann::json translations = nlohmann::json::object(); // L/R HPACK tables
        nlohmann::json h1_responses = nullptr; // ordered origin/local response slots
        bool hold_credit_reserved = false; // backend-owned until this instance ends
        nlohmann::json protocols = nullptr; // opt-in Spider-local protocol observations
    };
    static std::size_t state_charge(const nlohmann::json& state, const nlohmann::json& holds,
                                   const nlohmann::json& translations,
                                   const nlohmann::json& h1_responses, bool reserved,
                                   const nlohmann::json& protocols);
    struct Runtime {
        std::shared_ptr<InspectionPool> pool;
        std::timed_mutex serial;
        std::atomic_uint waiting{}, active{}, instances{};
        std::atomic_bool retired{};
        std::atomic_uint64_t rejected{}, state_bytes{};
        std::map<std::string, Instance> states; // guarded by serial
        std::set<std::string> addon_connections; // guarded by serial; successful setup only
        bool addon{}; // fixed before publication
        unsigned consecutive_errors{}, consecutive_slow{};
    };
    nlohmann::json run_instance(const nlohmann::json& item, const nlohmann::json& event,
                               const nlohmann::json& enrichments, int remaining, bool hold_allowed,
                               bool translate_allowed = false, bool translate_active = false);
    nlohmann::json run_addon_preview(nlohmann::json request);
    nlohmann::json run_request(nlohmann::json request, const std::shared_ptr<InspectionPool>& pool);
    nlohmann::json record_result(const nlohmann::json& request, nlohmann::json result);
    void expire_instances(Runtime& runtime, int idle_seconds) const;
    void clear_flow(const std::string& id);
    void record_shutdown(const std::string& id, const std::shared_ptr<InspectionPool>& pool);

    // Keep the deployment generation alive until its CONNECT exchange ends.
    struct ConnectOwner {
        std::string deployment;
        std::shared_ptr<Runtime> runtime;
        int timeout_ms;
    };

    struct ConnectPin {
        std::timed_mutex serial;
        std::vector<ConnectOwner> owners;
        bool requested = false;
        bool finished = false;
        bool failed = false;
    };

    std::map<std::string, std::shared_ptr<ConnectPin>> connect_pins_; // guarded by mutex_
    std::map<std::string, std::shared_ptr<Runtime>> runtimes_;
    std::shared_ptr<InspectionPool> legacy_pool_;
    std::filesystem::path storage_root_;
    nlohmann::json notifications_ = nlohmann::json::array();
    std::uint64_t next_notification_{};
    std::set<std::string> closed_flows_;
    struct TranslationPin {
        std::string deployment;
        nlohmann::json version;
        bool failed{false};
        std::uint64_t sequence{};
    };
    std::map<std::string, TranslationPin> translations_; // guarded by mutex_
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
