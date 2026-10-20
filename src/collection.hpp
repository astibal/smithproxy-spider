#pragma once
#include <filesystem>
#include <mutex>
#include <map>
#include <nlohmann/json.hpp>

namespace spider {
// Bounded, original-input snapshots. Collection never changes a traffic decision.
class Collection {
public:
    explicit Collection(std::filesystem::path root = {}, std::uint64_t limit = 1024ULL * 1024 * 1024);
    void capture(const nlohmann::json& event, const nlohmann::json& enrichments,
                 const nlohmann::json& session);
    nlohmann::json status() const;
    nlohmann::json list(std::size_t offset = 0, const std::string& query = "") const;
    nlohmann::json read(const std::string& id) const;
    nlohmann::json save_flow(nlohmann::json snapshot);
    nlohmann::json list_flows(std::size_t offset = 0) const;
    nlohmann::json read_flow(const std::string& id) const;
private:
    std::filesystem::path root_;
    std::uint64_t limit_, bytes_{}, saved_{}, errors_{};
    std::string last_error_;
    mutable std::mutex mutex_;
    struct CachedSummary {
        std::filesystem::file_time_type modified;
        std::uintmax_t size;
        nlohmann::json value;
    };
    mutable std::mutex summary_mutex_;
    mutable std::map<std::string, CachedSummary> summaries_;
    nlohmann::json describe(const std::string& id) const;
};
}
