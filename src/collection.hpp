#pragma once
#include <filesystem>
#include <mutex>
#include <nlohmann/json.hpp>

namespace spider {
// Bounded, original-input snapshots. Collection never changes a traffic decision.
class Collection {
public:
    explicit Collection(std::filesystem::path root = {}, std::uint64_t limit = 1024ULL * 1024 * 1024);
    void capture(const nlohmann::json& event, const nlohmann::json& enrichments,
                 const nlohmann::json& session);
    nlohmann::json status() const;
    nlohmann::json list(std::size_t offset = 0) const;
    nlohmann::json read(const std::string& id) const;
private:
    std::filesystem::path root_;
    std::uint64_t limit_, bytes_{}, saved_{}, errors_{};
    std::string last_error_;
    mutable std::mutex mutex_;
};
}
