#pragma once

#include <cstdint>
#include <chrono>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace sift {

struct Match {
    std::string signature;
    std::size_t begin{};
    std::size_t end{};
};

struct Verdict {
    std::string action{"accept"};
    std::vector<Match> matches;
};

class Runtime {
public:
    [[nodiscard]] Verdict inspect(std::string_view session, char side,
                                  std::string_view payload);
    void close(std::string_view session);
    [[nodiscard]] nlohmann::json status() const;

private:
    struct Flow {
        std::string left;
        std::string right;
    };

    mutable std::mutex lock_;
    std::unordered_map<std::string, Flow> flows_;
    const std::chrono::steady_clock::time_point started_{std::chrono::steady_clock::now()};
    std::unordered_map<std::string, std::uint64_t> signature_matches_;
    std::uint64_t flows_seen_{};
    std::uint64_t flows_closed_{};
    std::uint64_t payloads_{};
    std::uint64_t bytes_{};
    std::uint64_t matches_{};
    std::uint64_t matched_payloads_{};
    std::uint64_t left_payloads_{};
    std::uint64_t left_bytes_{};
    std::uint64_t right_payloads_{};
    std::uint64_t right_bytes_{};
    std::uint64_t accepted_{};
    std::uint64_t last_payload_size_{};
    std::uint64_t min_payload_size_{std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t max_payload_size_{};
    std::uint64_t inspection_samples_{};
    std::uint64_t inspection_total_ns_{};
    std::uint64_t inspection_last_ns_{};
    std::uint64_t inspection_min_ns_{std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t inspection_max_ns_{};
};

[[nodiscard]] nlohmann::json verdict_json(const Verdict& verdict);

} // namespace sift
