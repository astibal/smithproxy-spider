#pragma once

#include <cstdint>
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
    std::uint64_t payloads_{};
    std::uint64_t bytes_{};
    std::uint64_t matches_{};
};

[[nodiscard]] nlohmann::json verdict_json(const Verdict& verdict);

} // namespace sift
