#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

class SessionFilter {
public:
    static std::optional<SessionFilter> compile(const std::string& expression,
                                                std::string& error);
    [[nodiscard]] bool matches(const nlohmann::json& event) const;
    static std::optional<std::string> endpoint_key(const nlohmann::json& event, bool source);
    enum class Operation {
        protocol, host, src_host, dst_host, port, src_port, dst_port, side,
        logical_and, logical_or, logical_not,
    };
    struct Instruction {
        Operation operation;
        std::string value;
        std::uint16_t port{};
    };

private:
    explicit SessionFilter(std::vector<Instruction> program)
        : program_(std::move(program)) {}

    std::vector<Instruction> program_;
};

} // namespace spider
