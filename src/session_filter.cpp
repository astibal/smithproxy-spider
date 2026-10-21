#include "session_filter.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <string_view>

namespace spider {
namespace {

struct Endpoint {
    std::string protocol;
    std::string host;
    std::uint16_t port{};
};

struct Connection {
    Endpoint source;
    Endpoint destination;
    std::string side;
};

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::optional<Endpoint> parse_endpoint(const std::string_view text) {
    const auto separator = text.find('_');
    if (separator == std::string_view::npos) return std::nullopt;
    Endpoint result;
    result.protocol = lower(std::string(text.substr(0, separator)));
    auto address = text.substr(separator + 1);
    std::string_view port_text;
    if (address.starts_with('[')) {
        const auto bracket = address.find(']');
        if (bracket == std::string_view::npos || bracket + 1 >= address.size() ||
            address[bracket + 1] != ':') return std::nullopt;
        result.host = lower(std::string(address.substr(1, bracket - 1)));
        port_text = address.substr(bracket + 2);
    } else {
        const auto colon = address.rfind(':');
        if (colon == std::string_view::npos) return std::nullopt;
        result.host = lower(std::string(address.substr(0, colon)));
        port_text = address.substr(colon + 1);
    }
    unsigned int port{};
    const auto converted = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (converted.ec != std::errc{} || converted.ptr != port_text.data() + port_text.size() ||
        port > 65535U) return std::nullopt;
    result.port = static_cast<std::uint16_t>(port);
    return result;
}

std::optional<Connection> connection_from(const nlohmann::json& event) {
    const auto details = event.find("details");
    if (details == event.end() || !details->is_object()) return std::nullopt;
    const auto info = details->find("info");
    if (info == details->end() || !info->is_object()) return std::nullopt;
    const auto label = info->value("session", "");
    const auto separator = label.find('+');
    if (separator == std::string::npos) return std::nullopt;
    auto source = parse_endpoint(std::string_view(label).substr(0, separator));
    auto destination = parse_endpoint(std::string_view(label).substr(separator + 1));
    if (!source || !destination) return std::nullopt;
    return Connection{std::move(*source), std::move(*destination), info->value("side", "")};
}

std::vector<std::string> tokenize(const std::string& expression, std::string& error) {
    std::vector<std::string> tokens;
    std::size_t cursor{};
    while (cursor < expression.size()) {
        if (std::isspace(static_cast<unsigned char>(expression[cursor]))) {
            ++cursor;
            continue;
        }
        if (expression[cursor] == '(' || expression[cursor] == ')') {
            tokens.emplace_back(1, expression[cursor++]);
            continue;
        }
        const auto begin = cursor;
        while (cursor < expression.size() &&
               !std::isspace(static_cast<unsigned char>(expression[cursor])) &&
               expression[cursor] != '(' && expression[cursor] != ')') ++cursor;
        tokens.push_back(lower(expression.substr(begin, cursor - begin)));
    }
    if (tokens.empty()) error = "filter is empty";
    return tokens;
}

class Parser {
public:
    Parser(std::vector<std::string> tokens, std::string& error)
        : tokens_(std::move(tokens)), error_(error) {}

    bool parse() {
        if (!parse_or()) return false;
        if (cursor_ != tokens_.size()) {
            error_ = "unexpected token: " + tokens_[cursor_];
            return false;
        }
        return true;
    }

    std::vector<SessionFilter::Instruction> finish() { return std::move(program_); }

private:
    bool take(const std::string_view token) {
        if (cursor_ >= tokens_.size() || tokens_[cursor_] != token) return false;
        ++cursor_;
        return true;
    }

    bool parse_or() {
        if (!parse_and()) return false;
        while (take("or")) {
            if (!parse_and()) return fail("expected expression after or");
            program_.push_back({SessionFilter::Operation::logical_or, {}});
        }
        return true;
    }

    bool parse_and() {
        if (!parse_unary()) return false;
        while (take("and")) {
            if (!parse_unary()) return fail("expected expression after and");
            program_.push_back({SessionFilter::Operation::logical_and, {}});
        }
        return true;
    }

    bool parse_unary() {
        if (take("not")) {
            if (!parse_unary()) return fail("expected expression after not");
            program_.push_back({SessionFilter::Operation::logical_not, {}});
            return true;
        }
        if (take("(")) {
            if (!parse_or()) return false;
            if (!take(")")) return fail("missing closing parenthesis");
            return true;
        }
        return parse_predicate();
    }

    bool parse_predicate() {
        if (cursor_ >= tokens_.size()) return fail("expected filter predicate");
        const auto first = tokens_[cursor_++];
        if (first == "tcp" || first == "udp" || first == "quic" ||
            first == "ssli" || first == "ssl") {
            program_.push_back({SessionFilter::Operation::protocol, first});
            return true;
        }
        if (first == "side") return string_value(SessionFilter::Operation::side, "side");
        if (first == "host") return string_value(SessionFilter::Operation::host, "host");
        if (first == "port") return port_value(SessionFilter::Operation::port, "port");
        if (first == "src" || first == "dst") {
            if (cursor_ >= tokens_.size()) return fail("expected host or port after " + first);
            const auto kind = tokens_[cursor_++];
            if (kind == "host") return string_value(first == "src" ? SessionFilter::Operation::src_host : SessionFilter::Operation::dst_host, first + " host");
            if (kind == "port") return port_value(first == "src" ? SessionFilter::Operation::src_port : SessionFilter::Operation::dst_port, first + " port");
            return fail("expected host or port after " + first);
        }
        return fail("unknown predicate: " + first);
    }

    bool string_value(const SessionFilter::Operation operation, const std::string& label) {
        if (cursor_ >= tokens_.size()) return fail("expected value after " + label);
        program_.push_back({operation, tokens_[cursor_++]});
        return true;
    }

    bool port_value(const SessionFilter::Operation operation, const std::string& label) {
        if (cursor_ >= tokens_.size()) return fail("expected port after " + label);
        const auto& text = tokens_[cursor_++];
        unsigned int port{};
        const auto converted = std::from_chars(text.data(), text.data() + text.size(), port);
        if (converted.ec != std::errc{} || converted.ptr != text.data() + text.size() || port > 65535U)
            return fail("invalid port: " + text);
        program_.push_back({operation, {}, static_cast<std::uint16_t>(port)});
        return true;
    }

    bool fail(std::string message) {
        error_ = std::move(message);
        return false;
    }

    std::vector<std::string> tokens_;
    std::size_t cursor_{};
    std::string& error_;
    std::vector<SessionFilter::Instruction> program_;
};

bool protocol_matches(const std::string& filter, const Connection& connection) {
    if (filter == "tcp") return connection.source.protocol != "udp" &&
                                connection.source.protocol != "quic";
    if (filter == "ssl") return connection.source.protocol == "ssl" ||
                                connection.source.protocol == "ssli";
    return connection.source.protocol == filter;
}

} // namespace

std::optional<std::string> SessionFilter::endpoint_key(const nlohmann::json& event, bool source) {
    const auto connection = connection_from(event);
    if (!connection) return std::nullopt;
    const auto& endpoint = source ? connection->source : connection->destination;
    if (endpoint.host.empty()) return std::nullopt;
    return source ? endpoint.host : endpoint.protocol + "://[" + endpoint.host + "]:" + std::to_string(endpoint.port);
}

std::optional<SessionFilter> SessionFilter::compile(const std::string& expression,
                                                    std::string& error) {
    error.clear();
    auto tokens = tokenize(expression, error);
    if (!error.empty()) return std::nullopt;
    Parser parser(std::move(tokens), error);
    if (!parser.parse()) return std::nullopt;
    return SessionFilter(parser.finish());
}

bool SessionFilter::matches(const nlohmann::json& event) const {
    const auto connection = connection_from(event);
    if (!connection) return false;
    std::vector<bool> stack;
    for (const auto& instruction : program_) {
        const auto unary = instruction.operation == Operation::logical_not;
        const auto binary = instruction.operation == Operation::logical_and ||
                            instruction.operation == Operation::logical_or;
        if (unary) {
            if (stack.empty()) return false;
            stack.back() = !stack.back();
            continue;
        }
        if (binary) {
            if (stack.size() < 2) return false;
            const auto right = stack.back(); stack.pop_back();
            const auto left = stack.back(); stack.pop_back();
            stack.push_back(instruction.operation == Operation::logical_and ? left && right : left || right);
            continue;
        }
        bool result{};
        switch (instruction.operation) {
        case Operation::protocol: result = protocol_matches(instruction.value, *connection); break;
        case Operation::host: result = connection->source.host == instruction.value || connection->destination.host == instruction.value; break;
        case Operation::src_host: result = connection->source.host == instruction.value; break;
        case Operation::dst_host: result = connection->destination.host == instruction.value; break;
        case Operation::port: result = connection->source.port == instruction.port || connection->destination.port == instruction.port; break;
        case Operation::src_port: result = connection->source.port == instruction.port; break;
        case Operation::dst_port: result = connection->destination.port == instruction.port; break;
        case Operation::side: result = lower(connection->side) == instruction.value; break;
        default: return false;
        }
        stack.push_back(result);
    }
    return stack.size() == 1 && stack.back();
}

} // namespace spider
