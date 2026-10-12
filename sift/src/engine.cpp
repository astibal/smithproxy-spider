#include <sift/engine.hpp>

#include <array>

namespace sift {
namespace {

struct FixedSignature {
    std::string_view name;
    std::string_view bytes;
};

// Bootstrap set. The full compiled-pack loader will replace this table; keeping
// it here makes the daemon and its stateful API independently testable first.
constexpr std::array fixed_signatures{
    FixedSignature{"protocol.amqp.v091", std::string_view{"AMQP\0\0\x09\x01", 8}},
    FixedSignature{"protocol.http2.preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
    FixedSignature{"protocol.ssh.banner", "SSH-"},
};

} // namespace

Verdict Runtime::inspect(const std::string_view session, const char side,
                         const std::string_view payload) {
    std::scoped_lock guard(lock_);
    auto& flow = flows_[std::string(session)];
    auto& stream = side == 'R' || side == 'w' ? flow.right : flow.left;
    const auto old_size = stream.size();
    stream.append(payload);
    ++payloads_;
    bytes_ += payload.size();

    Verdict verdict;
    for (const auto& signature : fixed_signatures) {
        const auto position = stream.find(signature.bytes);
        if (position == std::string::npos || position + signature.bytes.size() <= old_size) continue;
        verdict.matches.push_back({std::string(signature.name), position,
                                   position + signature.bytes.size() - 1});
        ++matches_;
    }
    return verdict;
}

void Runtime::close(const std::string_view session) {
    std::scoped_lock guard(lock_);
    flows_.erase(std::string(session));
}

nlohmann::json Runtime::status() const {
    std::scoped_lock guard(lock_);
    return {{"service", "sx-siftd"}, {"engine", "bootstrap-ng"},
            {"flows", flows_.size()}, {"payloads", payloads_},
            {"bytes", bytes_}, {"matches", matches_}};
}

nlohmann::json verdict_json(const Verdict& verdict) {
    auto matches = nlohmann::json::array();
    for (const auto& match : verdict.matches) {
        matches.push_back({{"signature", match.signature}, {"begin", match.begin},
                           {"end", match.end}});
    }
    return {{"action", verdict.action}, {"matches", std::move(matches)},
            {"engine", "sx-siftd"}};
}

} // namespace sift
