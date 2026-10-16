#pragma once

#include <string_view>
#include <optional>

#include <nlohmann/json.hpp>

namespace spider {

struct WebhookReply {
    unsigned status;
    nlohmann::json body;
};

class SessionStore;
class DecisionBroker;

[[nodiscard]] WebhookReply process_webhook(SessionStore& store, DecisionBroker& decisions,
                                           const nlohmann::json& event,
                                           std::optional<std::string_view> raw_payload = std::nullopt);

} // namespace spider
