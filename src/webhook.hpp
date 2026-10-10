#pragma once

#include <nlohmann/json.hpp>

namespace spider {

struct WebhookReply {
    unsigned status;
    nlohmann::json body;
};

class SessionStore;
class DecisionBroker;

[[nodiscard]] WebhookReply process_webhook(SessionStore& store, DecisionBroker& decisions,
                                           const nlohmann::json& event);

} // namespace spider
