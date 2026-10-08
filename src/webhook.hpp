#pragma once

#include <nlohmann/json.hpp>

namespace spider {

struct WebhookReply {
    unsigned status;
    nlohmann::json body;
};

class SessionStore;

[[nodiscard]] WebhookReply process_webhook(SessionStore& store, const nlohmann::json& event);

} // namespace spider

