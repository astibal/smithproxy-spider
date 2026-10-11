#include "webhook.hpp"

#include "decision_broker.hpp"
#include "session_store.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace spider {

WebhookReply process_webhook(SessionStore& store, DecisionBroker& decisions,
                             const nlohmann::json& original_event) {
    auto event = original_event;
    if (!event.is_object()) return {400, {{"error", "JSON object required"}}};

    const auto action = event.value("action", "");
    constexpr std::array<std::string_view, 8> supported{
        "access-request", "connection-content", "connection-start", "connection-stop",
        "connection-info", "hostname-info", "neighbor", "ping",
    };
    if (std::find(supported.begin(), supported.end(), action) == supported.end()) {
        return {422, {{"error", "unsupported action"}}};
    }

    const auto ticket = decisions.prepare(event);
    decisions.observe(event);
    store.apply(event);
    if (action == "access-request") return {200, {{"access-response", "accept"}}};
    if (action == "connection-content") return decisions.wait(ticket);
    return {200, nlohmann::json::object()};
}

} // namespace spider
