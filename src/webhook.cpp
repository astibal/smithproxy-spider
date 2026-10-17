#include "webhook.hpp"

#include "decision_broker.hpp"
#include "enrichment.hpp"
#include "session_store.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace spider {

WebhookReply process_webhook(SessionStore& store, DecisionBroker& decisions,
                             const nlohmann::json& original_event,
                             const std::optional<std::string_view> raw_payload,
                             EnrichmentEngine* enrichment) {
    auto event = original_event;
    if (!event.is_object()) return {400, {{"error", "JSON object required"}}};

    const auto action = event.value("action", "");
    constexpr std::array<std::string_view, 9> supported{
        "access-request", "connection-content", "connection-start", "connection-stop",
        "connection-info", "hostname-info", "info", "neighbor", "ping",
    };
    if (std::find(supported.begin(), supported.end(), action) == supported.end()) {
        return {422, {{"error", "unsupported action"}}};
    }

    if (action == "info") {
        return {200, {{"action", "info-response"},
                      {"protocols", {{"connection-content", {"sxbn-001"}}}}}};
    }
    const auto ticket = decisions.prepare(event);
    decisions.observe(event);
    if (enrichment) enrichment->observe(event);
    const auto enrichments = enrichment && raw_payload
        ? enrichment->process(event, *raw_payload) : std::vector<SxbnEnvelope>{};
    if (event.value("decision", nlohmann::json::object()).value("state", "") != "ignored") {
        store.apply(event, raw_payload, enrichments);
    }
    if (action == "access-request") return {200, {{"access-response", "accept"}}};
    if (action == "connection-content") return decisions.wait(ticket);
    return {200, nlohmann::json::object()};
}

} // namespace spider
