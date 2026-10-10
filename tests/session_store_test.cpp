#include "session_store.hpp"
#include "webhook.hpp"

#include <cassert>

int main() {
    spider::SessionStore store(2);
    const nlohmann::json start = {
        {"action", "connection-start"}, {"id", "42"},
        {"details", {{"info", {{"session", "tcp 10.0.0.1:1 -> 10.0.0.2:443"}}}}},
    };
    const auto reply = spider::process_webhook(store, start);
    assert(reply.status == 200);
    assert(store.snapshot()["sessions"].size() == 1);
    assert(store.snapshot()["sessions"][0]["id"] == "42");
    assert(store.status()["callbacks_received"] == 1);
    assert(store.status()["active_sessions"] == 1);
    assert(store.status()["last_callback"]["action"] == "connection-start");
    assert(store.status()["last_callback"]["received_at_ms"].get<std::int64_t>() > 0);

    assert(spider::process_webhook(store, {{"action", "connection-info"}, {"id", "42"}}).status == 200);
    assert(spider::process_webhook(store, {{"action", "connection-stop"}, {"id", "42"}}).status == 200);
    assert(store.snapshot()["sessions"].empty());
    assert(store.events_after(0)["events"].size() == 2);

    store.apply({{"action", "spider-smithproxy-status"}, {"state", "connected"}});
    assert(store.status()["ready"] == true);
    assert(store.status()["callbacks_received"] == 3);
    assert(store.status()["smithproxy"].contains("spider_received_at_ms"));

    const auto invalid = spider::process_webhook(store, {{"action", "wat"}});
    assert(invalid.status == 422);
}
