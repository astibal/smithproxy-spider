#include "heavy_traffic.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include <cassert>
using namespace std::chrono;
int main() {
    spider::HeavyTraffic guard;
    const auto start = steady_clock::time_point(seconds(100));
    assert(guard.observe("off", 99999999, false, start).is_null());
    guard.configure({{"enabled", true}});
    for (int t = 0; t < 80; ++t)
        assert(guard.observe("bytes", 2097152, false, start + milliseconds(t * 100)).is_null());
    auto cutoff = guard.observe("bytes", 2097152, false, start + seconds(8));
    assert(cutoff["first"] == true && cutoff["notice"]["reason"] == "bytes/s");
    guard.configure({{"enabled", false}});
    assert(guard.observe("bytes", 1, false, start + seconds(9))["first"] == false);
    guard.stop("bytes");
    assert(guard.observe("bytes", 99999999, false, start + seconds(10)).is_null());
    guard.configure({{"enabled", true}, {"messages_per_second", 2}});
    for (int t = 0; t < 100; ++t) {
        assert(guard.observe("managed", 99999999, true, start + milliseconds(t * 100)).is_null());
        assert(guard.observe("small", 1, false, start + seconds(t)).is_null());
    }
    assert(guard.observe("burst", 1, false, start).is_null());
    for (int t = 50; t < 60; ++t) assert(guard.observe("burst", 2, false, start + milliseconds(t * 100)).is_null());
    assert(guard.observe("burst", 1, false, start + seconds(9)).is_null());
    guard.configure({{"enabled", true}, {"messages_per_second", 2}});
    nlohmann::json result;
    for (int t = 0; t < 90 && result.is_null(); ++t) result = guard.observe("messages", 1, false, start + milliseconds(t * 100));
    assert(result["notice"]["reason"] == "messages/s");
    bool invalid = false;
    try { guard.configure({{"grace_seconds", 4}}); } catch (const std::invalid_argument&) { invalid = true; }
    assert(invalid);
    guard.configure({{"include_managed", true}});
    result = nullptr;
    for (int t = 0; t < 90 && result.is_null(); ++t) result = guard.observe("opted-in", 2097152, true, start + milliseconds(t * 100));
    assert(!result.is_null());

    // Seed monotonic history; verify the real webhook declines before decoding/processing data.
    spider::DecisionBroker broker;
    spider::SessionStore store;
    broker.heavy_traffic.configure({{"enabled", true}, {"bytes_per_second", 1}, {"sustain_seconds", 1}});
    const auto now = steady_clock::now();
    broker.heavy_traffic.observe("wire", 2, false, now - milliseconds(6200));
    broker.heavy_traffic.observe("wire", 2, false, now - milliseconds(1100));
    broker.heavy_traffic.observe("wire", 2, false, now - milliseconds(500));
    auto reply = spider::process_webhook(store, broker, {{"action", "connection-content"}, {"id", "wire"},
        {"details", {{"info", {{"content", "YWJj"}}}}}});
    assert(reply.body["action"] == "not-interested");
    assert(store.session_detail("wire").has_value());
    const auto saved = store.session_detail("wire");
    assert(saved->dump().find("heavy_traffic") != std::string::npos);
    assert(saved->dump().find("YWJj") == std::string::npos);
    const auto revision = store.revision();
    reply = spider::process_webhook(store, broker, {{"action", "connection-content"}, {"id", "wire"},
        {"details", {{"info", {{"content", "YWJj"}}}}}});
    assert(reply.body["action"] == "not-interested" && store.revision() == revision);
}
