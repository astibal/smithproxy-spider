#include "inspection.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include <cassert>
#include <chrono>
#include <iostream>
using nlohmann::json;
int main() {
    spider::Inspection runtime;
    json event = {{"action", "connection-content"}, {"id", "headless"},
        {"details", {{"info", {{"content", "YWJj"}, {"side", "L"},
        {"session", "tcp://127.0.0.1:1234-tcp://127.0.0.2:80"},
        {"L7_payload_start", {0}}, {"L7_payload_end", {3}}}}}}};
    auto run = [&](const std::string& script) { return runtime.run({{"script", script}, {"event", event}}); };
    auto result = run("api.print(api.l7_state, len(api.l7_bytes))\nreturn api.bytes.upper()");
    assert(result["ok"] == true && result["replacement"] == "QUJD");
    assert(result["logs"][0] == "body 3");
    assert(run("return None")["replacement"].is_null());
    result = run("assert api.message.size == 3\nassert api.message.bytes == api.bytes\nassert api.metadata.side == 'L'\nassert api.metadata.payload_layer is None\nassert not api.http1.available\nassert api.http1.method is None\nreturn None");
    assert(result["ok"] == true);
    result = runtime.run({{"script", "assert api.http1.available\nassert api.http1.method == 'GET'\nassert api.http1.target == '/demo'\nassert api.http1.status is None\nassert len(api.http1.headers) == 2\nassert api.http1.headers[1].value == 'two'\napi.print(api.http1.headers[0].name)"},
        {"event", event}, {"enrichments", json::array({{{"metadata", {
            {"operation", "http1.parse-head"}, {"context", "complete"}, {"message", {
                {"method", "GET"}, {"target", "/demo"}, {"headers", json::array({
                    {{"name", "X-Test"}, {"value", "one"}}, {{"name", "X-Test"}, {"value", "two"}}})}}}}}}})}});
    assert(result["ok"] == true && result["logs"][0] == "X-Test");
    assert(run("api.message.size = 99")["ok"] == false);
    assert(run("raise ValueError('bad')")["ok"] == false);
    assert(run("return 123")["ok"] == false);
    assert(run("api.print('x' * 1000000)")["logs"][0].get<std::string>().size() == 50000);
    auto start = std::chrono::steady_clock::now();
    assert(run("import time\ntime.sleep(20)")["ok"] == false);
    assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(5));
    spider::SessionStore store;
    spider::DecisionBroker decisions;
    runtime.configure({{"script", "return api.bytes.upper()"}, {"enabled", true}, {"scope", "all"}});
    auto reply = spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &runtime);
    assert(reply.body["action"] == "replace" && reply.body["content"] == "QUJD");
    // Browser departure only disables manual decisions, not backend execution.
    decisions.handle_message({{"type", "live-edit"}, {"enabled", false}});
    decisions.handle_message({{"type", "script-available"}, {"available", false}});
    assert(spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &runtime).body["action"] == "replace");
    (void)decisions.set_traffic_rules({{"bypass_all", true}});
    assert(spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &runtime).body["action"] == "unchanged");
    (void)decisions.set_traffic_rules({{"bypass_all", false}});
    runtime.configure({{"script", "raise RuntimeError('broken')"}, {"enabled", true}, {"scope", "all"}});
    assert(spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &runtime).body["action"] == "unchanged");
    runtime.configure({{"script", "return b'x'"}, {"enabled", false}});
    assert(spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &runtime).body["action"] == "unchanged");
    assert(runtime.status()["errors"].get<int>() >= 4);
    std::cout << "Backend inspection and headless webhook checks passed\n";
}
