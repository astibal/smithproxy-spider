#include "inspection.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include "enrichment.hpp"
#include <cassert>
#include <chrono>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unistd.h>
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
    spider::Inspection chain;
    auto configure = [&](json request) {
        request["revision"] = chain.status()["revision"];
        return chain.configure(request);
    };
    auto deployment = configure({{"operation", "deploy"}, {"name", "upper"}, {"script", "return api.bytes.upper()"}, {"scope", "all"}});
    const auto first = deployment["chain"][0]["id"];
    assert(deployment["chain"][0]["enabled"] == false);
    assert(chain.automatic(event, json::array()).is_null());
    configure({{"operation", "enable"}, {"id", first}, {"enabled", true}});
    deployment = configure({{"operation", "deploy"}, {"name", "append"}, {"script", "return api.bytes + b'!'"}, {"scope", "all"}});
    const auto second = deployment["chain"][1]["id"];
    configure({{"operation", "enable"}, {"id", second}, {"enabled", true}});
    auto output = chain.automatic(event, json::array());
    assert(output["replacement"] == "QUJDIQ==" && output["steps"].size() == 2);
    assert(chain.status()["chain"][0]["runs"] == 1);
    bool rejected = false;
    try { configure({{"operation", "deploy"}, {"id", first}, {"name", "bad"}, {"script", "if:"}, {"scope", "all"}}); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected && chain.status()["chain"][0]["version"] == 1);
    rejected = false;
    try { chain.configure({{"operation", "remove"}, {"id", first}, {"revision", 0}}); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    configure({{"operation", "deploy"}, {"id", second}, {"name", "fail"}, {"script", "raise ValueError('test')"}, {"scope", "all"}});
    assert(chain.automatic(event, json::array())["replacement"].is_null());
    configure({{"operation", "reorder"}, {"ids", json::array({second, first})}});
    assert(chain.status()["chain"][0]["id"] == second);
    configure({{"operation", "remove"}, {"id", second}});
    configure({{"operation", "remove"}, {"id", first}});
    assert(chain.automatic(event, json::array()).is_null());

    char temporary[] = "/tmp/spider-collection-test-XXXXXX";
    const auto directory = mkdtemp(temporary);
    assert(directory);
    spider::Collection collection(directory, 1000000);
    auto collected = event;
    collected["details"]["info"]["session"] = "tcp_192.0.2.1:1234+tcp_192.0.2.2:80";
    spider::DecisionBroker collecting;
    auto rules = collecting.set_traffic_rules({{"rules", json::array({
        {{"id", "focus"}, {"address", "192.0.2.99"}, {"mode", "focus"}},
        {{"id", "collect"}, {"address", "192.0.2.2"}, {"mode", "collect"}}
    })}});
    assert(rules["errors"].empty());
    (void)collecting.prepare(collected);
    assert(collected["collections"].size() == 1);
    assert(collected["decision"]["state"] == "passed"); // capture is independent of focus
    collected["collections"][0]["endpoint"] = "../../*.example.test";
    const auto enrichments = json::array({{{"metadata", {{"operation", "test"}}}, {"content", "YWJj"}}});
    collection.capture(collected, enrichments, {{"context", "preserved"}});
    assert(collection.status()["saved"] == 1);
    const auto samples = collection.list();
    assert(samples["total"] == 1 && samples["items"].size() == 1);
    const auto saved = collection.read(samples["items"][0]["id"]);
    assert(saved["event"] == collected && saved["enrichments"] == enrichments);
    assert(saved["session_context"]["context"] == "preserved");
    assert(collection.list(1000)["items"].empty());
    bool traversal_rejected = false;
    try { (void)collection.read("../outside.json"); } catch (...) { traversal_rejected = true; }
    assert(traversal_rejected);
    auto rules_result = decisions.set_traffic_rules({{"rules", json::array({
        {{"id", "follow-collect"}, {"kind", "session"}, {"value", "headless"}, {"mode", "collect"}}})}});
    assert(rules_result["errors"].empty());
    auto exact = event;
    (void)decisions.prepare(exact);
    assert(exact.contains("collections"));
    exact = event; exact["id"] = "other";
    (void)decisions.prepare(exact);
    assert(!exact.contains("collections"));
    for (const auto& path : std::filesystem::recursive_directory_iterator(directory)) {
        if (!path.is_regular_file()) continue;
        std::ifstream input(path.path()); json sample; input >> sample;
        assert(sample["event"]["details"]["info"]["content"] == "YWJj");
        assert(sample["enrichments"] == enrichments);
        assert(sample["session_context"]["context"] == "preserved");
        assert(sample["capture_stage"] == "before-inspection");
        assert(path.path().parent_path().parent_path() == directory);
    }
    spider::Collection full(directory, 1);
    full.capture(collected, enrichments, json::object());
    assert(full.status()["errors"] == 1 && full.status()["saved"] == 0);
    rules = collecting.set_traffic_rules({{"bypass_all", true}, {"rules", json::array({
        {{"id", "hostnames"}, {"kind", "hostname-glob"}, {"value", "*.example.test"}, {"mode", "collect"}}
    })}});
    assert(rules["errors"].empty());
    collecting.observe({{"action", "hostname-info"}, {"details", {{"info", {{"list", json::array({
        {{"hostname", "www.example.test"}, {"address", {"192.0.2.2"}}}
    })}}}}}});
    collected.erase("collections");
    (void)collecting.prepare(collected);
    assert(collected["collections"].size() == 1 && collected["decision"]["reason"] == "bypass-all");
    spider::Inspection capture_runtime(std::filesystem::path(directory) / "webhook");
    spider::EnrichmentEngine enrichment;
    const std::string http = "GET / HTTP/1.1\r\nHost: www.example.test\r\n\r\n";
    collected["details"]["info"]["content"] = spider::base64_encode(http);
    collected["details"]["info"]["content_annotations"] = json::array({
        json::array({0, 16, "http1.start_line"}), json::array({16, http.size(), "http1.headers"})});
    collected.erase("collections");
    auto captured_reply = spider::process_webhook(store, collecting, collected, std::nullopt, &enrichment, &capture_runtime);
    assert(captured_reply.body["action"] == "unchanged");
    assert(capture_runtime.collection.status()["saved"] == 1);
    for (const auto& path : std::filesystem::recursive_directory_iterator(std::filesystem::path(directory) / "webhook")) {
        if (!path.is_regular_file()) continue;
        std::ifstream input(path.path()); json sample; input >> sample;
        assert(sample["enrichments"].size() == 1);
        assert(sample["enrichments"][0]["metadata"]["operation"] == "http1.parse-head");
        assert(sample["event"]["details"]["info"]["content"] == spider::base64_encode(http));
    }
    std::filesystem::remove_all(directory); // only this test's freshly allocated mkdtemp directory
    std::cout << "Backend inspection and headless webhook checks passed\n";
}
