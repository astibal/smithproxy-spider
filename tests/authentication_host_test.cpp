#include "inspection.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <unistd.h>

using nlohmann::json;

int main() {
    char temporary[] = "/tmp/spider-auth-hook-XXXXXX";
    assert(mkdtemp(temporary));
    const std::filesystem::path root(temporary);
    {
        spider::Inspection engine(root / "collection");
        spider::SessionStore store;
        spider::DecisionBroker decisions;
        const json auth = {
            {"version", 1}, {"protocol", "http-connect"}, {"username", "test-user"},
            {"password", "DO-NOT-RETAIN"}, {"status", "accepted"}, {"identity", "test-user"},
            {"groups", json::array({"users"})}, {"peer", {{"host", "127.0.0.1"}, {"port", "12345"}}}
        };
        json event = {{"action", "proxy-authentication"}, {"id", "auth-test"},
                      {"details", {{"authentication", auth}}}};
        auto call = [&] {
            return spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &engine);
        };
        auto configure = [&](json request) {
            request["revision"] = engine.status()["revision"];
            return engine.configure(request);
        };
        auto deploy = [&](const std::string& source, const std::string& id = "") {
            return configure({{"operation", "deploy"}, {"id", id}, {"name", "Auth policy"},
                {"script", source}, {"scope", "all"}, {"hook", "authentication"}});
        };

        // No observer preserves the AAA result. Authentication must never enter
        // captured history, even when it contains intentionally recognizable data.
        const auto revision = store.revision();
        assert(call().body["decision"] == "accept");
        event["details"]["authentication"]["status"] = "rejected";
        assert(call().body["decision"] == "reject");
        assert(store.revision() == revision);
        event["details"]["authentication"]["status"] = "accepted";

        auto state = deploy("def main(api, state): api.auth.allowed = False");
        const auto id = state["chain"][0]["id"].get<std::string>();
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
        assert(call().body["decision"] == "reject");
        assert(!engine.has_enabled_scripts());
        assert(engine.automatic({{"action", "connection-start"}, {"id", "content"}}, json::array()).is_null());

        deploy("def main(api, state): api.auth.allowed = True", id);
        assert(call().body["decision"] == "accept");
        for (const auto* status : {"rejected", "unavailable"}) {
            event["details"]["authentication"]["status"] = status;
            assert(call().body["decision"] == "reject");
        }
        event["details"]["authentication"]["status"] = "accepted";

        // Error text and explicit printing cannot leak credentials into the
        // normal inspection history or the webhook response.
        deploy("def main(api, state):\n    print(api.auth.password)\n    raise ValueError(api.auth.password)", id);
        const auto failed = call();
        assert(failed.body["decision"] == "reject");
        assert(failed.body.dump().find("DO-NOT-RETAIN") == std::string::npos);
        assert(engine.status().dump().find("DO-NOT-RETAIN") == std::string::npos);
        assert(call().body["decision"] == "reject");
        assert(store.revision() == revision);

        auto malformed = event;
        malformed["details"]["authentication"]["groups"] = "not an array";
        assert(spider::process_webhook(store, decisions, malformed, std::nullopt, nullptr, &engine).status == 400);

        // A deliberate disable releases the policy; worker loss alone does not.
        configure({{"operation", "enable"}, {"id", id}, {"enabled", false}});
        assert(call().body["decision"] == "accept");

        // Authentication addons use their own generation and do not require
        // the content Translate owner's flow-instancing contract.
        deploy("#!mitmproxy\ncalls = 0\ndef socks5_auth(data):\n"
               "    global calls\n    calls += 1\n    data.valid = calls == 1\n", id);
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
        event["details"]["authentication"]["protocol"] = "socks5";
        assert(call().body["decision"] == "accept");
        assert(call().body["decision"] == "reject");
        assert(!engine.has_enabled_scripts());

        // An independent content addon can coexist with the auth policy.
        const auto content = configure({{"operation", "deploy"}, {"name", "Content"},
            {"script", "#!mitmproxy\ndef request(flow): pass"},
            {"scope", "all"}, {"instancing", "flow"}, {"hook", "content"}});
        const auto content_id = content["chain"].back()["id"];
        configure({{"operation", "enable"}, {"id", content_id}, {"enabled", true}});
        assert(engine.has_enabled_scripts());
        assert(call().body["decision"] == "reject");
        assert(store.revision() == revision);
    }
    std::filesystem::remove_all(root);
    std::cout << "authentication host boundary passed\n";
}
