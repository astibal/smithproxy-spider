#include "inspection.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include "binary_envelope.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <unistd.h>

using nlohmann::json;

int main() {
    char directory[] = "/tmp/spider-translate-XXXXXX";
    assert(mkdtemp(directory));
    spider::Inspection engine(std::filesystem::path(directory) / "collections");
    spider::SessionStore store;
    spider::DecisionBroker decisions;
    auto configure = [&](json request) {
        request["revision"] = engine.status()["revision"];
        return engine.configure(request);
    };
    const std::string script =
        "api.state['runs'] = api.state.get('runs', 0) + 1\n"
        "api.print('ran', api.state['runs'], api.side)\n"
        "if api.info.get('skip'): return None\n"
        "if api.state['runs'] == 1:\n"
        "    for part in api.message.parts:\n"
        "        if part.headers is not None: part.headers.set_header(b'x-lab', b'changed')\n"
        "return api.message.translate()";
    auto state = configure({{"operation", "deploy"}, {"name", "translate"}, {"script", script},
        {"scope", "all"}, {"instancing", "flow"}, {"filter", "src host 10.0.0.1"}});
    auto id = state["chain"][0]["id"];
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    auto frame = [](const std::string& block, unsigned type = 1, unsigned flags = 4) {
        std::string wire(9, '\0');
        wire[2] = static_cast<char>(block.size()); wire[3] = type; wire[4] = flags; wire[8] = 3;
        return wire + block;
    };
    const auto first = frame(std::string("\x40\x05x-lab\x08original", 16));
    const auto indexed = frame(std::string("\xbe", 1));
    auto send = [&](std::string flow, std::uint64_t sequence, std::string payload,
                    bool skip = false, bool match = true, std::string side = "L", bool capability = true) {
        json info{{"side", side}, {"content", spider::base64_encode(payload)}, {"skip", skip},
            {"session", match ? "tcp_10.0.0.1:1234+tcp_10.0.0.2:80" : "tcp_10.0.0.9:1234+tcp_10.0.0.2:80"},
            {"content_annotations", {{0, 9, "h2.frame.header"}}}};
        if (capability) info["webhook_control"] = {{"version", 1}, {"sequence", sequence},
            {"mode", sequence == 1 ? "regular" : "strict"}};
        auto result = spider::process_webhook(store, decisions,
            {{"action", "connection-content"}, {"id", flow}, {"details", {{"info", info}}}},
            std::nullopt, nullptr, &engine);
        if (result.status != 200) std::cerr << engine.status().dump(2) << '\n';
        return result;
    };
    auto activated = send("flow", 1, first);
    assert(activated.status == 200 && activated.body["action"] == "replace");
    assert(activated.body["control"]["mode"] == "strict");
    assert(engine.translation_required({{"id", "flow"}}));
    // Filter mismatch must no longer suppress a pinned callback.
    auto next = send("flow", 2, indexed, false, false);
    assert(next.status == 200 && next.body["action"] == "replace");
    assert(next.body["content"] != spider::base64_encode(indexed));
    assert(send("flow", 3, frame("body", 0, 1)).body["action"] == "replace");
    assert(send("flow", 4, first, false, false, "R").body["action"] == "replace");
    assert(engine.status()["chain"][0]["last_result"]["logs"][0] == "ran 4 R");
    assert(engine.status().dump().find("\"translate_state\"") == std::string::npos);
    assert(send("flow", 5, indexed, true).status == 503);
    assert(send("flow", 6, indexed).status == 503);

    assert(send("stopped", 1, first).body["action"] == "replace");
    configure({{"operation", "enable"}, {"id", id}, {"enabled", false}});
    assert(send("stopped", 2, indexed).status == 503);
    assert(send("lost", 2, indexed).status == 503); // strict after backend restart
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    auto old_proxy = send("unsupported", 1, first, false, true, "L", false);
    assert(old_proxy.body["action"] == "unchanged");
    assert(!old_proxy.body.contains("control"));
    assert(send("gap", 1, first).body["action"] == "replace");
    assert(send("gap", 3, indexed).status == 503);
    std::cout << "Live translate routing, control and failure tests passed\n";
}
