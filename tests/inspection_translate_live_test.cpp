#include "inspection.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include "binary_envelope.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <thread>
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
        "for part in api.message.parts:\n"
        "    if not part.complete:\n"
        "        api.message.parts.hold_from(part)\n"
        "        break\n"
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
                    bool skip = false, bool match = true, std::string side = "L", bool capability = true,
                    bool reverse = false) {
        json info{{"side", side}, {"content", spider::base64_encode(payload)}, {"skip", skip},
            {"session", match ? "tcp_10.0.0.1:1234+tcp_10.0.0.2:80" : "tcp_10.0.0.9:1234+tcp_10.0.0.2:80"},
            {"content_annotations", {{0, 9, "h2.frame.header"}}}};
        if (capability) info["webhook_control"] = {{"version", 1}, {"sequence", sequence},
            {"mode", sequence == 1 ? "regular" : "strict"}};
        if (reverse) info["webhook_control"]["content-reverse"] = true;
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

    // Initial need-more must activate strict even without an emitted byte.
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    auto held = send("fragmented", 1, preface.substr(0, 1));
    assert(held.status == 200 && held.body["action"] == "need-more");
    assert(held.body["control"]["mode"] == "strict");
    assert(!held.body.contains("content"));

    // The opposite direction has independent hold and table checkpoints.
    assert(send("fragmented", 2, first, false, true, "R").body["action"] == "replace");
    auto prefix = send("fragmented", 3, preface.substr(1) + first.substr(0, 8));
    assert(prefix.status == 200 && prefix.body["action"] == "replace");
    assert(prefix.body["content"] == spider::base64_encode(preface));
    auto completed = send("fragmented", 4, first.substr(8));
    assert(completed.status == 200 && completed.body["action"] == "replace");
    // Reservations are admitted by the backend under the deployment serial
    // transaction. Two workers/connections cannot promise the same capacity.
    configure({{"operation", "remove"}, {"id", id}});
    const std::string reserve_script =
        "for part in api.message.parts:\n"
        "    if part.type == PartType.Http2.Header and part.content.complete is False:\n"
        "        api.message.parts.hold_from(part)\n"
        "        api.connection.http2.reserve_body(part, 256 * 1024)\n"
        "        break\n"
        "return api.message.translate()";
    state = configure({{"operation", "deploy"}, {"name", "reserve"}, {"script", reserve_script},
                       {"scope", "all"}, {"instancing", "flow"}});
    id = state["chain"][0]["id"];
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    auto reserve_send = [&](const std::string& flow, unsigned sequence, const std::string& wire) {
        return send(flow, sequence, wire, false, true, "L", true, true);
    };
    const auto request_header = frame(std::string("\x83", 1)); // :method POST
    assert(reserve_send("reserve-a", 1, preface).status == 200);
    assert(reserve_send("reserve-b", 1, preface).status == 200);
    unsigned status_a = 0, status_b = 0;
    std::thread a([&] { status_a = reserve_send("reserve-a", 2, request_header).status; });
    std::thread b([&] { status_b = reserve_send("reserve-b", 2, request_header).status; });
    a.join(); b.join();
    assert((status_a == 200 && status_b == 503) || (status_a == 503 && status_b == 200));
    const auto winner = status_a == 200 ? "reserve-a" : "reserve-b";
    auto charge = engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>();
    assert(charge > 2 * 1024 * 1024 && charge < 3 * 1024 * 1024);
    auto early = reserve_send(winner, 3, frame("abc", 0, 0));
    assert(early.status == 200 && early.body["action"] == "replace");
    assert(early.body["content"] == "" && early.body.contains("content-reverse"));
    auto released = reserve_send(winner, 4, frame("def", 0, 1));
    assert(released.status == 200 && released.body["action"] == "replace");
    // Completed output has settled all early credit: the live connection now
    // needs only actual metadata, and another connection can obtain admission.
    assert(engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>() < 65536);
    assert(reserve_send("reserve-c", 1, preface).status == 200);
    assert(reserve_send("reserve-c", 2, request_header).status == 200);
    assert(reserve_send("reserve-c", 3, frame("abc", 0, 0)).status == 200);
    assert(send("reserve-c", 4, frame(std::string("\x88", 1)), false, true, "R", true, true).status == 200);
    assert(engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>() > 3 * 1024 * 1024);
    assert(send("reserve-c", 5, frame("reply", 0, 1), false, true, "R", true, true).status == 200);
    charge = engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>();
    assert(charge > 2 * 1024 * 1024 && charge < 3 * 1024 * 1024);
    const auto reset = frame(std::string("\0\0\0\x08", 4), 3, 0);
    auto cancelled = send("reserve-c", 6, reset, false, true, "R", true, true);
    assert(cancelled.status == 200 && cancelled.body["action"] == "replace");
    assert(engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>() < 65536);
    assert(engine.status().dump().find("peer_held_parts") == std::string::npos);
    // Resume the cancelled direction: its saved HPACK block is consumed without
    // leaking the cancelled body or replaying its already-refunded DATA.
    auto next_header = request_header;
    next_header[8] = 5;
    assert(reserve_send("reserve-c", 7, next_header).status == 200);
    auto next_data = frame("", 0, 1);
    next_data[8] = 5;
    assert(reserve_send("reserve-c", 8, next_data).status == 200);
    assert(reserve_send("reserve-d", 1, preface).status == 200);
    assert(reserve_send("reserve-d", 2, request_header).status == 200);
    engine.automatic({{"action", "connection-stop"}, {"id", "reserve-d"}}, json::array());
    assert(engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>() < 65536);
    // Smaller holds admit two independent connections under the same 4 MiB
    // deployment quota. A third must fail atomically, including racing workers.
    configure({{"operation", "remove"}, {"id", id}});
    auto small_script = reserve_script;
    small_script.replace(small_script.find("256 * 1024"), 10, "128 * 1024");
    state = configure({{"operation", "deploy"}, {"name", "small reserve"}, {"script", small_script},
                       {"scope", "all"}, {"instancing", "flow"}});
    id = state["chain"][0]["id"];
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    for (const auto* flow : {"small-a", "small-b", "small-c"})
        assert(reserve_send(flow, 1, preface).status == 200);
    std::thread small_a([&] { status_a = reserve_send("small-a", 2, request_header).status; });
    std::thread small_b([&] { status_b = reserve_send("small-b", 2, request_header).status; });
    small_a.join(); small_b.join();
    assert(status_a == 200 && status_b == 200);
    charge = engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>();
    assert(charge > 3 * 1024 * 1024 && charge < 4 * 1024 * 1024);
    assert(reserve_send("small-c", 2, request_header).status == 503);
    for (const auto* flow : {"small-a", "small-b"})
        assert(reserve_send(flow, 3, frame("done", 0, 1)).status == 200);
    assert(engine.status()["chain"][0]["state_bytes"].get<std::uint64_t>() < 65536);
    std::cout << "Live translate routing, admission, control and failure tests passed\n";
}
