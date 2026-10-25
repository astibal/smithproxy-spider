#include "inspection.hpp"
#include "webhook.hpp"
#include "decision_broker.hpp"
#include "session_store.hpp"
#include "enrichment.hpp"
#include "binary_envelope.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <thread>
#include <unistd.h>

using nlohmann::json;

int main() {
    char directory[] = "/tmp/spider-hold-XXXXXX";
    assert(mkdtemp(directory));
    spider::Inspection engine(std::filesystem::path(directory) / "collections");
    spider::SessionStore store;
    spider::DecisionBroker decisions;
    (void)decisions.set_traffic_rules({{"rules", json::array({
        {{"address", "10.0.0.1"}, {"mode", "inspect"}}})}});
    spider::EnrichmentEngine enrichment;
    auto configure = [&](json request) {
        request["revision"] = engine.status()["revision"];
        return engine.configure(request);
    };
    const std::string script =
        "if api.info.get('fail'): raise ValueError('test failure')\n"
        "for part in api.message.parts:\n"
        "    if part.type == PartType.Http1.Body:\n"
        "        if not part.content.complete:\n"
        "            api.message.parts.hold_from(api.message.parts[0])\n"
        "            return api.message.commit()\n"
        "        assert part.get_bytes() == b'abcdef'\n"
        "        part.set_bytes(b'changed body')\n"
        "return api.message.commit()";
    auto status = configure({{"operation", "deploy"}, {"name", "hold"}, {"script", script},
        {"scope", "all"}, {"instancing", "flow"}});
    const auto deployment = status["chain"][0]["id"];
    configure({{"operation", "enable"}, {"id", deployment}, {"enabled", true}});
    const std::string head = "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\n";
    const std::string expected = "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 12\r\n\r\nchanged body";
    auto event = [&](const std::string& id, const std::string& side, const std::string& data, bool annotated) {
        json info{{"side", side}, {"content", spider::base64_encode(data)},
            {"session", "tcp_10.0.0.1:1234+tcp_10.0.0.2:80"}};
        if (annotated) info["content_annotations"] = {{0, 17, "http1.start_line"}, {17, head.size(), "http1.headers"}};
        return json{{"action", "connection-content"}, {"id", id}, {"details", {{"info", info}}}};
    };
    auto send = [&](const std::string& id, const std::string& side, const std::string& data, bool annotated = false) {
        return spider::process_webhook(store, decisions, event(id, side, data, annotated),
            std::nullopt, &enrichment, &engine).body;
    };
    auto expect_hold = [&](const json& reply) {
        assert(reply["action"] == "need-more");
        assert(!reply.contains("content")); // No byte may escape to the fake peer.
        assert(engine.status().dump().find("\"held_parts\"") == std::string::npos);
    };
    auto expect_release = [&](const json& reply) {
        assert(reply["action"] == "replace");
        assert(reply["content"] == spider::base64_encode(expected));
    };

    // Interleave connections and both directions; release each exactly once.
    expect_hold(send("one", "L", head + "a", true));
    expect_hold(send("one", "R", head + "abc", true));
    expect_hold(send("two", "L", head + "ab", true));
    expect_hold(send("one", "L", "bc"));
    expect_release(send("one", "R", "def"));
    expect_release(send("two", "L", "cdef"));
    expect_release(send("one", "L", "def"));
    assert(send("one", "L", "next")["content"] == spider::base64_encode("next"));

    // The complete Content-Length body can arrive one byte at a time.
    expect_hold(send("tiny", "L", head, true));
    for (char ch : std::string("abcde")) expect_hold(send("tiny", "L", std::string(1, ch)));
    expect_release(send("tiny", "L", "f"));

    // Two distinct flows can enter the deployment concurrently without mixing.
    expect_hold(send("parallel-a", "L", head + "abc", true));
    expect_hold(send("parallel-b", "L", head + "abc", true));
    json a, b;
    std::thread first([&] { a = send("parallel-a", "L", "def"); });
    std::thread second([&] { b = send("parallel-b", "L", "def"); });
    first.join(); second.join();
    expect_release(a); expect_release(b);

    // Explicitly retain today's fail-open policy, with abandonment metadata.
    expect_hold(send("error", "L", head + "abc", true));
    auto failing = event("error", "L", "def", false);
    failing["details"]["info"]["fail"] = true;
    const auto failure = engine.automatic(failing, json::array());
    assert(!failure["ok"].get<bool>() && failure["replacement"].is_null());
    assert(failure["hold"]["state"] == "abandoned");
    assert(send("error", "L", "fresh")["content"] == spider::base64_encode("fresh"));

    expect_hold(send("closed", "L", head + "abc", true));
    engine.automatic({{"action", "connection-stop"}, {"id", "closed"}}, json::array());
    engine.automatic({{"action", "connection-start"}, {"id", "closed"}}, json::array());
    assert(send("closed", "L", "fresh")["content"] == spider::base64_encode("fresh"));

    // Preview cannot accidentally create a live transport checkpoint.
    auto preview = engine.run({{"script", script}, {"event", event("preview", "L", head, true)},
        {"hold_allowed", true}, {"instance", {{"mode", "flow"}}}});
    assert(!preview["ok"].get<bool>());
    assert(preview["error"].get<std::string>().find("live flow deployment") != std::string::npos);

    // HPACK is decoded once by the live engine, across two callbacks. Its
    // completed indexed-field metadata must reattach to the held HEADERS part.
    const std::string h2_script =
        "for part in api.message.parts:\n"
        "    if not part.complete:\n"
        "        api.message.parts.hold_from(api.message.parts[0])\n"
        "        return api.message.commit()\n"
        "    if part.headers is not None:\n"
        "        part.headers.set_header(b'x', b'rewritten')\n"
        "return api.message.commit()";
    expect_hold(send("old-generation", "L", head + "abc", true));
    configure({{"operation", "deploy"}, {"id", deployment}, {"name", "H2 hold"},
        {"script", h2_script}, {"scope", "all"}, {"instancing", "flow"}});
    assert(send("old-generation", "L", "def")["content"] == spider::base64_encode("def"));
    auto h2frame = [](unsigned type, unsigned flags, std::string data) {
        std::string wire(9, '\0');
        wire[0] = static_cast<char>(data.size() >> 16);
        wire[1] = static_cast<char>(data.size() >> 8);
        wire[2] = static_cast<char>(data.size());
        wire[3] = static_cast<char>(type);
        wire[4] = static_cast<char>(flags);
        wire[8] = 1;
        return wire + data;
    };
    const std::string block = std::string("\x82\x00\x01x\x01v", 6);
    const auto h2_first = h2frame(1, 0, block.substr(0, 3));
    const auto h2_last = h2frame(9, 4, block.substr(3));
    auto send_h2 = [&](const std::string& wire, const std::string& kind) {
        auto input = event("h2-held", "L", wire, false);
        input["details"]["info"]["content_annotations"] = {{0, 9, "h2.frame.header"}, {9, wire.size(), kind}};
        return spider::process_webhook(store, decisions, input, std::nullopt, &enrichment, &engine).body;
    };
    expect_hold(send_h2(h2_first, "h2.headers"));
    const auto h2_reply = send_h2(h2_last, "h2.continuation");
    if (h2_reply["action"] != "replace") std::cerr << engine.status()["chain"][0]["last_result"].dump(2) << '\n';
    assert(h2_reply["action"] == "replace");
    const std::string changed = std::string("\x82\x00\x01x\x09", 5) + "rewritten";
    assert(h2_reply["content"] == spider::base64_encode(h2frame(1, 4, changed)));
    std::cout << "Live H1 hold: need-more, isolation, release, lifecycle and fail-open verified\n";
}
