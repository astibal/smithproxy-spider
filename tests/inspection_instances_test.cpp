#include "inspection.hpp"
#include "binary_envelope.hpp"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include <unistd.h>
using nlohmann::json;

int main(int argc, char** argv) {
    char directory[] = "/tmp/spider-instances-XXXXXX";
    assert(mkdtemp(directory));
    const auto root = std::filesystem::path(directory);
    spider::Inspection engine(root / "collections");
    auto configure = [&](json request) {
        request["revision"] = engine.status()["revision"];
        return engine.configure(request);
    };
    const std::string counter = "api.state['n'] = api.state.get('n', 0) + 1\n"
        "if api.info.get('fail'): raise ValueError('rollback')\napi.print(api.state['n'])\nreturn None";
    auto deploy = [&](std::string mode, std::string source, json options = json::object()) {
        const auto previous = engine.status();
        for (const auto& item : previous["chain"]) // retire previous deployment
            configure({{"operation", "remove"}, {"id", item["id"]}});
        options.update({{"operation", "deploy"}, {"name", "test"}, {"script", source}, {"scope", "all"}, {"instancing", mode}});
        const auto status = configure(options);
        const auto id = status["chain"][0]["id"];
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
        return id;
    };
    json event = {{"action", "connection-content"}, {"id", "one"},
        {"details", {{"info", {{"content", "YWJj"}, {"side", "L"},
            {"session", "tcp_10.0.0.1:1234+tcp_10.0.0.2:443"}}}}}};
    auto run = [&]() { return engine.automatic(event, json::array()); };
    // A single deployment and flow instance receives setup before content.
    auto setup = event;
    setup["action"] = "connection-start";
    setup["details"]["info"].erase("content");
    setup["details"]["info"].erase("side");
    deploy("flow", "if api.phase == 'setup':\n    api.state['ready'] = True\n"
                   "    api.connection.request_rewrite()\n    return\n"
                   "assert api.state['ready']\nreturn None");
    const auto ready = engine.automatic(setup, json::array());
    assert(ready["ok"] == true && ready["rewrite_requested"] == true);
    assert(run()["ok"] == true);
    assert(engine.status()["chain"][0]["instances"] == 1);
    auto added = configure({{"operation", "deploy"}, {"name", "observer"},
                            {"script", "return None"}, {"scope", "all"}});
    const auto observer = added["chain"][1]["id"];
    configure({{"operation", "enable"}, {"id", observer}, {"enabled", true}});
    auto reserved = engine.automatic(setup, json::array());
    assert(reserved["ok"] == true && reserved["rewrite_requested"] == true);
    assert(reserved["steps"].size() == 2); // A later observer does not erase opt-in.
    configure({{"operation", "deploy"}, {"id", observer}, {"name", "broken observer"},
               {"script", "raise ValueError('setup aborted')"}, {"scope", "all"}});
    configure({{"operation", "enable"}, {"id", observer}, {"enabled", true}});
    reserved = engine.automatic(setup, json::array());
    assert(reserved["ok"] == false && !reserved.value("rewrite_requested", false));
    deploy("flow", "api.connection.request_rewrite()", {{"filter", "dst port 80"}});
    assert(engine.automatic(setup, json::array()).is_null()); // Current destination is 443.
    {
        // The QUIC parent is visible to native scripts, but does not allocate
        // an HTTP addon instance or synthesize a second client_connected hook.
        auto parent = setup;
        parent["id"] = "quic-parent";
        parent["details"]["info"]["scope"] = "transport";
        parent["details"]["info"]["protocol"] = "quic";
        parent["details"]["info"]["session"] = "quic_[::1]:1234+quic_[::1]:443";
        deploy("flow", "assert api.info['scope'] == 'transport'\napi.print('parent')",
               {{"filter", "dst port 443"}});
        assert(engine.automatic(parent, json::array())["logs"][0] == "parent");
        engine.automatic({{"action", "connection-stop"}, {"id", "quic-parent"}}, json::array());
        assert(engine.status()["chain"][0]["instances"] == 0);

        deploy("flow", "#!mitmproxy\ndef client_connected(client):\n    print('client')\n"
                       "def client_disconnected(client):\n    print('closed')\n");
        assert(engine.automatic(parent, json::array()).is_null());
        assert(engine.status()["chain"][0]["instances"] == 0);
        for (const auto stream : {0, 4}) {
            auto child = setup;
            child["id"] = "quic-stream-" + std::to_string(stream);
            child["details"]["info"]["scope"] = "stream";
            child["details"]["info"]["parent_id"] = "quic-parent";
            child["details"]["info"]["stream_id"] = stream;
            assert(engine.automatic(child, json::array())["ok"] == true);
        }
        assert(engine.status()["chain"][0]["instances"] == 2);
        engine.automatic({{"action", "connection-stop"}, {"id", "quic-parent"}}, json::array());
        assert(engine.status()["chain"][0]["instances"] == 2);
        for (const auto stream : {0, 4}) {
            engine.automatic({{"action", "connection-stop"},
                              {"id", "quic-stream-" + std::to_string(stream)}}, json::array());
        }
        assert(engine.status()["chain"][0]["instances"] == 0);
    }

    {
        // The real worker owns one QUIC parent and carries mutations through
        // the same lifecycle bridge used by incoming webhook messages.
        deploy("flow", "#!mitmproxy\ndef quic_start_server(data):\n"
                       "    data.settings.cipher_suites = [0x1301]\n"
                       "    data.conn.sni = 'updated.test'\n",
               {{"quic_start_server", true}});
        auto parent = setup;
        parent["id"] = "quic-hook-parent";
        parent["details"]["info"]["scope"] = "transport";
        parent["details"]["info"]["protocol"] = "quic";
        const auto ready = engine.automatic(parent, json::array());
        assert(ready["ok"] == true && ready["quic_start_server"] == true);

        json observation = {
            {"protocol", "quic"},
            {"envelope", {{"version", 1}, {"connection_id", "quic-hook-parent"},
                {"attempt", 1U}, {"side", "server"}, {"event", "start"}}},
            {"upstream", {{"sni", "original.test"}, {"alpn", "h3"}, {"ciphers", nullptr}}}
        };
        const auto reply = engine.quic_lifecycle({{"id", "quic-hook-parent"},
            {"details", {{"quic", observation}}}});
        assert(reply["proceed"] == true);
        assert(reply["upstream"]["sni"] == "updated.test");
        assert(reply["upstream"]["ciphers"] == "TLS_AES_128_GCM_SHA256");

        observation.erase("upstream");
        observation["envelope"]["event"] = "established";
        observation["alpn"] = "h3";
        const auto outcome = engine.quic_lifecycle({{"id", "quic-hook-parent"},
            {"details", {{"quic", observation}}}});
        assert(outcome["proceed"] == true);
        engine.automatic({{"action", "connection-stop"}, {"id", "quic-hook-parent"}}, json::array());
        assert(engine.status()["chain"][0]["instances"] == 0);
    }

    deploy("message", counter);
    assert(run()["logs"][0] == "1" && run()["logs"][0] == "1");
    assert(engine.status()["chain"][0]["instances"] == 0);
    assert(engine.status()["chain"][0]["workers"]["idle"] == 2);
    deploy("message", "import os, time\ntime.sleep(.2)\napi.print(os.getpid())");
    json concurrent_a, concurrent_b;
    std::thread message_a([&] { concurrent_a = run(); });
    std::thread message_b([&] { concurrent_b = run(); });
    for (int i = 0; i < 1000 && engine.status()["chain"][0]["workers"]["busy"] != 2; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    assert(engine.status()["chain"][0]["workers"]["busy"] == 2);
    message_a.join(); message_b.join();
    assert(concurrent_a["ok"] == true && concurrent_b["ok"] == true);
    assert(concurrent_a["logs"] != concurrent_b["logs"]);
    auto id = deploy("flow", counter);
    assert(run()["logs"][0] == "1");
    event["details"]["info"]["side"] = "R";
    assert(run()["logs"][0] == "2");
    event["details"]["info"]["fail"] = true;
    assert(!run()["ok"].get<bool>());
    event["details"]["info"].erase("fail");
    assert(run()["logs"][0] == "3");
    event["id"] = "two";
    assert(run()["logs"][0] == "1");
    assert(engine.status()["chain"][0]["instances"] == 2);
    engine.automatic({{"action", "connection-stop"}, {"id", "one"}}, json::array());
    assert(engine.status()["chain"][0]["instances"] == 1);
    configure({{"operation", "deploy"}, {"id", id}, {"name", "new version"}, {"script", counter},
        {"scope", "all"}, {"instancing", "flow"}});
    assert(run()["logs"][0] == "1");
    configure({{"operation", "enable"}, {"id", id}, {"enabled", false}});
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    assert(run()["logs"][0] == "1");

    deploy("endpoint", counter, {{"endpoint", "destination"}});
    assert(run()["logs"][0] == "1");
    event["id"] = "three";
    event["details"]["info"]["session"] = "tcp_10.0.0.9:9999+tcp_10.0.0.2:443";
    assert(run()["logs"][0] == "2");
    event["details"]["info"]["session"] = "tcp_10.0.0.9:9999+tcp_10.0.0.2:80";
    assert(run()["logs"][0] == "1");
    deploy("endpoint", counter, {{"endpoint", "source"}});
    assert(run()["logs"][0] == "1");
    event["details"]["info"]["session"] = "tcp_10.0.0.9:5555+tcp_10.0.0.99:443";
    assert(run()["logs"][0] == "2");
    event["details"]["info"]["session"] = "unknown";
    assert(run()["error_kind"] == "capacity");
    assert(engine.status()["chain"][0]["errors"] == 0);
    event["details"]["info"]["session"] = "tcp_[2001:db8::1]:55+tcp_[2001:db8::2]:443";
    assert(run()["logs"][0] == "1");

    deploy("flow", counter, {{"max_instances", 1}, {"idle_seconds", 1}});
    assert(run()["logs"][0] == "1");
    event["id"] = "four";
    assert(run()["error_kind"] == "capacity");
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    assert(engine.status()["chain"][0]["instances"] == 0);
    assert(run()["logs"][0] == "1");

    id = deploy("flow", "raise ValueError('bad')", {{"error_limit", 2}});
    assert(!run()["ok"].get<bool>() && !run()["ok"].get<bool>());
    auto status = engine.status();
    assert(status["chain"][0]["suspended"] == true && status["chain"][0]["enabled"] == false);
    assert(!status["notifications"].empty() && run().is_null());
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    assert(engine.status()["chain"][0]["suspended"] == false);
    deploy("flow", "api.state['bad'] = b'bytes'", {{"error_limit", 1}});
    assert(!run()["ok"].get<bool>() && engine.status()["chain"][0]["instances"] == 0);
    deploy("message", "import time\ntime.sleep(1)", {{"timeout_ms", 100}, {"error_limit", 1}});
    assert(!run()["ok"].get<bool>() && engine.status()["chain"][0]["suspended"] == true);
    deploy("message", "import time\ntime.sleep(0.8)", {{"timeout_ms", 1000}});
    for (int i = 0; i < 5; ++i) assert(run()["ok"] == true);
    assert(engine.status()["chain"][0]["suspended"] == true);
    assert(engine.status()["chain"][0]["consecutive_slow"] == 5);

    deploy("flow", counter);
    json first, second;
    std::thread a([&] { first = run(); }), b([&] { second = run(); });
    a.join(); b.join();
    assert(first["ok"] == true && second["ok"] == true);
    assert(first["logs"][0] != second["logs"][0]);
    assert(engine.status()["chain"][0]["instances"] == 1);
    // A full wait budget is infrastructure pressure, not a faulty script.
    deploy("flow", "import time\ntime.sleep(0.6)\n" + counter, {{"error_limit", 1}});
    std::thread held([&] { first = run(); });
    for (int i = 0; i < 1000 && engine.status()["chain"][0]["executing"] == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    assert(engine.status()["chain"][0]["executing"] == 1);
    second = run();
    held.join();
    assert(second["error_kind"] == "capacity" && first["ok"] == true);
    assert(engine.status()["chain"][0]["suspended"] == false);
    assert(engine.status()["chain"][0]["errors"] == 0);

    // Stop during execution must not resurrect the state when that worker finishes.
    deploy("flow", "import time\ntime.sleep(0.15)\n" + counter);
    std::thread stopping([&] { first = run(); });
    for (int i = 0; i < 1000 && engine.status()["chain"][0]["executing"] == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    engine.automatic({{"action", "connection-stop"}, {"id", event["id"]}}, json::array());
    stopping.join();
    assert(first["ok"] == true && engine.status()["chain"][0]["instances"] == 0);
    engine.automatic({{"action", "connection-start"}, {"id", event["id"]}}, json::array());

    const std::string storage = "shared = api.storage.namespace('test')\napi.print(shared.increment('n'))";
    deploy("message", storage);
    assert(run()["logs"][0] == "1");
    deploy("message", storage);
    assert(run()["logs"][0] == "2");
    spider::Inspection restarted(root / "collections");
    assert(restarted.run({{"script", storage}, {"event", event}})["logs"][0] == "3");
    assert(!restarted.run({{"script", storage + "\nraise ValueError('after commit')"}, {"event", event}})["ok"].get<bool>());
    assert(restarted.run({{"script", storage}, {"event", event}})["logs"][0] == "5");
    const auto restarted_status = restarted.status();
    for (const auto& summary : restarted_status.at("recent")) assert(!summary.contains("instance_state"));

    // Protocol observations belong to the flow instance, not its worker. A
    // callback failure breaks continuity; reconnect is required to restart it.
    deploy("flow", R"PY(
if api.phase == 'setup':
    api.connection.track_states()
    return

if api.info.get('fail'):
    raise ValueError('tracking rollback')

if api.http1.state is None:
    api.print('unavailable')
else:
    api.print([message.sequence for message in api.http1.state])
)PY");
    json tracked = {{"action", "connection-content"}, {"id", "tracked-connection"},
        {"details", {{"info", {{"side", "L"}, {"content", "R0VUIC8gSFRUUC8xLjENCg0K"},
            {"content_annotations", json::array({
                json::array({0, 16, "http1.start_line"}),
                json::array({16, 18, "http1.headers"})})}}}}}};
    const json tracked_setup = {{"action", "connection-start"}, {"id", tracked.at("id")}};
    const auto tracking_started = engine.automatic(tracked_setup, json::array());
    assert(tracking_started.at("ok") == true);
    assert(!tracking_started.contains("protocol_state"));

    const auto observed_once = engine.automatic(tracked, json::array());
    assert(observed_once.at("ok") == true && observed_once.at("logs")[0] == "[1]");
    assert(!observed_once.contains("protocol_state"));
    const auto observed_twice = engine.automatic(tracked, json::array());
    assert(observed_twice.at("ok") == true && observed_twice.at("logs")[0] == "[2]");

    // A second connection starts with its own sequence, and cannot inherit the
    // first connection's checkpoint even when both use the same worker pool.
    auto other = tracked;
    other["id"] = "other-tracked-connection";
    engine.automatic({{"action", "connection-start"}, {"id", other.at("id")}}, json::array());
    assert(engine.automatic(other, json::array()).at("logs")[0] == "[1]");

    tracked["details"]["info"]["fail"] = true;
    const auto tracking_failed = engine.automatic(tracked, json::array());
    assert(tracking_failed.at("ok") == false);
    assert(tracking_failed.at("logs").dump().find("tracking disabled") != std::string::npos);
    tracked["details"]["info"].erase("fail");
    assert(engine.automatic(tracked, json::array()).at("logs")[0] == "unavailable");
    assert(engine.automatic(other, json::array()).at("logs")[0] == "[2]");

    engine.automatic({{"action", "connection-stop"}, {"id", tracked.at("id")}}, json::array());
    engine.automatic(tracked_setup, json::array());
    assert(engine.automatic(tracked, json::array()).at("logs")[0] == "[1]");

    const auto tracking_status = engine.status();
    for (const auto& summary : tracking_status.at("recent")) {
        assert(!summary.contains("protocol_state"));
    }

    {
        // Native H1 suspension must cross the actual host checkpoint boundary,
        // not just succeed inside a Python worker. A response to the first
        // request releases the paused second request in the opposite lane.
        deploy("flow", R"PY(
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

if api.side == 'L' and not api.state.get('paused_once'):
    api.message.suspend(api.message.parts[2])
    api.state['paused_once'] = True

if api.side == 'R' and not api.state.get('released'):
    parts = api.message.resume(0, side='L')
    parts[0].http1.target = '/edited'
    api.state['released'] = True

return api.message.commit()
)PY");
        const std::string identity = "native-h1-suspension";
        const auto started = engine.automatic(
            {{"action", "connection-start"}, {"id", identity}}, json::array());
        assert(started.at("ok") == true);

        auto content = [&](const std::string& direction,
                           const std::vector<std::string>& messages) {
            std::string wire;
            auto annotations = json::array();

            for (const auto& message : messages) {
                const auto offset = wire.size();
                const auto line_end = offset + message.find("\r\n") + 2;
                const auto head_end = offset + message.find("\r\n\r\n") + 4;
                annotations.push_back({offset, line_end, "http1.start_line"});
                annotations.push_back({line_end, head_end, "http1.headers"});
                wire += message;
            }

            return engine.automatic({{"action", "connection-content"}, {"id", identity},
                {"details", {{"info", {
                    {"side", direction}, {"content", spider::base64_encode(wire)},
                    {"content_annotations", annotations},
                    {"webhook_control", {{"content-reverse", true}}}
                }}}}}, json::array());
        };

        const std::string first = "GET /first HTTP/1.1\r\nHost: test\r\n\r\n";
        const std::string second = "GET /second HTTP/1.1\r\nHost: test\r\n\r\n";
        const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        const auto paused = content("L", {first, second});
        assert(paused.at("ok") == true);
        assert(paused.at("replacement") == spider::base64_encode(first));
        assert(!paused.contains("replacement_reverse"));

        const auto resumed = content("R", {response});
        assert(resumed.at("ok") == true);
        assert(resumed.at("replacement") == spider::base64_encode(response));
        assert(resumed.at("replacement_reverse") == spider::base64_encode(
            "GET /edited HTTP/1.1\r\nHost: test\r\n\r\n"));
        assert(!resumed.contains("peer_held_parts"));
        assert(!resumed.contains("h1_response_state"));

        // The next response consumes the one remaining request slot. No held
        // bytes or hook decisions may be replayed after successful publication.
        const auto next = content("R", {response});
        assert(next.at("ok") == true);
        assert(next.at("replacement") == spider::base64_encode(response));
        assert(!next.contains("replacement_reverse"));
        engine.automatic({{"action", "connection-stop"}, {"id", identity}}, json::array());
    }

    {
        // Retiring an owner with both H1 lanes paused must discard its native
        // checkpoints and addon flow objects before a fresh exchange begins.
        const std::string source = R"PY(#!mitmproxy

def request(flow):
    print('request ' + flow.request.path)
    if flow.request.path == '/wait':
        flow.intercept()

def response(flow):
    print('response ' + flow.request.path)
    if flow.request.path == '/first':
        flow.intercept()
)PY";
        const std::string identity = "h1-paused-owner-lifecycle";
        const std::string first = "GET /first HTTP/1.1\r\nHost: test\r\n\r\n";
        const std::string waiting = "GET /wait HTTP/1.1\r\nHost: test\r\n\r\n";
        const std::string fresh = "GET /fresh HTTP/1.1\r\nHost: test\r\n\r\n";
        const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        auto content = [&](const std::string& direction,
                           const std::vector<std::string>& messages) {
            std::string wire;
            auto annotations = json::array();

            for (const auto& message : messages) {
                const auto offset = wire.size();
                const auto line_end = offset + message.find("\r\n") + 2;
                const auto head_end = offset + message.find("\r\n\r\n") + 4;
                annotations.push_back({offset, line_end, "http1.start_line"});
                annotations.push_back({line_end, head_end, "http1.headers"});
                wire += message;
            }

            return engine.automatic({{"action", "connection-content"}, {"id", identity},
                {"details", {{"info", {
                    {"side", direction}, {"content", spider::base64_encode(wire)},
                    {"content_annotations", annotations},
                    {"webhook_control", {{"content-reverse", true}}}
                }}}}}, json::array());
        };

        for (const std::string retirement : {"connection-stop", "redeploy", "disable"}) {
            const auto deployment = deploy("flow", source);
            const auto started = engine.automatic(
                {{"action", "connection-start"}, {"id", identity}}, json::array());
            assert(started.at("ok") == true);

            const auto requests = content("L", {first, waiting});
            assert(requests.at("ok") == true);
            assert(requests.at("replacement") == spider::base64_encode(first));
            assert(!requests.contains("replacement_reverse"));

            const auto paused_response = content("R", {response});
            assert(paused_response.at("ok") == true);
            assert(paused_response.value("need_more", false));
            assert(!paused_response.contains("replacement_reverse"));
            assert(engine.status()["chain"][0]["instances"] == 1);

            if (retirement == "connection-stop") {
                engine.automatic(
                    {{"action", "connection-stop"}, {"id", identity}}, json::array());
            } else if (retirement == "redeploy") {
                configure({{"operation", "deploy"}, {"id", deployment},
                    {"name", "replacement"}, {"script", source},
                    {"scope", "all"}, {"instancing", "flow"}});
            } else {
                configure({{"operation", "enable"}, {"id", deployment}, {"enabled", false}});
                configure({{"operation", "enable"}, {"id", deployment}, {"enabled", true}});
            }
            assert(engine.status()["chain"][0]["instances"] == 0);

            // A replacement addon cannot join a connection whose setup it
            // never observed. Reject late content without publishing old holds;
            // the host's existing fail-open policy remains a separate boundary.
            if (retirement != "connection-stop") {
                const auto late = content("L", {fresh});
                assert(late.at("ok") == false);
                assert(late.at("replacement").is_null());
                assert(!late.contains("replacement_reverse"));
                assert(late.at("error").get<std::string>().find(
                    "Content arrived without addon connection setup") != std::string::npos);

                // A failed addon generation is not replayed. Prepare a new
                // generation and reconnect before checking normal publication.
                configure({{"operation", "deploy"}, {"id", deployment},
                    {"name", "fresh generation"}, {"script", source},
                    {"scope", "all"}, {"instancing", "flow"}});
                engine.automatic(
                    {{"action", "connection-stop"}, {"id", identity}}, json::array());
            }

            const auto reopened = engine.automatic(
                {{"action", "connection-start"}, {"id", identity}}, json::array());
            assert(reopened.at("ok") == true);

            const auto next_request = content("L", {fresh});
            if (!next_request.value("ok", false)) {
                std::cerr << retirement << ": " << next_request.dump(2) << '\n';
            }
            assert(next_request.at("ok") == true);
            assert(next_request.at("replacement") == spider::base64_encode(fresh));
            assert(!next_request.contains("replacement_reverse"));
            assert(next_request.at("logs") == json::array({"request /fresh"}));

            const auto next_response = content("R", {response});
            assert(next_response.at("ok") == true);
            assert(next_response.at("replacement") == spider::base64_encode(response));
            assert(!next_response.contains("replacement_reverse"));
            assert(next_response.at("logs") == json::array({"response /fresh"}));
            engine.automatic(
                {{"action", "connection-stop"}, {"id", identity}}, json::array());
        }
    }

    if (argc == 2) {
        // Optional production capture: replay the real producer envelopes
        // through the host and packaged workers, not hand-built setup values.
        std::ifstream input(argv[1]);
        assert(input.is_open());
        std::vector<json> observations;
        std::string line;
        while (std::getline(input, line)) {
            auto observation = json::parse(line);
            const auto scope = observation.value("details", json::object())
                .value("info", json::object()).value("scope", "");
            if (scope == "transport" || scope == "stream")
                observations.push_back(std::move(observation));
        }
        assert(!observations.empty());
        deploy("flow", R"PY(
if api.phase == 'setup':
    api.state['scope'] = api.info['scope']
    api.state['parent'] = api.info.get('parent_id')
else:
    assert api.state['scope'] == api.info['scope'] == 'stream'
    assert api.state['parent'] == api.info['parent_id']
)PY");
        for (const auto& observation : observations) {
            const auto action = observation.at("action");
            if (action != "connection-start" && action != "connection-content" &&
                action != "connection-stop") continue;
            const auto result = engine.automatic(observation, json::array());
            assert(action == "connection-stop" || result.at("ok") == true);
        }
        assert(engine.status()["chain"][0]["instances"] == 0);

        // H3 content adaptation is not implemented. Replay only its inspection
        // lifecycle to prove the physical parent adds no HTTP client callbacks.
        deploy("flow", "#!mitmproxy\ndef client_connected(client):\n    print('client')\n");
        unsigned int streams = 0;
        for (const auto& observation : observations) {
            const auto action = observation.at("action");
            if (action != "connection-start" && action != "connection-stop") continue;
            const auto result = engine.automatic(observation, json::array());
            if (action == "connection-stop") continue;
            if (observation["details"]["info"]["scope"] == "transport") {
                assert(result.is_null());
            } else {
                assert(result.at("ok") == true);
                ++streams;
            }
        }
        assert(streams >= 4);
        assert(engine.status()["chain"][0]["instances"] == 0);
        std::cout << "PASS: captured QUIC parent/stream envelopes through Spider workers\n";
    }

    std::filesystem::remove_all(root);
}
