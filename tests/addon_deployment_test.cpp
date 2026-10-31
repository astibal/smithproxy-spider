#include "inspection.hpp"
#include "binary_envelope.hpp"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

using nlohmann::json;

int main() {
    spider::Inspection engine;
    auto configure = [&](json request) {
        request["revision"] = engine.status()["revision"];
        return engine.configure(request);
    };
    const std::string source =
        "#!mitmproxy\nimport asyncio\nprint('loaded')\ncount = 0\n"
        "async def request(flow):\n"
        "    global count\n    await asyncio.sleep(.1)\n    count += 1\n"
        "    print('request', count)\n"
        "def error(flow):\n    print('closed', flow.request.path)\n";
    auto state = configure({{"operation", "deploy"}, {"name", "Addon"}, {"script", source},
                            {"scope", "all"}, {"instancing", "flow"},
                            {"idle_seconds", 1}, {"max_instances", 1},
                            {"filter", "src host 10.0.0.1"}});
    const auto id = state["chain"][0]["id"];
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});

    auto setup = [&](const std::string& identity) {
        return engine.automatic({{"action", "connection-start"}, {"id", identity},
            {"details", {{"info", {{"session", "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"}}}}}}, json::array());
    };
    auto content = [&](const std::string& identity,
                       const std::string& bytes = "AAAOAQUAAAABgodBiS+R010FXSVCf4Q=",
                       unsigned sequence = 1) {
        return engine.automatic({{"action", "connection-content"}, {"id", identity},
            {"details", {{"info", {
                {"session", "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"}, {"side", "L"},
                {"content", bytes},
                {"content_annotations", {{0, 9, "h2.frame.header"}}},
                {"webhook_control", {{"version", 1}, {"sequence", sequence},
                                     {"mode", sequence == 1 ? "regular" : "strict"}}}
            }}}}}, json::array());
    };
    auto stop = [&](const std::string& identity) {
        // Deliberately no session label: a stop must not depend on the filter.
        return engine.automatic({{"action", "connection-stop"}, {"id", identity}}, json::array());
    };

    const auto started = setup("one");
    assert(started["ok"] == true && started["rewrite_requested"] == true);
    assert(started["logs"] == json::array({"loaded"}));
    const auto first = content("one");
    assert(first["ok"] == true && first["translated"] == true);
    assert(first["logs"] == json::array({"request 1"}));
    assert(engine.translation_required({{"id", "one"}}));
    assert(stop("one").is_null());
    assert(!engine.translation_required({{"id", "one"}}));
    assert(engine.status()["recent"].back()["logs"] == json::array({"closed /"}));
    const auto runs = engine.status()["runs"];
    stop("one");
    stop("never registered");
    assert(engine.status()["runs"] == runs);

    // A failed warm-up must not replace the live generation or its globals.
    const auto before = engine.status();
    bool rejected = false;
    try {
        configure({{"operation", "deploy"}, {"id", id}, {"name", "Broken"},
                   {"script", "#!mitmproxy\nraise RuntimeError('startup failed')"},
                   {"scope", "all"}, {"instancing", "flow"}});
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    assert(engine.status()["revision"] == before["revision"]);
    assert(engine.status()["chain"] == before["chain"]);
    assert(setup("two")["ok"] == true);
    assert(content("two")["logs"] == json::array({"request 2"}));
    stop("two");

    // Closing during an awaited hook must drain the original owner, discard
    // its publication, and never resurrect the native translation pin.
    assert(setup("racing")["ok"] == true);
    json in_flight;
    std::thread running([&] { in_flight = content("racing"); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (engine.status()["running"] == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(engine.status()["running"] != 0);
    stop("racing");
    running.join();
    assert(in_flight["ok"] == false);
    assert(!engine.translation_required({{"id", "racing"}}));
    assert(engine.status()["recent"].back()["logs"] == json::array({"closed /"}));
    assert(setup("after race")["ok"] == true);
    assert(content("after race")["logs"] == json::array({"request 4"}));
    stop("after race");

    // The native checkpoint and Python stream table must share a lifetime.
    // Status polling used to expire only the native side of an idle connection.
    assert(setup("idle owner")["ok"] == true);
    assert(content("idle owner")["logs"] == json::array({"request 5"}));
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    assert(engine.status()["chain"][0]["instances"] == 1);
    assert(engine.translation_required({{"id", "idle owner"}}));
    const auto excess = setup("over capacity");
    assert(excess["ok"] == false);
    assert(excess["error_kind"] == "capacity");
    const auto continued = content("idle owner", "AAAOAQUAAAADgodBiS+R010FXSVCf4Q=", 2);
    if (!continued.value("ok", false)) {
        std::cerr << continued.dump(2) << '\n';
    }
    assert(continued["ok"] == true && continued["translated"] == true);
    assert(continued["logs"] == json::array({"request 6"}));
    stop("idle owner");
    assert(engine.status()["chain"][0]["instances"] == 0);
    assert(setup("capacity released")["ok"] == true);
    stop("capacity released");

    // Local H1 responses use a backend-owned pipeline checkpoint. A later
    // local response must not overtake an earlier request sent upstream.
    configure({{"operation", "deploy"}, {"id", id}, {"name", "H1 local response"},
        {"script", "#!mitmproxy\nfrom mitmproxy import http\n"
                   "def request(flow):\n"
                   "    if flow.request.path == '/local':\n"
                   "        flow.response = http.Response.make(204, b'local body', {'X-Local': 'yes'})\n"
                   "def response(flow):\n"
                   "    if flow.request.path == '/local':\n"
                   "        flow.response.trailers = http.Headers([(b'X-Finished', b'yes')])\n"},
        {"scope", "all"}, {"instancing", "flow"}});
    assert(setup("h1 local")["ok"] == true);
    const std::string first_request =
        "GET /origin HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const std::string local_request =
        "GET /local HTTP/1.1\r\nHost: example.test\r\n\r\n";
    auto h1_content = [&](const std::string& side, const std::string& payload,
                          const json& annotations, unsigned sequence) {
        return engine.automatic({{"action", "connection-content"}, {"id", "h1 local"},
            {"details", {{"info", {
                {"session", "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"}, {"side", side},
                {"content", spider::base64_encode(payload)},
                {"content_annotations", annotations},
                {"webhook_control", {{"version", 1}, {"sequence", sequence},
                                     {"mode", "regular"}, {"content-reverse", true}}}
            }}}}}, json::array());
    };
    const auto first_line = first_request.find("\r\n") + 2;
    const auto first_head = first_request.size();
    const auto second_line = local_request.find("\r\n") + 2;
    const auto second_start = first_request.size();
    const auto queued = h1_content("L", first_request + local_request, {
        {0, first_line, "http1.start_line"},
        {first_line, first_head, "http1.headers"},
        {second_start, second_start + second_line, "http1.start_line"},
        {second_start + second_line, second_start + local_request.size(), "http1.headers"},
    }, 1);
    assert(queued["ok"] == true);
    assert(queued["replacement"] == spider::base64_encode(first_request));
    assert(!queued.contains("replacement_reverse"));
    assert(!queued.contains("h1_response_state"));

    const std::string origin_response =
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin";
    const auto response_line = origin_response.find("\r\n") + 2;
    const auto flushed = h1_content("R", origin_response, {
        {0, response_line, "http1.start_line"},
        {response_line, origin_response.find("\r\n\r\n") + 4, "http1.headers"},
    }, 2);
    assert(flushed["ok"] == true);
    const std::string local_response =
        "HTTP/1.1 204 No Content\r\nX-Local: yes\r\nTrailer: X-Finished\r\n"
        "Transfer-Encoding: chunked\r\n\r\na\r\nlocal body\r\n0\r\n"
        "X-Finished: yes\r\n\r\n";
    assert(flushed["replacement"] ==
           spider::base64_encode(origin_response + local_response));
    assert(!flushed.contains("h1_response_state"));
    stop("h1 local");

    // HTTP/1 termination is an explicit callback-local producer decision.
    // It carries no wire bytes and does not retire persistent addon state.
    configure({{"operation", "deploy"}, {"id", id}, {"name", "H1 kill"},
        {"script", "#!mitmproxy\n"
                   "events = []\n"
                   "def requestheaders(flow):\n"
                   "    events.append('requestheaders')\n"
                   "    flow.kill()\n"
                   "def error(flow):\n"
                   "    assert str(flow.error) == 'Connection killed.'\n"
                   "    events.append('error')\n"
                   "    print(events)\n"},
        {"scope", "all"}, {"instancing", "flow"}});
    assert(setup("h1 kill")["ok"] == true);
    auto killed_event = json{{"action", "connection-content"}, {"id", "h1 kill"},
        {"details", {{"info", {
            {"session", "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"}, {"side", "L"},
            {"content", spider::base64_encode(first_request)},
            {"content_annotations", {
                {0, first_line, "http1.start_line"},
                {first_line, first_head, "http1.headers"},
            }},
            {"webhook_control", {{"version", 1}, {"sequence", 1},
                                 {"mode", "regular"}, {"content-reverse", true},
                                 {"connection-close", true}}}
        }}}}};
    const auto killed = engine.automatic(killed_event, json::array());
    assert(killed["ok"] == true);
    assert((killed["connection_close"] ==
            json{{"reason", "Connection killed."}}));
    assert(killed["replacement"] == "");
    assert(!killed.contains("replacement_reverse"));
    assert(killed["logs"] == json::array({"['requestheaders', 'error']"}));
    stop("h1 kill");
    assert(setup("after h1 kill")["ok"] == true);
    stop("after h1 kill");

    state = configure({{"operation", "deploy"}, {"name", "Native"}, {"script", "return None"}});
    const auto second_id = state["chain"][1]["id"];
    const auto revision = state["revision"];
    rejected = false;
    try {
        configure({{"operation", "enable"}, {"id", second_id}, {"enabled", true}});
    } catch (const std::invalid_argument& error) {
        rejected = std::string(error.what()).find("exactly one") != std::string::npos;
    }
    assert(rejected);
    assert(engine.status()["revision"] == revision);

    // An abnormal teardown cannot leave an enabled generation with leaked
    // connection ownership. The failure is visible and requires redeployment.
    configure({{"operation", "deploy"}, {"id", id}, {"name", "Failing teardown"},
               {"script", "#!mitmproxy\ndef error(flow):\n    raise SystemExit('stop failed')\n"},
               {"scope", "all"}, {"instancing", "flow"}});
    assert(setup("bad stop")["ok"] == true);
    assert(content("bad stop")["ok"] == true);
    stop("bad stop");
    const auto failed = engine.status();
    assert(failed["chain"][0]["enabled"] == false);
    assert(failed["chain"][0]["suspended"] == true);
    assert(failed["chain"][0]["suspension_reason"] ==
           "Addon connection teardown failed; redeploy required");
    assert(failed["chain"][0]["workers"]["starts"] == 1);
    assert(failed["chain"][0]["workers"]["restarts"] == 0);
    assert(failed["recent"].back()["ok"] == false);
    assert(!engine.translation_required({{"id", "bad stop"}}));

    configure({{"operation", "deploy"}, {"id", id}, {"name", "Cleanup failure"},
               {"script", "#!mitmproxy\ndef done():\n    raise ValueError('cleanup history test')\n"},
               {"scope", "all"}, {"instancing", "flow"}});
    configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    const auto removed = configure({{"operation", "remove"}, {"id", id}});
    const auto cleanup = removed["recent"].back();
    assert(cleanup["phase"] == "shutdown");
    assert(cleanup["script_id"] == id);
    assert(cleanup["ok"] == false);
    assert(cleanup["logs"].dump().find("cleanup history test") != std::string::npos);
    assert(engine.status()["runs"] == removed["runs"]);
    assert(engine.status()["recent"].back() == cleanup);

    // Removal during a callback leaves report delivery to that callback's
    // owner. It must survive removal and not be recorded twice by configure().
    const auto retirement_release = std::filesystem::temp_directory_path() /
        ("spider-addon-retirement-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) +
         ".release");
    std::filesystem::remove(retirement_release);
    state = configure({{"operation", "deploy"}, {"name", "Concurrent cleanup"},
        {"script", "#!mitmproxy\nimport asyncio, os\n"
                   "async def request(flow):\n"
                   "    while not os.path.exists(" +
                       json(retirement_release.string()).dump() + "):\n"
                   "        await asyncio.sleep(.005)\n"
                   "def done():\n    print('retired exactly once')\n"},
        {"scope", "all"}, {"instancing", "flow"}});
    const auto concurrent_id = state["chain"].back()["id"];
    configure({{"operation", "enable"}, {"id", concurrent_id}, {"enabled", true}});
    assert(setup("retiring callback")["ok"] == true);
    json retiring_result;
    std::thread finishing([&] { retiring_result = content("retiring callback"); });
    // A request can be counted as running before it owns the worker. Wait for
    // admission so removal actually exercises retirement during an exchange.
    const auto worker_busy = [&] {
        const auto snapshot = engine.status();
        return snapshot["chain"].back()["workers"]["busy"] != 0;
    };
    const auto wait_until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!worker_busy() && std::chrono::steady_clock::now() < wait_until) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(worker_busy());
    configure({{"operation", "remove"}, {"id", concurrent_id}});
    std::ofstream(retirement_release) << "release\n";
    finishing.join();
    std::filesystem::remove(retirement_release);
    unsigned shutdowns = 0;
    const auto after_retirement = engine.status();
    for (const auto& report : after_retirement["recent"]) {
        if (report.value("phase", "") == "shutdown" && report.value("script_id", json()) == concurrent_id) {
            ++shutdowns;
            assert(report["logs"] == json::array({"retired exactly once"}));
        }
    }
    if (shutdowns != 1) {
        std::cerr << "Retiring callback result: " << retiring_result.dump(2) << '\n';
        std::cerr << after_retirement.dump(2) << '\n';
    }
    assert(shutdowns == 1);

    state = configure({{"operation", "deploy"}, {"name", "Failed retiring callback"},
        {"script", "#!mitmproxy\nimport asyncio\n"
                   "async def request(flow):\n    await asyncio.sleep(2)\n"},
        {"scope", "all"}, {"instancing", "flow"}, {"timeout_ms", 100}});
    const auto failing_id = state["chain"].back()["id"];
    configure({{"operation", "enable"}, {"id", failing_id}, {"enabled", true}});
    assert(setup("retiring timeout")["ok"] == true);
    std::thread timing_out([&] { content("retiring timeout"); });
    const auto timeout_wait = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!worker_busy() && std::chrono::steady_clock::now() < timeout_wait) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(worker_busy());
    configure({{"operation", "remove"}, {"id", failing_id}});
    timing_out.join();
    const auto timeout_history = engine.status()["recent"];
    assert(timeout_history.back()["phase"] == "shutdown");
    assert(timeout_history.back()["script_id"] == failing_id);
    assert(timeout_history.back()["ok"] == false);
    assert(timeout_history.back()["cleanup_skipped"] == true);

    {
        // A generation worker is shared by many connections, but its Python
        // state never migrates to another worker.  Retiring the deployment
        // closes every pending flow before running done() exactly once.
        spider::Inspection stressed;
        auto update = [&](json request) {
            request["revision"] = stressed.status()["revision"];
            return stressed.configure(request);
        };
        const std::string stress_source =
            "#!mitmproxy\nimport os\nrequests = 0\nclosed = 0\n"
            "def request(flow):\n"
            "    global requests\n    requests += 1\n"
            "    print('request', os.getpid(), requests)\n"
            "def error(flow):\n"
            "    global closed\n    closed += 1\n"
            "def done():\n"
            "    print('done', os.getpid(), requests, closed)\n";
        auto stress_state = update({{"operation", "deploy"}, {"name", "State stress"},
            {"script", stress_source}, {"scope", "all"}, {"instancing", "flow"},
            {"max_instances", 64}});
        const auto stress_id = stress_state["chain"][0]["id"];
        update({{"operation", "enable"}, {"id", stress_id}, {"enabled", true}});

        const auto begin = [&](const std::string& identity) {
            return stressed.automatic({{"action", "connection-start"}, {"id", identity},
                {"details", {{"info", {{"session",
                    "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"}}}}}}, json::array());
        };
        const auto request_content = [&](const std::string& identity) {
            return stressed.automatic({{"action", "connection-content"}, {"id", identity},
                {"details", {{"info", {
                    {"session", "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"},
                    {"side", "L"}, {"content", "AAAOAQUAAAABgodBiS+R010FXSVCf4Q="},
                    {"content_annotations", {{0, 9, "h2.frame.header"}}},
                    {"webhook_control", {{"version", 1}, {"sequence", 1},
                                         {"mode", "regular"}}}
                }}}}}, json::array());
        };

        constexpr unsigned connection_count = 48;
        std::string worker_pid;
        for (unsigned index = 0; index < connection_count; ++index) {
            const auto identity = "stress-" + std::to_string(index);
            assert(begin(identity)["ok"] == true);
            const auto result = request_content(identity);
            assert(result["ok"] == true);
            const auto line = result["logs"][0].get<std::string>();
            const auto first_space = line.find(' ');
            const auto second_space = line.find(' ', first_space + 1);
            assert(first_space != std::string::npos && second_space != std::string::npos);
            const auto pid = line.substr(first_space + 1, second_space - first_space - 1);
            if (worker_pid.empty()) {
                worker_pid = pid;
            }
            assert(pid == worker_pid);
            assert(line.substr(second_space + 1) == std::to_string(index + 1));
        }
        const auto before_remove = stressed.status();
        assert(before_remove["chain"][0]["instances"] == connection_count);
        assert(before_remove["chain"][0]["workers"]["starts"] == 1);

        const auto retired = update({{"operation", "remove"}, {"id", stress_id}});
        const auto report = retired["recent"].back();
        assert(report["ok"] == true);
        assert(report["phase"] == "shutdown");
        assert(report["logs"] == json::array({
            "done " + worker_pid + " " + std::to_string(connection_count) + " " +
                std::to_string(connection_count)
        }));
    }
}
