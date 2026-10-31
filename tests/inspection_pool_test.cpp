#include "inspection_pool.hpp"
#include <atomic>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>
#include <unistd.h>
using nlohmann::json;
using Clock = std::chrono::steady_clock;

json request(const std::string& mode = "") {
    return {{"event", {{"details", {{"info", {{"content", "YWJj"}, {"mode", mode}}}}}}}};
}
template<class Predicate> void await(Predicate ready) {
    const auto deadline = Clock::now() + std::chrono::seconds(5);
    while (!ready() && Clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    assert(ready());
}
int main() {
    char directory[] = "/tmp/spider-pool-XXXXXX";
    assert(mkdtemp(directory));
    const std::filesystem::path root(directory);
    {
        const auto marker = root / "addon-shutdown.txt";
        const auto source = "#!mitmproxy\nimport asyncio\n"
            "async def done():\n    await asyncio.sleep(.05)\n"
            "    with open(" + json(marker.string()).dump() + ", 'a') as output:\n"
            "        output.write('done\\n')\n"
            "    print('cleanup complete')\n";
        spider::InspectionPool pool(source, root.string());
        pool.warm();
        pool.retire();
        pool.retire();
        std::ifstream input(marker);
        std::string first, second;
        assert(std::getline(input, first) && first == "done");
        assert(!std::getline(input, second));
        assert(pool.status()["idle"] == 0);
        assert(pool.status()["shutdown"]["ok"] == true);
        assert(pool.status()["shutdown"]["logs"] == json::array({"cleanup complete"}));
    }
    for (const auto* cleanup : {"while True: pass", "import time; time.sleep(10)"}) {
        spider::InspectionPool pool(std::string("#!mitmproxy\ndef done():\n    ") + cleanup + "\n",
                                    root.string());
        pool.warm();
        const auto start = Clock::now();
        pool.retire();
        assert(Clock::now() - start < std::chrono::seconds(2));
        assert(pool.status()["idle"] == 0);
        assert(pool.status()["shutdown"]["ok"] == false);
        assert(pool.status()["shutdown"]["error_kind"] == "shutdown");
    }
    {
        spider::InspectionPool pool(
            "#!mitmproxy\ndef done():\n    print('cleanup started')\n"
            "    raise ValueError('cleanup test failure')\n", root.string());
        pool.warm();
        pool.retire();
        const auto report = pool.status()["shutdown"];
        assert(report["ok"] == false);
        assert(report["error"] == "Addon cleanup hook failed");
        assert(report["logs"][0] == "cleanup started");
        assert(report["logs"].dump().find("cleanup test failure") != std::string::npos);
    }
    for (const bool directive : {false, true}) {
        // Actual addons must pin automatically, even if their shebang overrides
        // the requested convention. The caller need not select Generation too.
        const std::string body = "import os, time\nprint('loaded once')\ncalls = 0\n"
            "def request(flow):\n    global calls\n    calls += 1\n"
            "    until = time.process_time() + .002\n"
            "    while time.process_time() < until:\n        pass\n"
            "    print(os.getpid(), calls)\n"
            "    if calls == 1400:\n        print(time.process_time())\n";
        const auto source = directive ? "\xEF\xBB\xBF#!mitmproxy\r\n" + body : body;
        spider::InspectionPool pool(source, root.string(),
            spider::InspectionPool::Lifetime::Rotating, directive ? "unknown" : "mitmproxy");
        pool.warm();
        assert(pool.status()["capacity"] == 1);
        assert(pool.status()["lifetime"] == "generation");
        assert(pool.status()["script_api"] == "mitmproxy");
        std::string process;
        // Cross both old retirement thresholds: >4096 IPC calls and >2 CPU
        // seconds, while each callback stays well below its own budget.
        const unsigned connection_count = directive ? 3 : 1400;
        for (unsigned index = 1; index <= connection_count; ++index) {
            const auto identity = "addon-connection-" + std::to_string(index);
            json invocation = {{"event", {{"id", identity}, {"action", "connection-start"}}},
                               {"instance", {{"mode", "flow"}}}};
            const auto setup = pool.run(invocation, 1000);
            assert(setup["ok"] == true && setup["rewrite_requested"] == true);
            if (index == 1) {
                assert(setup["logs"] == json::array({"loaded once"}));
            } else {
                assert(setup["logs"].empty());
            }
            // A complete H2 GET https://example.test/ on stream 1. Reusing the
            // stream number across distinct connections must not reset state.
            invocation["event"]["action"] = "connection-content";
            invocation["event"]["details"]["info"] = {
                {"side", "L"}, {"content", "AAAOAQUAAAABgodBiS+R010FXSVCf4Q="},
                {"content_annotations", json::array({json::array({0, 9, "h2.frame.header"})})}};
            invocation["translate_allowed"] = true;
            const auto result = pool.run(invocation, 1000);
            assert(result["ok"] == true && result["translated"] == true);
            const auto log = result["logs"][0].get<std::string>();
            const auto separator = log.find(' ');
            if (process.empty()) {
                process = log.substr(0, separator);
            }
            assert(log.substr(0, separator) == process);
            assert(log.substr(separator + 1) == std::to_string(index));
            if (index == 1400) {
                assert(std::stod(result["logs"][1].get<std::string>()) > 2.0);
            }
            invocation["event"]["action"] = "connection-stop";
            assert(pool.run(invocation, 1000)["ok"] == true);
        }
        assert(pool.status()["starts"] == 1);
        assert(pool.status()["restarts"] == 0);
        assert(pool.status()["rotations"] == 0);
        const auto failed = pool.run(request(), 1000);
        assert(failed["ok"] == false && failed["worker_state_lost"] == true);
        assert(pool.run(request(), 1000)["error_kind"] == "worker_state_lost");
        assert(pool.status()["starts"] == 1);
    }
    {
        // Generation mode pins every connection to one process. Python module
        // state is used here to observe process continuity independently of the
        // addon adapter, which retains the actual addon globals and instances.
        const auto source = "import os, builtins\n"
            "builtins.generation_calls = getattr(builtins, 'generation_calls', 0) + 1\n"
            "api.print(os.getpid(), builtins.generation_calls)\nreturn api.bytes";
        spider::InspectionPool pool(source, root.string(), spider::InspectionPool::Lifetime::Generation);
        pool.warm();
        assert(pool.status()["capacity"] == 1);
        assert(pool.status()["starts"] == 1);
        std::string process;
        for (unsigned index = 1; index <= 300; ++index) {
            auto invocation = request();
            invocation["event"]["id"] = "connection-" + std::to_string(index % 7);
            const auto result = pool.run(invocation, 1000);
            assert(result["ok"] == true);
            const auto log = result["logs"][0].get<std::string>();
            const auto separator = log.find(' ');
            if (process.empty()) process = log.substr(0, separator);
            assert(log.substr(0, separator) == process);
            assert(log.substr(separator + 1) == std::to_string(index));
        }
        assert(pool.status()["starts"] == 1);
        assert(pool.status()["rotations"] == 0);
        assert(pool.status()["state_lost"] == false);
    }
    {
        // A queued connection must learn that state was lost, not enter a
        // freshly spawned replacement process with an empty addon namespace.
        spider::InspectionPool pool(
            "import os, time\nif api.info.get('mode') == 'exit':\n"
            "    time.sleep(.1)\n    os._exit(7)\nreturn api.bytes",
            root.string(), spider::InspectionPool::Lifetime::Generation);
        pool.warm();
        json dying, waiting;
        std::thread first([&] { dying = pool.run(request("exit"), 1000); });
        await([&] { return pool.status()["busy"] == 1; });
        std::thread second([&] { waiting = pool.run(request(), 1000); });
        first.join();
        second.join();
        assert(dying["ok"] == false && dying["worker_state_lost"] == true);
        assert(waiting["error_kind"] == "worker_state_lost");
        assert(pool.run(request(), 1000)["error_kind"] == "worker_state_lost");
        assert(pool.status()["starts"] == 1);
        assert(pool.status()["restarts"] == 0);
        assert(pool.status()["state_lost"] == true);
        assert(pool.status()["queued"] == 0);
        bool refused = false;
        try {
            pool.warm();
        } catch (const std::runtime_error&) {
            refused = true;
        }
        assert(refused);
    }
    {
        spider::InspectionPool pool("import time\ntime.sleep(1)", root.string(),
                                    spider::InspectionPool::Lifetime::Generation);
        pool.warm();
        const auto timed_out = pool.run(request(), 50);
        assert(timed_out["ok"] == false && timed_out["worker_state_lost"] == true);
        assert(pool.run(request(), 1000)["error_kind"] == "worker_state_lost");
        assert(pool.status()["starts"] == 1);
    }
    {
        // Retirement is a state transition, not a timeout. A callback that
        // already owns the generation may finish and deliver cleanup, while
        // every queued caller must wake immediately without entering Python.
        const auto release = root / "retire-queued.release";
        const auto source = "#!mitmproxy\nimport asyncio, os\n"
            "async def request(flow):\n"
            "    while not os.path.exists(" + json(release.string()).dump() + "):\n"
            "        await asyncio.sleep(.005)\n"
            "    print('request complete')\n"
            "def done():\n"
            "    print('cleanup once')\n";
        spider::InspectionPool pool(source, root.string());
        pool.warm();

        json invocation = {
            {"event", {{"id", "retire-queued"}, {"action", "connection-start"}}},
            {"instance", {{"mode", "flow"}}},
        };
        assert(pool.run(invocation, 1000)["ok"] == true);
        invocation["event"]["action"] = "connection-content";
        invocation["event"]["details"]["info"] = {
            {"side", "L"},
            {"content", "AAAOAQUAAAABgodBiS+R010FXSVCf4Q="},
            {"content_annotations", json::array({
                json::array({0, 9, "h2.frame.header"}),
            })},
        };
        invocation["translate_allowed"] = true;

        json admitted;
        std::thread active([&] { admitted = pool.run(invocation, 1000); });
        await([&] { return pool.status()["busy"] == 1; });

        std::array<json, 4> rejected;
        std::vector<std::thread> queued;
        std::atomic_uint queue_finished{};
        for (auto& result : rejected) {
            queued.emplace_back([&pool, &invocation, &result, &queue_finished] {
                result = pool.run(invocation, 1000);
                ++queue_finished;
            });
        }
        await([&] { return pool.status()["queued"] == rejected.size(); });

        pool.retire();
        const auto queue_deadline = Clock::now() + std::chrono::milliseconds(500);
        while (queue_finished != rejected.size() && Clock::now() < queue_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const bool released_before_active_callback = queue_finished == rejected.size();
        std::ofstream(release) << "release\n";
        for (auto& caller : queued) caller.join();
        active.join();
        assert(released_before_active_callback);
        for (const auto& result : rejected) {
            assert(result["ok"] == false);
            assert(result["error_kind"] == "capacity");
            assert(result["error"] == "Deployment pool retired");
        }

        assert(admitted["ok"] == true);
        assert(admitted["logs"] == json::array({"request complete"}));
        const auto status = pool.status();
        assert(status["idle"] == 0);
        assert(status["busy"] == 0);
        assert(status["queued"] == 0);
        assert(status["starts"] == 1);
        assert(status["restarts"] == 0);
        assert(status["shutdown"]["ok"] == true);
        assert(status["shutdown"]["logs"] == json::array({"cleanup once"}));

        const auto report = pool.take_shutdown_report();
        assert(report["logs"] == json::array({"cleanup once"}));
        assert(pool.take_shutdown_report().is_null());
    }
    {
        spider::InspectionPool pool("import os\nglobal calls\ncalls = globals().get('calls', 0) + 1\napi.print(os.getpid(), calls)\nreturn api.bytes", root.string());
        pool.warm();
        assert(pool.status()["idle"] == 2 && pool.status()["starts"] == 2);
        std::set<std::string> processes;
        const auto begin = Clock::now();
        for (int i = 0; i < 100; ++i) {
            const auto result = pool.run(request(), 1000);
            assert(result["ok"] == true && result["replacement"] == "YWJj");
            const auto log = result["logs"][0].get<std::string>();
            assert(log.ends_with(" 1")); // globals never leak between invocations
            processes.insert(log);
        }
        assert(processes.size() == 2 && pool.status()["starts"] == 2);
        std::cout << "Warm pool: 100 callbacks in " <<
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - begin).count() << " us\n";
        pool.retire();
        assert(pool.status()["idle"] == 0);
        assert(pool.run(request(), 100)["error_kind"] == "capacity");
    }
    {
        spider::InspectionPool pool("import time, os\ntime.sleep(.2)\napi.print(os.getpid())", root.string());
        pool.warm();
        json a, b;
        std::thread first([&] { a = pool.run(request(), 1000); });
        std::thread second([&] { b = pool.run(request(), 1000); });
        await([&] { return pool.status()["busy"] == 2; });
        const auto excess = pool.run(request(), 50);
        assert(excess["error_kind"] == "capacity");
        assert(pool.status()["queued"] == 0); // timed-out ticket must not block its successors
        first.join(); second.join();
        assert(a["ok"] == true && b["ok"] == true && a["logs"] != b["logs"]);
    }
    {
        // Hold both slots, then let only one become available. The two queued
        // requests must enter in FIFO order, not race for a freshly free slot.
        spider::InspectionPool pool(
            "import time\napi.print(api.storage.namespace('fifo').increment('order'))\n"
            "time.sleep(float(api.info.get('mode') or 0))", root.string());
        pool.warm();
        json long_result, short_result, first_result, second_result;
        std::thread long_call([&] { long_result = pool.run(request(".4"), 1000); });
        std::thread short_call([&] { short_result = pool.run(request(".15"), 1000); });
        await([&] { return pool.status()["busy"] == 2; });
        std::thread first([&] { first_result = pool.run(request(".05"), 1000); });
        await([&] { return pool.status()["queued"] == 1; });
        std::thread second([&] { second_result = pool.run(request(), 1000); });
        first.join(); second.join(); long_call.join(); short_call.join();
        assert(long_result["ok"] == true && short_result["ok"] == true);
        assert(first_result["ok"] == true && first_result["logs"][0] == "3");
        assert(second_result["ok"] == true && second_result["logs"][0] == "4");
        assert(pool.status()["queued"] == 0);
    }
    {
        // A Python module can retain changes, but only inside this deployment.
        spider::InspectionPool a("import builtins\nbuiltins.spider_test = 'private'", root.string());
        spider::InspectionPool b("import builtins\napi.print(getattr(builtins, 'spider_test', 'clean'))", root.string());
        a.warm(); b.warm();
        assert(a.run(request(), 1000)["ok"] == true);
        assert(a.run(request(), 1000)["ok"] == true);
        for (int i = 0; i < 4; ++i) assert(b.run(request(), 1000)["logs"][0] == "clean");
    }
    {
        const auto source = "import os, time\nmode = api.info.get('mode')\n"
            "if mode == 'timeout':\n    api.storage.namespace('pool').increment('once')\n    time.sleep(1)\n"
            "if mode == 'exit': os._exit(7)\n"
            "if mode == 'protocol': os.write(1, b'not-json\\n')\n"
            "if mode == 'oversize': os.write(1, b'x' * (3 * 1024 * 1024))\n"
            "if mode == 'denied': open('/etc/passwd').read()\n"
            "api.print(api.storage.namespace('pool').get('once', 0))\nreturn api.bytes";
        spider::InspectionPool pool(source, root.string());
        pool.warm();
        for (const auto* mode : {"timeout", "exit", "protocol", "oversize"}) {
            const auto before = pool.status()["restarts"].get<unsigned>();
            const auto result = pool.run(request(mode), std::string(mode) == "timeout" ? 50 : 1000);
            assert(result["ok"] == false && result["replacement"].is_null());
            await([&] { return pool.status()["restarts"].get<unsigned>() > before && pool.status()["idle"] == 2; });
            const auto healthy = pool.run(request(), 1000);
            assert(healthy["ok"] == true && healthy["logs"][0] == "1"); // no automatic replay
        }

        // A sandbox denial is a normal, structured callback error. It must not
        // consume a healthy worker slot or create a transient capacity outage.
        const auto before = pool.status()["restarts"].get<unsigned>();
        const auto denied = pool.run(request("denied"), 1000);
        assert(denied["ok"] == false && denied["replacement"].is_null());
        assert(pool.status()["restarts"] == before);
        assert(pool.status()["idle"] == 2);
        const auto healthy = pool.run(request(), 1000);
        assert(healthy["ok"] == true && healthy["logs"][0] == "1");
    }
    {
        spider::InspectionPool pool("return api.bytes", root.string());
        pool.warm();
        for (int i = 0; i < 520; ++i) assert(pool.run(request(), 1000)["ok"] == true);
        await([&] { return pool.status()["restarts"].get<unsigned>() >= 2 && pool.status()["idle"] == 2; });
        assert(pool.status()["cold_waits"] == 0);
    }
    {
        // Both workers age together under round-robin dispatch. Rolling
        // retirement must never empty the pool during healthy sustained use.
        spider::InspectionPool pool("return api.bytes", root.string());
        pool.warm();
        std::vector<std::thread> producers;
        for (int i = 0; i < 4; ++i) producers.emplace_back([&] {
            for (int n = 0; n < 1000; ++n) {
                const auto result = pool.run(request(), 1000);
                assert(result["ok"] == true && result["replacement"] == "YWJj");
            }
        });
        for (auto& producer : producers) producer.join();
        const auto status = pool.status();
        assert(status["completed"] == 4000);
        assert(status["restarts"].get<unsigned>() >= 2);
        assert(status["cold_waits"] == 0);
        assert(status["forced_recycles"] == 0);
        std::cout << "Rolling pool: " << status.dump() << '\n';
        pool.retire();
        await([&] { return pool.status()["starting"] == 0; });
        assert(pool.status()["idle"] == 0);
    }
    std::filesystem::remove_all(root); // only this test's mkdtemp tree
}
