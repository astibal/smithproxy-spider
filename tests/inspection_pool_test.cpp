#include "inspection_pool.hpp"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <set>
#include <thread>
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
        for (const auto* mode : {"timeout", "exit", "protocol", "oversize", "denied"}) {
            const auto before = pool.status()["restarts"].get<unsigned>();
            const auto result = pool.run(request(mode), std::string(mode) == "timeout" ? 50 : 1000);
            assert(result["ok"] == false && result["replacement"].is_null());
            await([&] { return pool.status()["restarts"].get<unsigned>() > before && pool.status()["idle"] == 2; });
            const auto healthy = pool.run(request(), 1000);
            assert(healthy["ok"] == true && healthy["logs"][0] == "1"); // no automatic replay
        }
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
