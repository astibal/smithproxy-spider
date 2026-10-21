#include "inspection.hpp"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <thread>
#include <unistd.h>
using nlohmann::json;

int main() {
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
    deploy("message", counter);
    assert(run()["logs"][0] == "1" && run()["logs"][0] == "1");
    assert(engine.status()["chain"][0]["instances"] == 0);
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
    std::filesystem::remove_all(root);
}
