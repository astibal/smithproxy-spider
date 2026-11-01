#include "inspection.hpp"
#include "inspection_pool.hpp"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using nlohmann::json;
using Clock = std::chrono::steady_clock;

int main() {
    char directory[] = "/tmp/spider-lifecycle-XXXXXX";
    assert(mkdtemp(directory));
    const std::filesystem::path root(directory);
    const json event = {{"action", "connection-content"}, {"id", "test"},
                        {"details", {{"info", {{"content", "aGVsbG8="}}}}}};
    const std::string script = R"PY(
import time

def init(api, state):
    assert state is None
    print('init')
    return {'calls': 0}

def main(api, state):
    state['calls'] += 1
    deadline = time.process_time() + 0.0006
    while time.process_time() < deadline:
        pass
    print(state['calls'], api.network_enabled)

def exit(api, state):
    print('exit', state['calls'])
)PY";

    // Native lifecycle discovery pins one generation even with default pool
    // settings. Crossing legacy rotation thresholds must not call init again.
    {
        spider::InspectionPool pool(script, root.string());
        pool.warm();
        assert(pool.status()["capacity"] == 1);
        assert(pool.status()["lifetime"] == "generation");
        for (unsigned index = 1; index <= 4100; ++index) {
            const auto result = pool.run({{"event", event}}, 1000);
            assert(result["ok"] == true);
            auto logs = json::array({std::to_string(index) + " False"});
            if (index == 1) logs.insert(logs.begin(), "init");
            assert(result["logs"] == logs);
        }
        pool.retire();
        pool.retire();
        assert(pool.status()["starts"] == 1);
        assert(pool.status()["rotations"] == 0);
        assert(pool.status()["shutdown"]["logs"] == json::array({"exit 4100"}));
    }

    // A partial callback cannot silently restart an empty state object.
    {
        spider::InspectionPool pool("def main(api, state): raise ValueError('failed')", root.string());
        pool.warm();
        assert(pool.run({{"event", event}}, 1000)["worker_state_lost"] == true);
        assert(pool.run({{"event", event}}, 1000)["error_kind"] == "worker_state_lost");
        assert(pool.status()["starts"] == 1);
    }
    for (const auto* body : {"while True: pass", "import time; time.sleep(10)"}) {
        spider::InspectionPool pool(std::string("def main(api, state): pass\ndef exit(api, state):\n    ") + body,
                                    root.string());
        pool.warm();
        const auto started = Clock::now();
        pool.retire();
        assert(Clock::now() - started < std::chrono::seconds(2));
        assert(pool.status()["shutdown"]["ok"] == false);
    }

    // Deployment grants survive edits and disable/enable. Redeploy starts a fresh
    // state and changing the capability creates a new sandbox, never relaxes one.
    {
        spider::Inspection engine(root / "collection");
        auto configure = [&](json request) {
            request["revision"] = engine.status()["revision"];
            return engine.configure(request);
        };
        auto state = configure({{"operation", "deploy"}, {"name", "Lifecycle"},
            {"script", script}, {"scope", "all"}, {"network_enabled", true}});
        const auto id = state["chain"][0]["id"];
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
        auto result = engine.automatic(event, json::array());
        assert(result["ok"] == true);
        assert(result["logs"] == json::array({"init", "1 True"}));
        configure({{"operation", "deploy"}, {"id", id}, {"name", "Lifecycle"},
            {"script", script}, {"scope", "all"}});
        assert(engine.status()["chain"][0]["network_enabled"] == true);
        assert(engine.automatic(event, json::array())["logs"] == json::array({"init", "1 True"}));
        configure({{"operation", "deploy"}, {"id", id}, {"name", "Lifecycle"},
            {"script", script}, {"scope", "all"}, {"network_enabled", false}});
        assert(engine.automatic(event, json::array())["logs"] == json::array({"init", "1 False"}));
        configure({{"operation", "enable"}, {"id", id}, {"enabled", false}});
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
        assert(engine.automatic(event, json::array())["logs"] == json::array({"init", "1 False"}));

        // A failed initializer cannot replace an already serving deployment.
        const auto revision = engine.status()["revision"];
        bool rejected = false;
        try {
            configure({{"operation", "deploy"}, {"id", id}, {"name", "Broken"},
                {"script", "def init(api, state): raise ValueError('init failed')\ndef main(api, state): pass"},
                {"scope", "all"}});
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        assert(rejected);
        assert(engine.status()["revision"] == revision);
        assert(engine.automatic(event, json::array())["logs"] == json::array({"2 False"}));
    }
    std::filesystem::remove_all(root);
    std::cout << "native lifecycle host checks passed\n";
}
