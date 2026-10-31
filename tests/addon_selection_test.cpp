#include "inspection.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>

using nlohmann::json;

int main() {
    spider::Inspection engine;
    const std::string addon = "raise RuntimeError('validation must not execute source')\n"
                              "def request(flow):\n    pass\n";
    auto validate = [&](const std::string& source, const json& api) {
        return engine.run({{"script", source}, {"script_api", api}, {"validate_only", true}});
    };
    auto result = validate(addon, "mitmproxy");
    if (!result.value("ok", false)) std::cerr << result.dump(2) << '\n';
    assert(result["ok"] == true);
    assert(result["script_api"] == "mitmproxy");
    assert(result["script_api_source"] == "selection");
    assert(result["logs"].empty());
    for (const auto& selected : {json("spider"), json("unknown"), json(nullptr)}) {
        result = validate("\xEF\xBB\xBF#!mitmproxy\r\n" + addon, selected);
        assert(result["ok"] == true);
        assert(result["script_api"] == "mitmproxy");
        assert(result["script_api_source"] == "shebang");
    }
    assert(validate(addon, "unknown")["ok"] == false);
    assert(validate("return None", "mitmproxy")["ok"] == false);
    assert(validate("return None", "spider")["ok"] == true);
    // Preview owns a fresh temporary generation and runs the complete addon
    // lifecycle. The directive wins even without an explicit API selection.
    const std::string preview = "#!mitmproxy\n"
        "from mitmproxy import ctx\n"
        "events = []\n"
        "def load(loader):\n"
        "    events.append('load')\n"
        "    loader.add_option('preview_count', int, 1, 'Preview count')\n"
        "def configure(updated):\n    events.append('configure')\n"
        "def running():\n    events.append('running')\n"
        "def request(flow):\n"
        "    events.append('request')\n"
        "    flow.request.headers['x-preview'] = 'yes'\n"
        "    print(' > '.join(events) + ':' + str(ctx.options.preview_count))\n"
        "def done():\n    print('done')\n";
    const auto preview_event = [](const std::string& identity) {
        json info = {
            {"side", "L"},
            {"content", "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUudGVzdA0KDQo="},
            {"content_annotations", {{0, 16, "http1.start_line"},
                                     {16, 38, "http1.headers"}}},
        };
        return json{{"id", identity}, {"action", "connection-content"},
                    {"details", {{"info", std::move(info)}}}};
    };
    result = engine.run({{"script", preview}, {"script_api", "spider"},
                         {"addon_options", json::array({"preview_count=7"})},
                         {"event", preview_event("preview-one")}});
    if (!result.value("ok", false)) std::cerr << result.dump(2) << '\n';
    assert(result["ok"] == true);
    assert(result["script_api"] == "mitmproxy");
    assert(result["script_api_source"] == "shebang");
    assert(result["logs"] == json::array({"load > configure > running > request:7", "done"}));
    assert(result["replacement"].get<std::string>() ==
        "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUudGVzdA0KeC1wcmV2aWV3OiB5ZXMNCg0K");

    // Preview generations are intentionally isolated: addon globals never
    // carry over to a later press of the Run button.
    result = engine.run({{"script", preview}, {"script_api", "mitmproxy"},
                         {"event", preview_event("preview-two")}});
    assert(result["ok"] == true);
    assert(result["logs"] == json::array({"load > configure > running > request:1", "done"}));

    // Explicit addon selection also supports an isolated H2 translation. This
    // is the real native Translate path, not a facade-only object mutation.
    const std::string h2_preview =
        "def request(flow):\n"
        "    flow.request.path = '/preview'\n";
    auto h2_event = json{{"id", "preview-h2"}, {"action", "connection-content"},
        {"details", {{"info", {
            {"side", "L"},
            {"content", "AAAOAQUAAAABgodBiS+R010FXSVCf4Q="},
            {"content_annotations", {{0, 9, "h2.frame.header"}}},
            {"webhook_control", {{"content-reverse", true}}},
        }}}}};
    result = engine.run({{"script", h2_preview}, {"script_api", "mitmproxy"},
                         {"event", std::move(h2_event)}});
    assert(result["ok"] == true);
    assert(result["translated"] == true);
    assert(result["replacement"] != "AAAOAQUAAAABgodBiS+R010FXSVCf4Q=");
    assert(!result.contains("translate_state"));
    assert(!result.contains("translate_control"));

    auto configure = [&](json request) {
        request["revision"] = engine.status()["revision"];
        return engine.configure(request);
    };
    auto saved = configure({{"operation", "deploy"}, {"name", "Addon"},
                            {"script", addon}, {"script_api", "mitmproxy"}});
    const auto id = saved["chain"][0]["id"];
    assert(saved["chain"][0]["script_api"] == "mitmproxy");
    assert(saved["chain"][0]["enabled"] == false);
    saved = configure({{"operation", "deploy"}, {"id", id},
                       {"name", "Edited addon"}, {"script", addon}});
    assert(saved["chain"][0]["script_api"] == "mitmproxy");
    const auto previous = engine.status();
    bool rejected = false;
    try {
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    } catch (const std::invalid_argument& error) {
        rejected = std::string(error.what()).find("flow instantiation") != std::string::npos;
    }
    assert(rejected);
    assert(engine.status()["revision"] == previous["revision"]);
    assert(engine.status()["chain"] == previous["chain"]);

    saved = configure({{"operation", "deploy"}, {"id", id}, {"name", "Native"},
                       {"script", "return None"}, {"script_api", "spider"}});
    assert(saved["chain"][0]["script_api"] == "spider");
    saved = configure({{"operation", "deploy"}, {"id", id}, {"name", "Directive"},
                       {"script", "#!mitmproxy\n" + addon}, {"script_api", "spider"}});
    assert(saved["chain"][0]["script_api"] == "mitmproxy");
    assert(saved["chain"][0]["script_api_source"] == "shebang");

    // Persist the effective API, not the conflicting UI selection.  The same
    // value must warm the deployed worker and survive a later edit that does
    // not repeat script_api.  BOM and CRLF handling belongs to this complete
    // path as well as to the isolated validator above.
    const std::string directive_source =
        "\xEF\xBB\xBF#!mitmproxy\r\n"
        "def request(flow):\r\n"
        "    flow.request.headers['x-deployed'] = 'yes'\r\n";
    saved = configure({{"operation", "deploy"}, {"id", id}, {"name", "Directive lifecycle"},
                       {"script", directive_source}, {"script_api", "spider"},
                       {"instancing", "flow"}});
    assert(saved["chain"][0]["script_api"] == "mitmproxy");
    assert(saved["chain"][0]["script_api_source"] == "shebang");
    saved = configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    assert(saved["chain"][0]["script_api"] == "mitmproxy");
    assert(saved["chain"][0]["script_api_source"] == "shebang");
    assert(saved["chain"][0]["workers"]["script_api"] == "mitmproxy");
    saved = configure({{"operation", "enable"}, {"id", id}, {"enabled", false}});
    saved = configure({{"operation", "deploy"}, {"id", id}, {"name", "Directive edited"},
                       {"script", directive_source}, {"instancing", "flow"}});
    assert(saved["chain"][0]["script_api"] == "mitmproxy");
    assert(saved["chain"][0]["script_api_source"] == "shebang");

    {
        spider::Inspection configured_addon;
        auto update = [&](json request) {
            request["revision"] = configured_addon.status()["revision"];
            return configured_addon.configure(request);
        };
        const std::string configured_source =
            "#!mitmproxy\n"
            "from mitmproxy import ctx, exceptions\n"
            "def load(loader):\n"
            "    loader.add_option('probe_count', int, 1, 'Probe count')\n"
            "def configure(updated):\n"
            "    if ctx.options.probe_count != 7:\n"
            "        raise exceptions.OptionsError('override was not applied before configure')\n";
        auto option_state = update({{"operation", "deploy"}, {"name", "Configured addon"},
            {"script", configured_source}, {"scope", "all"}, {"instancing", "flow"},
            {"addon_options", json::array({"probe_count=7"})}});
        const auto option_id = option_state["chain"][0]["id"];
        assert(option_state["chain"][0]["addon_options"] ==
               json::array({"probe_count=7"}));
        option_state = update({{"operation", "enable"}, {"id", option_id}, {"enabled", true}});
        assert(option_state["chain"][0]["enabled"] == true);

        const auto before_invalid = configured_addon.status();
        bool invalid_value_rejected = false;
        try {
            update({{"operation", "deploy"}, {"id", option_id}, {"name", "Invalid option"},
                {"script", configured_source}, {"scope", "all"}, {"instancing", "flow"},
                {"addon_options", json::array({"probe_count=not-an-int"})}});
        } catch (const std::runtime_error&) {
            invalid_value_rejected = true;
        }
        assert(invalid_value_rejected);
        assert(configured_addon.status()["revision"] == before_invalid["revision"]);
        assert(configured_addon.status()["chain"] == before_invalid["chain"]);
    }

    {
        spider::Inspection content_views;
        auto update = [&](json request) {
            request["revision"] = content_views.status()["revision"];
            return content_views.configure(request);
        };
        const std::string view_addon =
            "#!mitmproxy\n"
            "from mitmproxy import contentviews\n"
            "class Counter(contentviews.InteractiveContentview):\n"
            "    syntax_highlight = 'yaml'\n"
            "    calls = 0\n"
            "    def prettify(self, data, metadata):\n"
            "        self.calls += 1\n"
            "        if data == b'bad':\n"
            "            raise ValueError('bad view input')\n"
            "        return data.decode() + ':' + str(self.calls)\n"
            "    def render_priority(self, data, metadata):\n"
            "        return 10 if metadata.content_type == 'text/probe' else -1\n"
            "    def reencode(self, text, metadata):\n"
            "        return text.lower().encode()\n"
            "contentviews.add(Counter)\n";
        auto view_state = update({{"operation", "deploy"}, {"name", "Content view"},
            {"script", view_addon}, {"scope", "all"}, {"instancing", "flow"}});
        const auto view_id = view_state["chain"][0]["id"];
        update({{"operation", "enable"}, {"id", view_id}, {"enabled", true}});

        const auto listed = content_views.content_view({
            {"action", "list"}, {"_shutdown", true},
        });
        assert(listed["ok"] == true);
        assert(listed["deployment_id"] == view_id);
        assert(listed["views"] == json::array({{
            {"key", "counter"}, {"name", "Counter"},
            {"syntax_highlight", "yaml"}, {"interactive", true},
        }}));

        const auto rendered = content_views.content_view({
            {"action", "render"}, {"data", "aGk="},
            {"content_type", "text/probe"}, {"view_name", "auto"},
        });
        assert(rendered["ok"] == true);
        assert(rendered["text"] == "hi:1");
        assert(rendered["syntax_highlight"] == "yaml");
        assert(rendered["interactive"] == true);

        const auto failed = content_views.content_view({
            {"action", "render"}, {"data", "YmFk"},
            {"content_type", "text/probe"}, {"view_name", "Counter"},
        });
        assert(failed["ok"] == false);
        assert(failed["error"].get<std::string>().find("bad view input") != std::string::npos);

        const auto after_failure = content_views.content_view({
            {"action", "render"}, {"data", "aGk="},
            {"content_type", "text/probe"}, {"view_name", "counter"},
        });
        assert(after_failure["ok"] == true);
        assert(after_failure["text"] == "hi:3");

        const auto reencoded = content_views.content_view({
            {"action", "reencode"}, {"data", "b3JpZ2luYWw="},
            {"content_type", "text/probe"}, {"view_name", "Counter"},
            {"text", "EDITED"},
        });
        assert(reencoded["ok"] == true);
        assert(reencoded["data"] == "ZWRpdGVk");
    }
}
