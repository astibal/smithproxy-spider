#include "collection.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <unistd.h>
using nlohmann::json;
int main() {
    char temporary[] = "/tmp/spider-library-XXXXXX";
    assert(mkdtemp(temporary));
    const std::filesystem::path root(temporary);
    spider::Collection collection(root);
    const json event = {{"action", "connection-content"}, {"id", "test"}, {"collections", {{{"endpoint", "example.test"}}}},
        {"details", {{"info", {{"content", "YWJj"}, {"side", "L"}, {"session", "tcp_127.0.0.1:123+tcp_127.0.0.2:443"}}}}}};
    collection.capture(event, json::array(), json::object());
    auto listing = collection.library();
    assert(listing["total"] == 1);
    const auto sample = listing["items"][0];
    std::ifstream before(root / sample["id"].get<std::string>());
    const std::string original((std::istreambuf_iterator<char>(before)), {});
    auto update = collection.edit_library({{"revision", 0}, {"operation", "folder"}, {"name", "HTTP tests"}});
    const auto folder = update["folders"][0]["id"];
    update = collection.edit_library({{"revision", update["revision"]}, {"operation", "item"}, {"key", sample["key"]},
        {"name", "Login response"}, {"folder", folder}, {"notes", "needle compression regression"}});
    assert(collection.library(0, "needle", folder)["total"] == 1);
    assert(collection.library(0, "", "")["total"] == 0);
    assert(collection.library(100)["items"].empty());
    bool stale = false;
    try { collection.edit_library({{"revision", 0}, {"operation", "folder"}, {"name", "stale"}}); } catch (...) { stale = true; }
    assert(stale);
    auto saved = collection.save_flow({{"name", "Root flow"}, {"scope", {{"type", "connection"}, {"label", "example.test"}}},
        {"library", {{"folder", folder}, {"notes", "saved note"}}}, {"records", {{{"event", event}}}}});
    assert(collection.library()["total"] == 2);
    update = collection.edit_library({{"revision", update["revision"]}, {"operation", "item"},
        {"key", "flow:" + saved["id"].get<std::string>()}, {"name", "Renamed flow"}, {"notes", "changed"}, {"folder", ""}});
    assert(collection.read_flow(saved["id"])["name"] == "Renamed flow");
    spider::Collection restarted(root);
    const auto index_time = std::filesystem::last_write_time(root / ".capture-index");
    const auto restored = restarted.library(0, "needle");
    assert(std::filesystem::last_write_time(root / ".capture-index") == index_time);
    assert(restored["total"] == 1 && restored["items"][0]["name"] == "Login response");
    assert(restarted.read(sample["id"])["library"]["notes"] == "needle compression regression");
    assert(restarted.read_flow(saved["id"])["name"] == "Renamed flow");
    std::ifstream after(root / sample["id"].get<std::string>());
    assert(std::string((std::istreambuf_iterator<char>(after)), {}) == original);
    bool invalid = false;
    try { restarted.edit_library({{"revision", update["revision"]}, {"operation", "item"}, {"key", "sample:../../etc/passwd"}, {"name", "oops"}}); } catch (...) { invalid = true; }
    assert(invalid);
    update = restarted.edit_library({{"revision", update["revision"]}, {"operation", "folder"}, {"id", folder}, {"name", "HTTP regressions"}});
    assert(restarted.library()["folders"][0]["name"] == "HTTP regressions");
    assert(restarted.library(0, "needle", folder)["total"] == 1);
    std::filesystem::remove_all(root);
}
