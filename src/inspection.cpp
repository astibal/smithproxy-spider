#include "inspection.hpp"
#include "inspection_worker.hpp"
#include "session_filter.hpp"
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace spider {
namespace {
struct File {
    int fd{-1};
    File() { char path[] = "/tmp/spider-inspection-XXXXXX"; fd = mkstemp(path); if (fd >= 0) { unlink(path); fcntl(fd, F_SETFD, FD_CLOEXEC); } }
    ~File() { if (fd >= 0) close(fd); }
};
nlohmann::json failure(const std::string& error) {
    return {{"ok", false}, {"error", error}, {"logs", nlohmann::json::array()}, {"replacement", nullptr}};
}
nlohmann::json execute(const nlohmann::json& request) {
    File input, output;
    if (input.fd < 0 || output.fd < 0) return failure("cannot create worker files");
    const auto body = request.dump();
    std::size_t offset = 0;
    while (offset < body.size()) {
        const auto n = write(input.fd, body.data() + offset, body.size() - offset);
        if (n <= 0) return failure("cannot write worker input");
        offset += static_cast<std::size_t>(n);
    }
    lseek(input.fd, 0, SEEK_SET);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, input.fd, STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, output.fd, STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclosefrom_np(&actions, 3);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0);
    char* argv[] = {const_cast<char*>(SPIDER_PYTHON), const_cast<char*>("-I"), const_cast<char*>("-c"),
                    const_cast<char*>(inspection_worker_source), nullptr};
    char path[] = "PATH=/usr/bin:/bin";
    char* env[] = {path, nullptr};
    pid_t pid{};
    const int spawned = posix_spawn(&pid, SPIDER_PYTHON, &actions, &attributes, argv, env);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    if (spawned != 0) return failure("cannot start backend Python");
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(std::clamp(request.value("timeout_ms", 3000), 1, 3000));
    int status = 0;
    bool timeout = false;
    for (;;) {
        const auto waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) { kill(-pid, SIGKILL); return failure("cannot wait for Python worker"); }
        if (std::chrono::steady_clock::now() >= deadline) { timeout = true; kill(-pid, SIGKILL); waitpid(pid, &status, 0); break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    kill(-pid, SIGKILL); // Terminate descendants on normal completion as well.
    if (timeout) return failure("Python exceeded the execution wall-clock budget (at most 3 s)");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return failure("Python worker exited or exceeded a resource limit");
    struct stat info{};
    if (fstat(output.fd, &info) != 0 || info.st_size > 2 * 1024 * 1024) return failure("worker output too large");
    lseek(output.fd, 0, SEEK_SET);
    std::string result;
    char buffer[8192];
    for (ssize_t n; (n = read(output.fd, buffer, sizeof(buffer))) > 0;) result.append(buffer, static_cast<std::size_t>(n));
    auto parsed = nlohmann::json::parse(result, nullptr, false);
    if (!parsed.is_object() || !parsed.contains("ok") || !parsed["ok"].is_boolean()) return failure("invalid worker response");
    return parsed;
}
}
nlohmann::json Inspection::configure(const nlohmann::json& request) {
    if (request.contains("operation")) {
        // Serialize control-plane changes, including validation, against other editors.
        std::unique_lock lock(mutex_);
        if (request.at("revision").get<std::uint64_t>() != revision_)
            throw std::invalid_argument("Backend changed; refresh before editing the chain");
        const auto operation = request.at("operation").get<std::string>();
        auto next = chain_;
        if (!chain_mode_ && next.empty() && !source_.empty()) {
            next.push_back({{"id", "legacy"}, {"name", "Previously deployed script"},
                {"script", source_}, {"scope", scope_}, {"filter", ""}, {"enabled", enabled_},
                {"version", 1}, {"runs", 0}, {"errors", 0}, {"last_run_ms", nullptr}});
        }
        const auto id = request.value("id", "");
        auto item = std::find_if(next.begin(), next.end(), [&](const auto& entry) { return entry["id"] == id; });
        if (operation == "deploy") {
            const auto source = request.at("script").get<std::string>();
            const auto name = request.at("name").get<std::string>();
            const auto scope = request.value("scope", "rules");
            const auto filter = request.value("filter", "");
            if (source.size() > 65536 || name.empty() || name.size() > 200 ||
                (scope != "all" && scope != "rules")) throw std::invalid_argument("Invalid source, name or scope");
            std::string error;
            if (!filter.empty() && !SessionFilter::compile(filter, error)) throw std::invalid_argument(error);
            auto validation = execute({{"script", source}, {"validate_only", true}});
            if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
            if (!id.empty() && item == next.end()) throw std::invalid_argument("Unknown deployment");
            if (item == next.end()) {
                if (next.size() >= 16) throw std::invalid_argument("Maximum 16 deployed scripts");
                next.push_back({{"id", "script-" + std::to_string(++next_script_id_)},
                    {"name", name}, {"script", source}, {"scope", scope}, {"filter", filter},
                    {"enabled", false}, {"version", 1}, {"runs", 0}, {"errors", 0}, {"last_run_ms", nullptr}});
            } else {
                (*item)["name"] = name; (*item)["script"] = source;
                (*item)["scope"] = scope; (*item)["filter"] = filter;
                (*item)["version"] = item->value("version", 0) + 1;
            }
        } else if (operation == "reorder") {
            const auto ids = request.at("ids").get<std::vector<std::string>>();
            if (ids.size() != next.size()) throw std::invalid_argument("Incomplete order");
            auto ordered = nlohmann::json::array();
            for (const auto& key : ids) {
                auto entry = std::find_if(next.begin(), next.end(), [&](const auto& v) { return v["id"] == key; });
                if (entry == next.end()) throw std::invalid_argument("Unknown or duplicate deployment");
                ordered.push_back(*entry); next.erase(entry);
            }
            next = std::move(ordered);
        } else {
            if (item == next.end()) throw std::invalid_argument("Unknown deployment");
            if (operation == "remove") next.erase(item);
            else if (operation == "enable") {
                const auto enabled = request.at("enabled").get<bool>();
                if (enabled) {
                    auto validation = execute({{"script", (*item)["script"]}, {"validate_only", true}});
                    if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
                }
                (*item)["enabled"] = enabled;
            } else throw std::invalid_argument("Unknown operation");
        }
        chain_ = std::move(next); chain_mode_ = true; ++revision_;
        lock.unlock();
        return status();
    }
    const auto source = request.at("script").get<std::string>();
    const auto scope = request.value("scope", "rules");
    const auto enabled = request.value("enabled", false);
    if (source.size() > 65536 || (scope != "rules" && scope != "all")) throw std::invalid_argument("invalid script size or scope");
    if (enabled) {
        auto validation = execute({{"script", source}, {"validate_only", true}});
        if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
    }
    { std::scoped_lock lock(mutex_);
      if (chain_mode_) throw std::invalid_argument("Use chain operations for multiple scripts");
      source_ = source; scope_ = scope; enabled_ = enabled; ++revision_; }
    return status();
}
nlohmann::json Inspection::status() const {
    std::scoped_lock lock(mutex_);
    return {{"script", chain_mode_ ? "" : source_}, {"scope", chain_mode_ ? "chain" : scope_},
            {"enabled", chain_mode_ ? std::any_of(chain_.begin(), chain_.end(),
                [](const auto& item) { return item.value("enabled", false); }) : enabled_}, {"revision", revision_},
            {"runs", runs_}, {"errors", errors_}, {"running", running_.load()}, {"recent", recent_},
            {"chain", chain_}, {"collection", collection.status()}};
}
nlohmann::json Inspection::run(nlohmann::json request) {
    if (!request.contains("script") || !request["script"].is_string() || request["script"].get_ref<const std::string&>().size() > 65536)
        return failure("script must be a string up to 64 KiB");
    if (running_.fetch_add(1) >= 4) { --running_; return failure("backend inspection busy (4 workers)"); }
    nlohmann::json result;
    try { result = execute(request); } catch (const std::exception& e) { result = failure(e.what()); }
    --running_;
    std::scoped_lock lock(mutex_);
    result["run_id"] = ++runs_;
    result["session_id"] = request.value("event", nlohmann::json::object()).value("id", "");
    if (request.contains("script_id")) result["script_id"] = request["script_id"];
    if (!result.value("ok", false)) ++errors_;
    auto summary = result;
    summary.erase("replacement");
    recent_.push_back(std::move(summary));
    if (recent_.size() > 20) recent_.erase(recent_.begin());
    return result;
}
nlohmann::json Inspection::automatic(const nlohmann::json& event, const nlohmann::json& enrichments) {
    std::string script;
    nlohmann::json chain;
    { std::scoped_lock lock(mutex_);
      if (event.value("action", "") != "connection-content") return nullptr;
      const auto state = event.value("decision", nlohmann::json::object()).value("state", "");
      if (state == "passed" || state == "forgotten" || state == "auto-accepted") return nullptr;
      chain = chain_;
      if (chain_mode_ && chain.empty()) return nullptr;
      if (chain.empty() && !enabled_) return nullptr;
      if (chain.empty() && scope_ == "rules" && event.value("traffic_rule", nlohmann::json::object()).value("mode", "") != "inspect") return nullptr;
      script = source_;
    }
    if (!chain.empty()) {
        auto current = event;
        auto annotations = enrichments;
        nlohmann::json result = nullptr;
        auto steps = nlohmann::json::array();
        nlohmann::json replacement = nullptr;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        for (const auto& item : chain) {
            if (!item.value("enabled", false)) continue;
            if (item.value("scope", "rules") == "rules" &&
                event.value("traffic_rule", nlohmann::json::object()).value("mode", "") != "inspect") continue;
            std::string error;
            const auto filter = item.value("filter", "");
            if (!filter.empty()) {
                auto compiled = SessionFilter::compile(filter, error);
                if (!compiled || !compiled->matches(event)) continue;
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            result = remaining <= 0 ? failure("Inspection chain exceeded its 3 s budget") :
                run({{"script", item["script"]}, {"event", current}, {"enrichments", annotations},
                     {"script_id", item["id"]}, {"timeout_ms", remaining}});
            {
                std::scoped_lock lock(mutex_);
                for (auto& live : chain_) if (live["id"] == item["id"] && live["version"] == item["version"]) {
                    live["runs"] = live.value("runs", 0ULL) + 1;
                    live["errors"] = live.value("errors", 0ULL) + (result.value("ok", false) ? 0 : 1);
                    live["last_run_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    live["last_result"] = result;
                    live["last_result"].erase("replacement");
                }
            }
            auto step = result; step.erase("replacement");
            step["script_id"] = item["id"]; step["version"] = item["version"];
            steps.push_back(step);
            // Fail open with the ORIGINAL payload, never a partially applied chain.
            if (!result.value("ok", false)) { result["replacement"] = nullptr; result["steps"] = steps; return result; }
            if (!result["replacement"].is_null()) {
                replacement = result["replacement"];
                current["details"]["info"]["content"] = replacement;
                // Original byte offsets and parsed headers are not valid after rewriting.
                auto& info = current["details"]["info"];
                const auto encoded = replacement.get<std::string>();
                info["payload_length"] = encoded.size() / 4 * 3 -
                    (encoded.ends_with("==") ? 2 : encoded.ends_with("=") ? 1 : 0);
                for (const auto* key : {"L7_payload_start", "L7_payload_end", "L7_encoding", "content_annotations"}) info.erase(key);
                annotations = nlohmann::json::array();
            }
        }
        if (!result.is_null()) { result["replacement"] = replacement; result["steps"] = steps; }
        return result;
    }
    return run({{"script", script}, {"event", event}, {"enrichments", enrichments}});
}
}
