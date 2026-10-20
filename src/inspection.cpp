#include "inspection.hpp"
#include "inspection_worker.hpp"
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
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
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
    if (timeout) return failure("Python exceeded the 3 s wall-clock limit");
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
    const auto source = request.at("script").get<std::string>();
    const auto scope = request.value("scope", "rules");
    const auto enabled = request.value("enabled", false);
    if (source.size() > 65536 || (scope != "rules" && scope != "all")) throw std::invalid_argument("invalid script size or scope");
    { std::scoped_lock lock(mutex_); source_ = source; scope_ = scope; enabled_ = enabled; ++revision_; }
    return status();
}
nlohmann::json Inspection::status() const {
    std::scoped_lock lock(mutex_);
    return {{"script", source_}, {"scope", scope_}, {"enabled", enabled_}, {"revision", revision_},
            {"runs", runs_}, {"errors", errors_}, {"running", running_.load()}, {"recent", recent_}};
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
    if (!result.value("ok", false)) ++errors_;
    auto summary = result;
    summary.erase("replacement");
    recent_.push_back(std::move(summary));
    if (recent_.size() > 20) recent_.erase(recent_.begin());
    return result;
}
nlohmann::json Inspection::automatic(const nlohmann::json& event, const nlohmann::json& enrichments) {
    std::string script;
    { std::scoped_lock lock(mutex_);
      if (!enabled_ || event.value("action", "") != "connection-content") return nullptr;
      const auto state = event.value("decision", nlohmann::json::object()).value("state", "");
      if (state == "passed" || state == "forgotten" || state == "auto-accepted") return nullptr;
      if (scope_ == "rules" && event.value("traffic_rule", nlohmann::json::object()).value("mode", "") != "inspect") return nullptr;
      script = source_;
    }
    return run({{"script", script}, {"event", event}, {"enrichments", enrichments}});
}
}
