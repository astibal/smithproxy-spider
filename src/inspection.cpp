#include "inspection.hpp"
#include "inspection_worker.hpp"
#include "inspection_pool.hpp"
#include "session_filter.hpp"
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <cstdlib>
#include <vector>
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
nlohmann::json capacity_failure(const std::string& error) {
    auto result = failure(error); result["error_kind"] = "capacity"; return result;
}
bool valid_connection_close(const nlohmann::json& result,
                            const nlohmann::json& event,
                            const std::string& mode) {
    const auto marker = result.find("connection_close");
    if (marker == result.end()) return true;
    if (mode != "flow" || event.value("action", "") != "connection-content" ||
        !marker->is_object() || marker->size() != 1 ||
        !marker->contains("reason") || !(*marker)["reason"].is_string()) {
        return false;
    }

    const auto& reason = (*marker)["reason"].get_ref<const std::string&>();
    if (reason.empty() || reason.size() > 1024 ||
        std::any_of(reason.begin(), reason.end(), [](unsigned char byte) {
            return byte < 0x20 || byte == 0x7f;
        })) {
        return false;
    }

    const auto control = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object())
        .value("webhook_control", nlohmann::json::object());
    const auto capability = control.find("connection-close");
    if (capability == control.end() || !capability->is_boolean() ||
        !capability->get<bool>()) {
        return false;
    }

    const auto checkpoint = result.find("h1_response_state");
    const bool empty_checkpoint = checkpoint != result.end() &&
        checkpoint->is_object() && checkpoint->value("version", 0) == 1 &&
        checkpoint->value("slots", nlohmann::json::array()) ==
            nlohmann::json::array();
    const bool empty_forward = result.contains("replacement") &&
        result["replacement"].is_string() &&
        result["replacement"].get_ref<const std::string&>().empty();
    const bool no_hold = !result.contains("held_parts") ||
        result["held_parts"].is_null();
    return empty_checkpoint && empty_forward && no_hold &&
        !result.contains("replacement_reverse") &&
        !result.value("translated", false) &&
        !result.value("need_more", false);
}
nlohmann::json validated_addon_options(const nlohmann::json& value) {
    if (!value.is_array() || value.size() > 128) {
        throw std::invalid_argument("Addon options must be an array of at most 128 entries");
    }
    std::size_t total = 0;
    for (const auto& entry : value) {
        if (!entry.is_string()) {
            throw std::invalid_argument("Addon option entries must be text");
        }
        const auto& text = entry.get_ref<const std::string&>();
        total += text.size();
        if (text.empty() || text.size() > 4096 || text.find('\0') != std::string::npos ||
            text.find('\r') != std::string::npos || text.find('\n') != std::string::npos) {
            throw std::invalid_argument("Addon option entries must be bounded single-line text");
        }
    }
    if (total > 65536) {
        throw std::invalid_argument("Addon options exceed 64 KiB");
    }
    return value;
}
nlohmann::json execute(const nlohmann::json& request) {
    File input, output;
    if (input.fd < 0 || output.fd < 0) return capacity_failure("cannot create worker files");
    const auto body = request.dump();
    std::size_t offset = 0;
    while (offset < body.size()) {
        const auto n = write(input.fd, body.data() + offset, body.size() - offset);
        if (n <= 0) return capacity_failure("cannot write worker input");
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
    std::vector<char*> argv = {
        const_cast<char*>(SPIDER_PYTHON),
        const_cast<char*>("-I"),
        const_cast<char*>("-c"),
        const_cast<char*>(inspection_worker_loader),
    };
    for (const auto* argument : inspection_worker_data_arguments) {
        argv.push_back(const_cast<char*>(argument));
    }
    argv.push_back(nullptr);
    char path[] = "PATH=/usr/bin:/bin";
    char* env[] = {path, nullptr};
    pid_t pid{};
    const int spawned = posix_spawn(&pid, SPIDER_PYTHON, &actions, &attributes,
                                    argv.data(), env);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    if (spawned != 0) return capacity_failure("cannot start backend Python");
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(std::clamp(request.value("timeout_ms", 3000), 1, 3000));
    int status = 0;
    bool timeout = false;
    for (;;) {
        const auto waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) { kill(-pid, SIGKILL); return capacity_failure("cannot wait for Python worker"); }
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
Inspection::Inspection(std::filesystem::path collection_root) : collection(std::move(collection_root)) {
    next_notification_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() * 1000ULL;
    const auto root = std::filesystem::path(collection.status().at("directory").get<std::string>());
    const char* configured = std::getenv("SPIDER_STORAGE_DIR");
    storage_root_ = configured ? std::filesystem::path(configured) :
        root.parent_path() / (root.filename().string() + "-inspection-storage");
    storage_root_ = std::filesystem::absolute(storage_root_);
}
nlohmann::json Inspection::configure(const nlohmann::json& request) {
    if (request.contains("operation")) {
        std::vector<std::pair<std::string, std::shared_ptr<InspectionPool>>> retiring_pools;
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
            const auto instancing = request.value("instancing", "message");
            const auto endpoint = request.value("endpoint", "destination");
            for (const auto* field : {"timeout_ms", "error_limit", "max_instances", "idle_seconds"}) {
                if (request.contains(field) && (!request[field].is_number_integer() ||
                    request[field] < 0 || request[field] > 86400))
                    throw std::invalid_argument("Runtime limits must be bounded integers");
            }
            const auto timeout = request.value("timeout_ms", 1000);
            const auto error_limit = request.value("error_limit", 3);
            const auto max_instances = request.value("max_instances", 128);
            const auto idle_seconds = request.value("idle_seconds", 1800);

            if (request.contains("network_enabled") && !request["network_enabled"].is_boolean()) {
                throw std::invalid_argument("network_enabled must be a boolean");
            }

            const bool network_enabled = request.value("network_enabled",
                item != next.end() && item->value("network_enabled", false));
            auto addon_options = item == next.end()
                ? nlohmann::json::array()
                : item->value("addon_options", nlohmann::json::array());
            if (request.contains("addon_options")) {
                addon_options = validated_addon_options(request["addon_options"]);
            }
            if ((instancing != "message" && instancing != "flow" && instancing != "endpoint") ||
                (endpoint != "source" && endpoint != "destination") || timeout < 50 || timeout > 3000 ||
                error_limit < 1 || error_limit > 100 || max_instances < 1 || max_instances > 1024 ||
                idle_seconds < 1 || idle_seconds > 86400)
                throw std::invalid_argument("Invalid instance mode or runtime limits");
            if (source.size() > 65536 || name.empty() || name.size() > 200 ||
                (scope != "all" && scope != "rules")) throw std::invalid_argument("Invalid source, name or scope");
            std::string error;
            if (!filter.empty() && !SessionFilter::compile(filter, error)) throw std::invalid_argument(error);
            auto validation_request = nlohmann::json{{"script", source}, {"validate_only", true}};
            if (request.contains("script_api")) {
                validation_request["script_api"] = request["script_api"];
            } else if (item != next.end() && item->value("script_api", "spider") != "spider") {
                validation_request["script_api"] = (*item)["script_api"];
            }
            auto validation = execute(validation_request);
            if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
            if (!id.empty() && item == next.end()) throw std::invalid_argument("Unknown deployment");
            const auto script_api = validation.value("script_api", "spider");
            if (script_api != "mitmproxy" && !addon_options.empty()) {
                throw std::invalid_argument("Addon options require the mitmproxy script API");
            }
            if (item == next.end()) {
                if (next.size() >= 16) throw std::invalid_argument("Maximum 16 deployed scripts");
                next.push_back({{"id", "script-" + std::to_string(++next_script_id_)},
                    {"name", name}, {"script", source}, {"scope", scope}, {"filter", filter},
                    {"enabled", false}, {"version", 1}, {"runs", 0}, {"errors", 0}, {"last_run_ms", nullptr}});
                item = std::prev(next.end());
            } else {
                (*item)["name"] = name; (*item)["script"] = source;
                (*item)["scope"] = scope; (*item)["filter"] = filter;
                (*item)["version"] = item->value("version", 0) + 1;
            }
            (*item)["instancing"] = instancing; (*item)["endpoint"] = endpoint;
            (*item)["script_api"] = script_api;
            (*item)["script_api_source"] = validation.value("script_api_source", "selection");
            (*item)["addon_options"] = std::move(addon_options);
            (*item)["network_enabled"] = network_enabled;
            (*item)["timeout_ms"] = timeout; (*item)["error_limit"] = error_limit;
            (*item)["max_instances"] = max_instances; (*item)["idle_seconds"] = idle_seconds;
            (*item)["suspended"] = false; (*item)["suspension_reason"] = "";
            (*item)["consecutive_errors"] = 0; (*item)["consecutive_slow"] = 0;
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
                    auto validation_request = nlohmann::json{{"script", (*item)["script"]}, {"validate_only", true}};
                    if (item->value("script_api", "spider") != "spider") {
                        validation_request["script_api"] = (*item)["script_api"];
                    }
                    auto validation = execute(validation_request);
                    if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
                    (*item)["script_api"] = validation.value("script_api", "spider");
                    (*item)["script_api_source"] = validation.value("script_api_source", "selection");
                }
                (*item)["enabled"] = enabled;
                (*item)["suspended"] = false; (*item)["suspension_reason"] = "";
                (*item)["consecutive_errors"] = 0; (*item)["consecutive_slow"] = 0;
            } else throw std::invalid_argument("Unknown operation");
        }
        const auto enabled_count = std::count_if(next.begin(), next.end(),
            [](const auto& entry) { return entry.value("enabled", false); });
        for (const auto& entry : next) {
            if (!entry.value("enabled", false) || entry.value("script_api", "spider") != "mitmproxy") {
                continue;
            }
            if (entry.value("instancing", "message") != "flow") {
                throw std::invalid_argument("Addon execution requires flow instantiation");
            }
            if (enabled_count != 1) {
                throw std::invalid_argument("Addon Translate requires exactly one enabled deployment");
            }
        }
        // Prepare the worker pool before changing the live generation. A failed
        // warm-up leaves the previous deployment untouched.
        std::shared_ptr<Runtime> prepared;
        std::string prepared_id;
        if (operation == "deploy" || operation == "enable") {
            const auto target = operation == "deploy" ? item : std::find_if(next.begin(), next.end(),
                [&](const auto& entry) { return entry["id"] == id; });
            if (target != next.end() && target->value("enabled", false)) {
                prepared_id = (*target)["id"].get<std::string>();
                prepared = std::make_shared<Runtime>();
                prepared->pool = std::make_shared<InspectionPool>(
                    (*target)["script"].get<std::string>(), storage_root_.string(),
                    InspectionPool::Lifetime::Rotating,
                    target->value("script_api", "spider"),
                    target->value("addon_options", nlohmann::json::array()),
                    target->value("network_enabled", false));
                prepared->pool->warm();
                prepared->addon = prepared->pool->status().value("script_api", "spider") == "mitmproxy";
            }
        }
        // Retire old runtime generations. In-flight work cannot publish state into a new version.
        for (const auto& old : chain_) {
            const auto key = old["id"].get<std::string>();
            const auto live = std::find_if(next.begin(), next.end(), [&](const auto& entry) { return entry["id"] == key; });
            if (live == next.end() || (*live)["version"] != old["version"] ||
                (operation == "enable" && key == id)) {
                if (runtimes_.contains(key)) {
                    runtimes_[key]->retired = true;
                    if (runtimes_[key]->pool) retiring_pools.emplace_back(key, runtimes_[key]->pool);
                }
                runtimes_.erase(key);
            }
        }
        if (prepared) runtimes_[prepared_id] = std::move(prepared);
        if (legacy_pool_) retiring_pools.emplace_back("", std::move(legacy_pool_));
        chain_ = std::move(next); chain_mode_ = true; ++revision_;
        lock.unlock();
        // User cleanup hooks must never run under the configuration mutex.
        for (const auto& [id, pool] : retiring_pools) {
            pool->retire();
            record_shutdown(id, pool);
        }
        return status();
    }
    const auto source = request.at("script").get<std::string>();
    const auto scope = request.value("scope", "rules");
    const auto enabled = request.value("enabled", false);
    if (source.size() > 65536 || (scope != "rules" && scope != "all")) throw std::invalid_argument("invalid script size or scope");
    if (enabled || request.contains("script_api")) {
        auto validation_request = nlohmann::json{{"script", source}, {"validate_only", true}};
        if (request.contains("script_api")) validation_request["script_api"] = request["script_api"];
        auto validation = execute(validation_request);
        if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
        if (validation.value("script_api", "spider") != "spider") {
            throw std::invalid_argument("Use chain deployments to store mitmproxy addon source; execution is not available yet");
        }
    }
    auto prepared_pool = enabled ? std::make_shared<InspectionPool>(source, storage_root_.string()) : nullptr;
    if (prepared_pool) prepared_pool->warm();
    { std::scoped_lock lock(mutex_);
      if (chain_mode_) throw std::invalid_argument("Use chain operations for multiple scripts");
      if (legacy_pool_) legacy_pool_->retire();
      legacy_pool_ = std::move(prepared_pool);
      source_ = source; scope_ = scope; enabled_ = enabled; ++revision_; }
    return status();
}
nlohmann::json Inspection::status() const {
    std::scoped_lock lock(mutex_);
    auto chain = chain_;
    for (auto& item : chain) {
        const auto it = runtimes_.find(item["id"].get<std::string>());
        if (it != runtimes_.end()) {
            std::unique_lock serial(it->second->serial, std::try_to_lock);
            if (serial) expire_instances(*it->second, item.value("idle_seconds", 1800));
        }
        item["instances"] = it == runtimes_.end() ? 0U : it->second->instances.load();
        item["state_bytes"] = it == runtimes_.end() ? 0ULL : it->second->state_bytes.load();
        item["waiting"] = it == runtimes_.end() ? 0U : it->second->waiting.load();
        item["executing"] = it == runtimes_.end() ? 0U : it->second->active.load();
        item["rejected"] = it == runtimes_.end() ? 0ULL : it->second->rejected.load();
        item["workers"] = it != runtimes_.end() && it->second->pool ?
            it->second->pool->status() : nlohmann::json{{"capacity", 2}, {"idle", 0}, {"busy", 0}, {"starts", 0}};
    }
    return {{"script", chain_mode_ ? "" : source_}, {"scope", chain_mode_ ? "chain" : scope_},
            {"enabled", chain_mode_ ? std::any_of(chain_.begin(), chain_.end(),
                [](const auto& item) { return item.value("enabled", false); }) : enabled_}, {"revision", revision_},
            {"runs", runs_}, {"errors", errors_}, {"running", running_.load()}, {"recent", recent_},
            {"chain", chain}, {"notifications", notifications_},
            {"sandbox", {{"required", true}, {"policy", "landlock-seccomp-v1"},
                         {"network", false}, {"network_configurable", true}, {"processes", false}, {"filesystem", "runtime-readonly + shared-storage"}}},
            {"storage", {{"directory", storage_root_.string()}, {"quota_bytes", 16 * 1024 * 1024}}},
            {"collection", collection.status()}};
}
nlohmann::json Inspection::language(nlohmann::json request) {
    if (!request.contains("script") || !request["script"].is_string() ||
        request["script"].get_ref<const std::string&>().size() > 65536 ||
        !request.contains("language_action") || !request["language_action"].is_string())
        return failure("Invalid language request");
    if (analyzing_.fetch_add(1) >= 1) { --analyzing_; return failure("Language service busy"); }
    nlohmann::json result;
    try {
        result = execute({{"script", request["script"]}, {"language_action", request["language_action"]},
            {"line", request.value("line", nlohmann::json())},
            {"column", request.value("column", nlohmann::json())}, {"timeout_ms", 2500}});
    } catch (const std::exception& error) { result = failure(error.what()); }
    --analyzing_;
    return result;
}

nlohmann::json Inspection::content_view(const nlohmann::json& request) {
    if (!request.is_object() || !request.contains("action") ||
        !request["action"].is_string()) {
        return failure("Content view action must be a string");
    }

    const auto action = request["action"].get<std::string>();
    if (action != "list" && action != "render" && action != "reencode") {
        return failure("Unknown content view action");
    }

    const auto requested_id = request.value("deployment_id", "");
    if (requested_id.size() > 200) {
        return failure("Invalid content view deployment ID");
    }

    std::string deployment_id;
    std::shared_ptr<Runtime> runtime;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& item : chain_) {
            if (!item.value("enabled", false) ||
                item.value("script_api", "spider") != "mitmproxy") {
                continue;
            }
            const auto candidate_id = item.value("id", "");
            if (!requested_id.empty() && candidate_id != requested_id) {
                continue;
            }
            const auto found = runtimes_.find(candidate_id);
            if (found != runtimes_.end() && found->second && found->second->pool) {
                deployment_id = candidate_id;
                runtime = found->second;
                break;
            }
        }
    }

    if (!runtime) {
        return failure(requested_id.empty()
            ? "No enabled addon generation provides content views"
            : "Content view deployment is not an enabled addon generation");
    }
    if (runtime->retired) {
        return failure("Content view deployment has been retired");
    }

    // Forward only the content-view protocol. In particular, callers cannot
    // inject worker-control fields such as _shutdown or _request_id.
    nlohmann::json worker_request = {{"content_view_action", action}};
    if (action != "list") {
        if (!request.contains("data") || !request["data"].is_string()) {
            return failure("Content view data must be base64 text");
        }
        const auto& data = request["data"].get_ref<const std::string&>();
        if (data.size() > 1400000) {
            return failure("Content view input exceeds the request budget");
        }
        worker_request["data"] = data;
        worker_request["content_type"] = request.value(
            "content_type", nlohmann::json(nullptr));
        worker_request["view_name"] = request.value("view_name", "auto");
    }
    if (action == "reencode") {
        if (!request.contains("text") || !request["text"].is_string()) {
            return failure("Edited content view text must be text");
        }
        const auto& text = request["text"].get_ref<const std::string&>();
        if (text.size() > 1024 * 1024) {
            return failure("Edited content view text exceeds 1 MiB");
        }
        worker_request["text"] = text;
    }

    ++runtime->waiting;
    if (!runtime->serial.try_lock_for(std::chrono::milliseconds(250))) {
        --runtime->waiting;
        return capacity_failure("Addon generation is busy");
    }
    --runtime->waiting;
    std::unique_lock<std::timed_mutex> serial(runtime->serial, std::adopt_lock);
    ++runtime->active;

    nlohmann::json result;
    try {
        result = runtime->pool->run(std::move(worker_request), 3000);
    } catch (const std::exception& error) {
        result = failure(error.what());
    }
    --runtime->active;
    serial.unlock();

    result.erase("replacement");
    result["deployment_id"] = deployment_id;
    record_shutdown(deployment_id, runtime->pool);
    return result;
}

nlohmann::json Inspection::run(nlohmann::json request) {
    request.erase("protocol_state"); // Preview must not import another flow's history.
    request.erase("translate_state");
    request.erase("peer_translate_state");
    request.erase("translate_control");
    request.erase("translate_allowed");
    request.erase("translate_active");
    request.erase("h1_response_state");
    request.erase("held_parts");
    request.erase("peer_held_parts");
    request.erase("hold_allowed"); // Preview never creates a transport hold.
    request.erase("hold_credit_available");
    request.erase("hold_credit_reserved");
    bool addon_preview = request.contains("script_api") && request["script_api"].is_string() &&
        request["script_api"] == "mitmproxy";
    if (request.contains("script") && request["script"].is_string()) {
        auto source = request["script"].get<std::string>();
        if (source.starts_with("\xEF\xBB\xBF")) source.erase(0, 3);
        const auto line_end = source.find('\n');
        auto first_line = source.substr(0, line_end);
        if (!first_line.empty() && first_line.back() == '\r') first_line.pop_back();
        addon_preview = addon_preview || first_line == "#!mitmproxy";
    }
    // Validation is deliberately inert: it must never execute module-level
    // addon code or lifecycle hooks merely because the selected API is addon.
    nlohmann::json result;
    if (addon_preview && !request.value("validate_only", false)) {
        result = run_addon_preview(std::move(request));
    } else {
        result = run_request(std::move(request), nullptr);
    }
    result.erase("held_parts");
    result.erase("peer_held_parts");
    result.erase("translate_state");
    result.erase("peer_translate_state");
    result.erase("translate_control");
    result.erase("h1_response_state");
    result.erase("protocol_state");
    return result;
}

nlohmann::json Inspection::run_addon_preview(nlohmann::json request) {
    if (!request.contains("script") || !request["script"].is_string() ||
        request["script"].get_ref<const std::string&>().size() > 65536) {
        return record_result(request, failure("script must be a string up to 64 KiB"));
    }
    if (running_.fetch_add(1) >= 4) {
        --running_;
        return record_result(request, capacity_failure("backend inspection busy (4 workers)"));
    }

    const auto timeout = std::clamp(request.value("timeout_ms", 3000), 1, 3000);
    const auto source = request["script"].get<std::string>();
    const auto selected_api = request.contains("script_api") && request["script_api"].is_string()
        ? request["script_api"].get<std::string>() : "spider";
    nlohmann::json addon_options = nlohmann::json::array();
    if (request.contains("addon_options")) {
        addon_options = validated_addon_options(request["addon_options"]);
    }
    auto pool = std::make_shared<InspectionPool>(
        source, storage_root_.string(), InspectionPool::Lifetime::Generation,
        selected_api, std::move(addon_options), request.value("network_enabled", false));
    nlohmann::json result;
    nlohmann::json lifecycle_logs = nlohmann::json::array();
    auto collect_logs = [&](const nlohmann::json& report) {
        if (!report.contains("logs") || !report["logs"].is_array()) return;
        for (const auto& line : report["logs"]) lifecycle_logs.push_back(line);
    };

    try {
        pool->warm();
        auto event = request.value("event", nlohmann::json::object());
        if (!event.is_object()) throw std::invalid_argument("event must be an object");
        if (event.value("id", "").empty()) event["id"] = "addon-preview";

        auto setup_event = event;
        setup_event["action"] = "connection-start";
        auto& setup_info = setup_event["details"]["info"];
        setup_info.erase("content");
        setup_info.erase("content_annotations");
        setup_info.erase("side");
        const nlohmann::json instance = {
            {"mode", "flow"}, {"key", "flow:" + event["id"].get<std::string>()},
            {"deployment_id", "preview"}, {"version", 0},
        };
        const auto setup = pool->run({
            {"script", source}, {"event", setup_event}, {"instance", instance},
            {"timeout_ms", timeout},
        }, timeout);
        collect_logs(setup);
        if (!setup.value("ok", false)) {
            result = setup;
        } else {
            request["event"] = event;
            request["event"]["action"] = "connection-content";
            request["instance"] = instance;
            request["translate_allowed"] = true;
            request["translate_active"] = false;
            request["hold_allowed"] = false;
            request["hold_credit_available"] = false;
            result = pool->run(request, timeout);
            collect_logs(result);

            auto stop_event = nlohmann::json{{"id", event["id"]},
                                              {"action", "connection-stop"}};
            const auto stopped = pool->run({
                {"script", source}, {"event", stop_event}, {"instance", instance},
                {"timeout_ms", timeout},
            }, timeout);
            collect_logs(stopped);
            if (result.value("ok", false) && !stopped.value("ok", false)) result = stopped;
        }
    } catch (const std::exception& error) {
        result = failure(error.what());
    }

    pool->retire();
    const auto shutdown = pool->take_shutdown_report();
    if (!shutdown.is_null()) {
        collect_logs(shutdown);
        if (result.value("ok", false) && !shutdown.value("ok", false)) result = shutdown;
    }
    result["logs"] = std::move(lifecycle_logs);
    --running_;
    return record_result(request, std::move(result));
}

nlohmann::json Inspection::run_request(nlohmann::json request, const std::shared_ptr<InspectionPool>& pool) {
    if (!request.contains("script") || !request["script"].is_string() || request["script"].get_ref<const std::string&>().size() > 65536)
        return failure("script must be a string up to 64 KiB");
    if (running_.fetch_add(1) >= 4) { --running_; return capacity_failure("backend inspection busy (4 workers)"); }
    request["storage_directory"] = storage_root_.string();
    nlohmann::json result;
    try {
        result = pool ? pool->run(request, std::clamp(request.value("timeout_ms", 3000), 1, 3000)) : execute(request);
    } catch (const std::exception& e) { result = failure(e.what()); }
    --running_;
    result = record_result(request, std::move(result));
    if (pool) record_shutdown(request.value("script_id", ""), pool);
    return result;
}

nlohmann::json Inspection::record_result(const nlohmann::json& request, nlohmann::json result) {
    std::unique_lock lock(mutex_);
    result["run_id"] = ++runs_;
    result["session_id"] = request.value("event", nlohmann::json::object()).value("id", "");
    if (request.contains("script_id")) result["script_id"] = request["script_id"];
    if (!result.value("ok", false)) ++errors_;
    auto summary = result;
    summary.erase("replacement");
    summary.erase("replacement_reverse");
    summary.erase("instance_state");
    summary.erase("held_parts");
    summary.erase("peer_held_parts");
    summary.erase("translate_state");
    summary.erase("peer_translate_state");
    summary.erase("translate_control");
    summary.erase("h1_response_state");
    summary.erase("protocol_state");
    summary.erase("hold_credit_reservation");
    recent_.push_back(std::move(summary));
    if (recent_.size() > 20) recent_.erase(recent_.begin());
    return result;
}

void Inspection::record_shutdown(const std::string& id, const std::shared_ptr<InspectionPool>& pool) {
    auto report = pool->take_shutdown_report();
    if (report.is_null()) return;
    // Retirement can finish either in configure() or after an in-flight call.
    // The pool hands off the report once; history outlives the old generation.
    std::scoped_lock lock(mutex_);
    report["run_id"] = ++runs_;
    report["script_id"] = id;
    report["session_id"] = "";
    report["phase"] = "shutdown";
    if (!report.value("ok", false)) ++errors_;
    recent_.push_back(std::move(report));
    if (recent_.size() > 20) recent_.erase(recent_.begin());
}
std::size_t Inspection::state_charge(const nlohmann::json& state, const nlohmann::json& holds,
                                     const nlohmann::json& translations,
                                     const nlohmann::json& h1_responses, bool reserved,
                                     const nlohmann::json& protocols) {
    auto bytes = state.dump().size() + holds.dump().size() + translations.dump().size() +
        h1_responses.dump().size() + protocols.dump().size();
    if (!reserved) return bytes;
    // Directional serialized capacity is promised before early credit escapes.
    // Keep the shared full control slot for arbitrarily resized queued output.
    const auto& flow = translations.at("settings").at("flow");
    for (const auto* side : {"L", "R"}) {
        const auto& direction = flow.at(side);
        if (!direction.contains("body") && direction.value("bodies", nlohmann::json::object()).empty() &&
            direction.value("advance_due", 0LL) == 0 &&
            direction.at("input").value("owned", 0LL) == 0) continue;
        const auto used = holds.contains(side) ? holds.at(side).dump().size() : 0;
        const auto capacity = direction.value("hold_capacity", std::size_t(1024 * 1024));
        if (capacity < 256 * 1024 || capacity > 1024 * 1024 || capacity % 65536 != 0)
            throw std::runtime_error("Invalid reserved hold capacity");
        bytes += capacity - std::min<std::size_t>(used, capacity);
    }
    const auto used = translations.contains("settings") ? translations.at("settings").dump().size() : 0;
    bytes += 1024 * 1024 - std::min<std::size_t>(used, 1024 * 1024);
    return bytes;
}

void Inspection::expire_instances(Runtime& runtime, int idle_seconds) const {
    const auto cutoff = std::chrono::steady_clock::now() - std::chrono::seconds(idle_seconds);
    for (auto it = runtime.states.begin(); it != runtime.states.end();) {
        // An addon retains HTTP flows and H2 stream state until connection-stop.
        // Expiring only the native half would lose its translation checkpoint
        // while the same live connection still belongs to the addon generation.
        const bool addon_owned = runtime.addon && it->first.starts_with("flow:") &&
            runtime.addon_connections.contains(it->first.substr(5));
        if (it->second.used < cutoff && !addon_owned) {
            it = runtime.states.erase(it);
        } else {
            ++it;
        }
    }
    std::uint64_t bytes = 0;
    for (const auto& [key, instance] : runtime.states) bytes += instance.bytes;
    runtime.instances = static_cast<unsigned>(runtime.states.size()); runtime.state_bytes = bytes;
}

void Inspection::clear_flow(const std::string& id) {
    if (id.empty()) return;
    std::map<std::string, std::shared_ptr<Runtime>> owners;
    {
        std::scoped_lock lock(mutex_);
        translations_.erase(id);
        closed_flows_.insert(id);
        if (closed_flows_.size() > 10000) closed_flows_.erase(closed_flows_.begin());
        owners = runtimes_;
    }
    for (auto& [key, runtime] : owners) {
        std::unique_lock serial(runtime->serial, std::defer_lock);
        if (runtime->addon) {
            // A stop waits for the current bounded callback, never while holding
            // the global configuration lock. Ownership survives filter changes.
            serial.lock();
        } else if (!serial.try_lock()) {
            continue; // Native callbacks discard closed-flow state when publishing.
        }
        if (runtime->addon_connections.erase(id) && !runtime->retired) {
            const auto result = run_request({{"script", ""}, {"script_id", key},
                {"event", {{"id", id}, {"action", "connection-stop"}}},
                {"timeout_ms", 1000}}, runtime->pool);
            if (!result.value("ok", false)) {
                // Failed teardown must not leave an apparently healthy addon
                // retaining unreachable flows. Redeployment is explicit.
                runtime->retired = true;
                runtime->pool->retire();
                record_shutdown(key, runtime->pool);
                std::scoped_lock lock(mutex_);
                const auto current = runtimes_.find(key);
                if (current != runtimes_.end() && current->second == runtime) {
                    for (auto& entry : chain_) {
                        if (entry["id"] != key) continue;
                        entry["enabled"] = false;
                        entry["suspended"] = true;
                        entry["suspension_reason"] = "Addon connection teardown failed; redeploy required";
                        ++revision_;
                    }
                }
            }
        }
        runtime->states.erase("flow:" + id);
        expire_instances(*runtime, 86400);
    }
}

nlohmann::json Inspection::run_instance(const nlohmann::json& item, const nlohmann::json& event,
                                       const nlohmann::json& enrichments, int remaining, bool hold_allowed,
                                       bool translate_allowed, bool translate_active) {
    const auto id = item.at("id").get<std::string>();
    const auto mode = item.value("instancing", "message");
    std::string key;
    if (mode == "flow") {
        const auto session = event.value("id", "");
        if (session.empty()) return capacity_failure("Flow instance requires a session id");
        key = "flow:" + session;
    } else if (mode == "endpoint") {
        const auto endpoint = SessionFilter::endpoint_key(event, item.value("endpoint", "destination") == "source");
        if (!endpoint) return capacity_failure("Endpoint instance requires a parseable session endpoint");
        key = "endpoint:" + *endpoint;
    }
    std::shared_ptr<Runtime> runtime;
    {
        std::scoped_lock lock(mutex_);
        const auto live = std::find_if(chain_.begin(), chain_.end(), [&](const auto& entry) { return entry["id"] == id; });
        if (live == chain_.end() || !live->value("enabled", false) || (*live)["version"] != item["version"])
            return {{"ok", true}, {"replacement", nullptr}, {"logs", nlohmann::json::array()}, {"skipped", true}};
        if (!runtimes_.contains(id)) {
            // Compatibility path for a legacy deployment migrated into a chain.
            auto created = std::make_shared<Runtime>();
            created->pool = std::make_shared<InspectionPool>(
                item["script"].get<std::string>(), storage_root_.string(),
                InspectionPool::Lifetime::Rotating,
                item.value("script_api", "spider"),
                item.value("addon_options", nlohmann::json::array()),
                item.value("network_enabled", false));
            try { created->pool->warm(); }
            catch (const std::exception& error) { return failure(error.what()); }
            created->addon = created->pool->status().value("script_api", "spider") == "mitmproxy";
            runtimes_[id] = std::move(created);
        }
        runtime = runtimes_[id];
    }
    if (runtime->waiting.fetch_add(1) >= 8) {
        --runtime->waiting; ++runtime->rejected;
        return capacity_failure("Deployment queue full (8 waiters); original payload retained");
    }
    const auto started_wait = std::chrono::steady_clock::now();
    std::unique_lock serial(runtime->serial, std::defer_lock);
    const bool acquired = serial.try_lock_for(std::chrono::milliseconds(std::min(remaining, 250)));
    --runtime->waiting;
    if (!acquired) { ++runtime->rejected; return capacity_failure("Deployment queue wait exceeded 250 ms"); }
    if (runtime->retired) return capacity_failure("Deployment generation retired");
    if (runtime->addon) {
        std::scoped_lock lock(mutex_);
        if (closed_flows_.contains(event.value("id", ""))) {
            return failure("Addon connection already closed");
        }
    }
    remaining -= static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_wait).count());
    if (remaining <= 0) return capacity_failure("Inspection chain budget exhausted while waiting");
    expire_instances(*runtime, item.value("idle_seconds", 1800));
    if (!key.empty() && !runtime->states.contains(key) && runtime->states.size() >= item.value("max_instances", 128U)) {
        ++runtime->rejected; return capacity_failure("Deployment instance limit reached");
    }
    const auto previous = key.empty() || !runtime->states.contains(key) ? nlohmann::json::object() : runtime->states.at(key).state;
    auto holds = key.empty() || !runtime->states.contains(key)
        ? nlohmann::json::object() : runtime->states.at(key).holds;
    auto translations = key.empty() || !runtime->states.contains(key)
        ? nlohmann::json::object() : runtime->states.at(key).translations;
    auto h1_responses = key.empty() || !runtime->states.contains(key)
        ? nlohmann::json(nullptr) : runtime->states.at(key).h1_responses;
    auto protocols = key.empty() || !runtime->states.contains(key)
        ? nlohmann::json(nullptr) : runtime->states.at(key).protocols;
    if (translate_active && translations.empty()) return failure("Translate state expired or was lost");
    const bool previously_reserved = !key.empty() && runtime->states.contains(key) &&
        runtime->states.at(key).hold_credit_reserved;
    const auto side = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("side", "");

    // H1 may release the peer lane without an H2 Translate checkpoint. The
    // authority comes from this connection's saved pause and retained bytes,
    // not merely from a worker returning a peer-hold field.
    const auto peer_side = side == "L" ? "R" : "L";
    const bool h1_suspended = h1_responses.is_object() &&
        h1_responses.value("version", 0) == 2 &&
        h1_responses.contains("paused") && h1_responses.at("paused").is_object();
    const bool h1_peer_owned = h1_suspended &&
        h1_responses.at("paused").contains(peer_side) && holds.contains(peer_side);

    const auto budget = std::min(remaining, item.value("timeout_ms", 1000));
    const auto started = std::chrono::steady_clock::now();
    ++runtime->active;
    // Stateless messages may use both workers. Stateful deployments retain the
    // existing serial transaction across read -> script -> state publication.
    if (mode == "message") serial.unlock();
    auto result = run_request({{"script", item["script"]}, {"event", event}, {"enrichments", enrichments},
        {"script_id", id}, {"timeout_ms", budget}, {"instance_state", previous},
        {"held_parts", holds.value(side, nlohmann::json(nullptr))},
        {"peer_held_parts", holds.value(side == "L" ? "R" : "L", nlohmann::json(nullptr))},
        {"hold_allowed", hold_allowed && mode == "flow"},
        {"hold_credit_available", hold_allowed && mode == "flow"},
        {"hold_credit_reserved", previously_reserved},
        {"translate_allowed", translate_allowed && mode == "flow" && holds.empty()},
        {"translate_active", translate_active},
        {"translate_state", translations.value(side, nlohmann::json(nullptr))},
        {"peer_translate_state", translations.value(side == "L" ? "R" : "L", nlohmann::json(nullptr))},
        {"translate_control", translations.value("settings", nlohmann::json(nullptr))},
        {"h1_response_state", h1_responses},
        {"protocol_state", protocols},
        {"instance", {{"mode", mode}, {"key", key}, {"deployment_id", id}, {"version", item["version"]}}}}, runtime->pool);
    --runtime->active;
    if (!serial.owns_lock()) serial.lock();
    if (result.value("ok", false) && !valid_connection_close(result, event, mode)) {
        result = failure(
            "Invalid callback-local connection close or missing producer capability");
    }
    if (runtime->addon && result.value("ok", false) && event.value("action", "") == "connection-start") {
        runtime->addon_connections.insert(event.value("id", ""));
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    result["duration_ms"] = elapsed;
    if (result.value("ok", false)) {
        const auto next = result.value("instance_state", nlohmann::json::object());
        const auto held = result.value("held_parts", nlohmann::json(nullptr));
        if (held.is_null()) holds.erase(side);
        else holds[side] = held;
        const bool peer_changed = result.contains("peer_held_parts");
        const auto peer_held = result.value("peer_held_parts", nlohmann::json(nullptr));
        if (peer_changed) {
            if (peer_held.is_null()) holds.erase(side == "L" ? "R" : "L");
            else holds[side == "L" ? "R" : "L"] = peer_held;
        }
        const auto state_size = next.dump().size();
        const auto translated = result.value("translate_state", nlohmann::json(nullptr));
        const bool peer_translated_changed = result.contains("peer_translate_state");
        const auto peer_translated = result.value("peer_translate_state", nlohmann::json(nullptr));
        const auto settings = result.value("translate_control", nlohmann::json(nullptr));
        const bool h1_responses_changed = result.contains("h1_response_state");
        const auto next_h1_responses = result.value(
            "h1_response_state", nlohmann::json(nullptr));

        if (h1_responses_changed) h1_responses = next_h1_responses;

        // The worker stages observations alongside its callback result. Keep
        // their owner and budget checks inside the same publication decision.
        const bool protocols_changed = result.contains("protocol_state");
        if (protocols_changed) protocols = result.at("protocol_state");

        bool invalid_protocols = false;
        if (protocols_changed) {
            invalid_protocols = mode != "flow" || !protocols.is_object() ||
                protocols.dump().size() > 512 * 1024;

            if (!invalid_protocols) {
                invalid_protocols = protocols.size() != 4 ||
                    !protocols.contains("version") || !protocols.at("version").is_number_integer() ||
                    protocols.at("version") != 1 ||
                    !protocols.contains("session_id") || !protocols.at("session_id").is_string() ||
                    protocols.at("session_id") != event.value("id", "") ||
                    !protocols.contains("http1") || !protocols.at("http1").is_object() ||
                    !protocols.contains("http2") || !protocols.at("http2").is_object();
            }
        }

        if (!translated.is_null()) {
            translations[side] = translated;
            if (peer_translated_changed) {
                translations[side == "L" ? "R" : "L"] = peer_translated;
            }
            translations["settings"] = settings;
        }

        const bool reserved = result.value("hold_credit_reservation", previously_reserved);
        const auto bytes = state_charge(next, holds, translations, h1_responses, reserved, protocols);
        const auto previous_bytes = runtime->states.contains(key) ? runtime->states.at(key).bytes : 0;
        const bool invalid_state = !next.is_object() || state_size > 65536;
        const bool invalid_translation = !translated.is_null() && (
            !(translate_allowed || translate_active) || mode != "flow" ||
            !translated.is_object() || translated.dump().size() > 65536 ||
            !settings.is_object() || settings.dump().size() > 1024 * 1024);
        const bool invalid_peer_translation = peer_translated_changed && (
            translated.is_null() || !peer_translated.is_object() ||
            peer_translated.dump().size() > 65536);
        const bool invalid_hold = !held.is_null() && (
            !hold_allowed || mode != "flow" || !held.is_object() || held.dump().size() > 1024 * 1024);
        const bool invalid_peer_hold = peer_changed && (
            !hold_allowed || mode != "flow" ||
            (translated.is_null() && !(h1_responses_changed &&
                (h1_peer_owned || result.contains("connection_close")))) ||
            (!peer_held.is_null() && (!peer_held.is_object() || peer_held.dump().size() > 1024 * 1024)));
        const bool invalid_reservation = reserved &&
            (!hold_allowed || mode != "flow" || translated.is_null() || !settings.is_object());
        const bool invalid_h1_responses = h1_responses_changed && (
            mode != "flow" || !next_h1_responses.is_object() ||
            next_h1_responses.dump().size() > 768 * 1024);
        const bool deployment_full = !key.empty() &&
            runtime->state_bytes.load() - previous_bytes + bytes > 4 * 1024 * 1024;

        if (invalid_state || invalid_translation || invalid_peer_translation ||
                invalid_hold || invalid_peer_hold || invalid_reservation ||
                invalid_h1_responses || invalid_protocols || deployment_full) {
            result = failure("Instance state / hold exceeds allowed mode or 64 KiB state / 1 MiB hold / 4 MiB deployment quota");
        } else if (!key.empty()) {
            std::scoped_lock lock(mutex_);
            const bool closed = mode == "flow" && closed_flows_.contains(event.value("id", ""));

            // A replacement must never outlive the checkpoint it depends on.
            const bool stateful_publication = translate_active || !translated.is_null() ||
                h1_suspended || (next_h1_responses.is_object() && next_h1_responses.contains("paused"));
            if (stateful_publication && (runtime->retired || closed))
                result = failure("Translate owner retired or connection closed during callback");
            else if (!runtime->retired && !closed)
                runtime->states[key] = Instance{
                    next, std::chrono::steady_clock::now(), bytes, holds,
                    translations, h1_responses, reserved, protocols};
        }
    }
    if (!result.value("ok", false) && runtime->states.contains(key)) {
        auto& instance = runtime->states.at(key);

        // Failed callbacks may fail open. Their input can escape observation,
        // so retaining an apparently continuous protocol history is unsafe.
        if (!instance.protocols.is_null()) {
            instance.protocols = nullptr;
            result["logs"].push_back("Protocol tracking disabled after callback failure; reconnect to restart it");
        }

        if (instance.holds.erase(side)) {
            // Current policy remains fail-open. Do not replay stale held bytes
            // after the failing callback has already been passed through.
            result["hold"] = {{"state", "abandoned"}, {"reason", "script failure; fail-open"}};
        }

        instance.bytes = state_charge(
            instance.state, instance.holds, instance.translations,
            instance.h1_responses, instance.hold_credit_reserved, instance.protocols);
    }
    result.erase("instance_state");
    result.erase("held_parts"); // Never publish checkpoint bytes into GUI/events.
    result.erase("peer_held_parts");
    result.erase("translate_state");
    result.erase("peer_translate_state");
    result.erase("translate_control");
    result.erase("h1_response_state");
    result.erase("protocol_state");
    result.erase("hold_credit_reservation");
    // Also discard a previous state if a stop arrived while the worker was executing.
    {
        std::scoped_lock lock(mutex_);
        if (mode == "flow" && closed_flows_.contains(event.value("id", ""))) runtime->states.erase(key);
    }
    expire_instances(*runtime, item.value("idle_seconds", 1800));
    if (!result.value("ok", false) && budget < item.value("timeout_ms", 1000) && elapsed >= budget)
        result["error_kind"] = "capacity";
    const auto kind = result.value("error_kind", "");
    const bool infrastructure = kind == "capacity" || kind == "storage_busy";
    if (infrastructure) ++runtime->rejected;
    if (!infrastructure) {
        runtime->consecutive_errors = result.value("ok", false) ? 0 : runtime->consecutive_errors + 1;
        // Do not blame this deployment for a budget shortened by earlier scripts in the chain.
        runtime->consecutive_slow = budget == item.value("timeout_ms", 1000) && elapsed >= budget * 8 / 10
            ? runtime->consecutive_slow + 1 : 0;
    }
    bool retire_pool = false;
    {
        std::scoped_lock lock(mutex_);
        for (auto& live : chain_) if (live["id"] == id && live["version"] == item["version"] && !runtime->retired) {
            live["last_duration_ms"] = elapsed;
            live["consecutive_errors"] = runtime->consecutive_errors;
            live["consecutive_slow"] = runtime->consecutive_slow;
            if (runtime->consecutive_errors >= item.value("error_limit", 3U) || runtime->consecutive_slow >= 5) {
                const auto reason = runtime->consecutive_errors >= item.value("error_limit", 3U)
                    ? "Repeated errors/timeouts; inspect output before resuming" : "Five consecutive runs used at least 80% of the wall-clock budget";
                live["enabled"] = false; live["suspended"] = true; live["suspension_reason"] = reason;
                runtime->retired = true;
                retire_pool = true;
                notifications_.push_back({{"id", ++next_notification_}, {"script_id", id},
                    {"name", live["name"]}, {"version", item["version"]}, {"reason", reason}});
                if (notifications_.size() > 20) notifications_.erase(notifications_.begin());
                ++revision_;
            }
        }
    }
    if (retire_pool && runtime->pool) {
        runtime->pool->retire();
        record_shutdown(id, runtime->pool);
    }
    return result;
}

bool Inspection::translation_required(const nlohmann::json& event) const {
    const auto control = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("webhook_control", nlohmann::json::object());
    std::scoped_lock lock(mutex_);
    return translations_.contains(event.value("id", "")) || control.value("mode", "regular") == "strict";
}

nlohmann::json Inspection::automatic(const nlohmann::json& event, const nlohmann::json& enrichments) {
    const bool setup = event.value("action", "") == "connection-start";

    if (event.value("action", "") == "connection-stop") {
        clear_flow(event.value("id", ""));
        return nullptr;
    }

    if (setup) {
        std::scoped_lock lock(mutex_);
        const auto id = event.value("id", "");
        closed_flows_.erase(id);
    }

    std::string script;
    std::shared_ptr<InspectionPool> legacy_pool;
    nlohmann::json chain;
    const auto session = event.value("id", "");
    const auto control = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("webhook_control", nlohmann::json::object());
    bool translate_active = false;
    bool translate_allowed = false;
    auto translate_failure = [](const std::string& message) {
        auto result = failure(message);
        result["translate_failed"] = true;
        return result;
    };

    {
        std::scoped_lock lock(mutex_);

        if (!setup && event.value("action", "") != "connection-content") return nullptr;

        const auto pin = translations_.find(session);
        translate_active = pin != translations_.end();

        if (translate_active) {
            const auto live = std::find_if(chain_.begin(), chain_.end(), [&](const auto& item) {
                return item["id"] == pin->second.deployment &&
                       item["version"] == pin->second.version && item.value("enabled", false);
            });
            const bool strict_proxy = control.value("version", 0) == 1 &&
                                      control.value("mode", "regular") == "strict";
            const bool next_callback = control.value("sequence", 0ULL) == pin->second.sequence + 1;

            if (pin->second.failed || live == chain_.end() || !strict_proxy || !next_callback) {
                pin->second.failed = true;
                return translate_failure("Pinned translate deployment unavailable or proxy lost strict mode");
            }

            // Once pinned, scope/filter decisions and unrelated deployments cannot
            // skip or rewrite a callback ahead of the owning translate script.
            chain = nlohmann::json::array({*live});
        } else if (control.value("mode", "regular") == "strict") {
            return translate_failure("Strict connection has no translate state (backend restart or lost flow)");
        }

        translate_allowed = !setup && control.value("rewrite", true) &&
                            control.value("sequence", 0ULL) == 1 && !session.empty() &&
                            control.value("version", 0) == 1 && translations_.size() < 10000;
        const auto state = event.value("decision", nlohmann::json::object()).value("state", "");
        const bool bypassed = state == "passed" || state == "forgotten" || state == "auto-accepted";

        if (!translate_active && bypassed) return nullptr;
        if (!translate_active) chain = chain_;

        if (chain_mode_ && chain.empty()) return nullptr;
        if (chain.empty() && !enabled_) return nullptr;

        const auto rule_mode = event.value("traffic_rule", nlohmann::json::object()).value("mode", "");

        if (chain.empty() && scope_ == "rules" && rule_mode != "inspect") return nullptr;

        script = source_;
        legacy_pool = legacy_pool_;
    }
    if (!chain.empty()) {
        auto current = event;
        auto annotations = enrichments;
        nlohmann::json result = nullptr;
        auto steps = nlohmann::json::array();
        nlohmann::json replacement = nullptr;
        bool rewrite_requested = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        std::string last_enabled;
        for (const auto& entry : chain)
            if (entry.value("enabled", false)) last_enabled = entry["id"].get<std::string>();
        // First live slice admits only one enabled deployment. No preceding
        // rewrite may invalidate the original HPACK input or its annotations.
        translate_allowed = translate_allowed && std::count_if(chain.begin(), chain.end(),
            [](const auto& item) { return item.value("enabled", false); }) == 1;
        for (const auto& item : chain) {
            if (!item.value("enabled", false)) continue;
            if (!translate_active && item.value("scope", "rules") == "rules" &&
                event.value("traffic_rule", nlohmann::json::object()).value("mode", "") != "inspect") continue;
            std::string error;
            const auto filter = item.value("filter", "");
            if (!translate_active && !filter.empty()) {
                auto compiled = SessionFilter::compile(filter, error);
                if (!compiled || !compiled->matches(event)) continue;
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            result = remaining <= 0 ? capacity_failure("Inspection chain exceeded its 3 s budget") :
                run_instance(item, current, annotations, static_cast<int>(remaining), !setup && item["id"] == last_enabled,
                             translate_allowed, translate_active);
            if (result.value("skipped", false) && !translate_active) continue;
            if (translate_active && (result.value("skipped", false) ||
                (result.value("ok", false) && !result.value("translated", false))))
                result = translate_failure("Active translate callback did not produce an explicit translation");
            if (translate_active || result.value("translated", false)) {
                std::scoped_lock lock(mutex_);
                // connection-stop may race with the worker. Do not resurrect its pin.
                if (closed_flows_.contains(session))
                    result = translate_failure("Connection closed during translate callback");

                const bool ok = result.value("ok", false);

                if (!closed_flows_.contains(session))
                    translations_[session] = TranslationPin{item["id"].get<std::string>(), item["version"], !ok,
                        control.value("sequence", 0ULL)};

                if (!ok) result["translate_failed"] = true;
            }
            {
                std::scoped_lock lock(mutex_);
                for (auto& live : chain_) if (live["id"] == item["id"] && live["version"] == item["version"]) {
                    live["runs"] = live.value("runs", 0ULL) + 1;
                    const auto kind = result.value("error_kind", "");
                    live["errors"] = live.value("errors", 0ULL) +
                        (!result.value("ok", false) && kind != "capacity" && kind != "storage_busy" ? 1 : 0);
                    live["last_run_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    live["last_result"] = result;
                    live["last_result"].erase("replacement");
                    live["last_result"].erase("replacement_reverse");
                    live["last_result"].erase("connection_close");
                }
            }
            auto step = result; step.erase("replacement");
            step.erase("replacement_reverse");
            step.erase("connection_close");
            step["script_id"] = item["id"]; step["version"] = item["version"];
            steps.push_back(step);
            // Fail open with the ORIGINAL payload, never a partially applied chain.
            if (!result.value("ok", false)) { result["replacement"] = nullptr; result["steps"] = steps; return result; }
            rewrite_requested = rewrite_requested || result.value("rewrite_requested", false);
            if (result.contains("connection_close")) {
                // Closing the transport is terminal for this callback chain.
                // No later deployment may observe or replace bytes which the
                // producer has been instructed to discard.
                break;
            }
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
        if (!result.is_null()) {
            if (!result.contains("connection_close")) {
                result["replacement"] = replacement;
            }
            result["steps"] = steps;
            if (setup) result["rewrite_requested"] = rewrite_requested;
        }
        return result;
    }
    auto result = run_request({{"script", script}, {"event", event}, {"enrichments", enrichments}}, legacy_pool);
    result.erase("instance_state");
    result.erase("held_parts");
    result.erase("protocol_state");
    return result;
}
}
