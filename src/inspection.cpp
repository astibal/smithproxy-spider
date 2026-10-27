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
    char* argv[] = {const_cast<char*>(SPIDER_PYTHON), const_cast<char*>("-I"), const_cast<char*>("-c"),
                    const_cast<char*>(inspection_worker_source), nullptr};
    char path[] = "PATH=/usr/bin:/bin";
    char* env[] = {path, nullptr};
    pid_t pid{};
    const int spawned = posix_spawn(&pid, SPIDER_PYTHON, &actions, &attributes, argv, env);
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
            if ((instancing != "message" && instancing != "flow" && instancing != "endpoint") ||
                (endpoint != "source" && endpoint != "destination") || timeout < 50 || timeout > 3000 ||
                error_limit < 1 || error_limit > 100 || max_instances < 1 || max_instances > 1024 ||
                idle_seconds < 1 || idle_seconds > 86400)
                throw std::invalid_argument("Invalid instance mode or runtime limits");
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
                item = std::prev(next.end());
            } else {
                (*item)["name"] = name; (*item)["script"] = source;
                (*item)["scope"] = scope; (*item)["filter"] = filter;
                (*item)["version"] = item->value("version", 0) + 1;
            }
            (*item)["instancing"] = instancing; (*item)["endpoint"] = endpoint;
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
                    auto validation = execute({{"script", (*item)["script"]}, {"validate_only", true}});
                    if (!validation.value("ok", false)) throw std::invalid_argument(validation.value("error", "Validation failed"));
                }
                (*item)["enabled"] = enabled;
                (*item)["suspended"] = false; (*item)["suspension_reason"] = "";
                (*item)["consecutive_errors"] = 0; (*item)["consecutive_slow"] = 0;
            } else throw std::invalid_argument("Unknown operation");
        }
        // Prepare both workers before changing the live generation. A failed
        // warm-up leaves the previous deployment untouched.
        std::shared_ptr<Runtime> prepared;
        std::string prepared_id;
        if (operation == "deploy" || operation == "enable") {
            const auto target = operation == "deploy" ? item : std::find_if(next.begin(), next.end(),
                [&](const auto& entry) { return entry["id"] == id; });
            if (target != next.end() && target->value("enabled", false)) {
                prepared_id = (*target)["id"].get<std::string>();
                prepared = std::make_shared<Runtime>();
                prepared->pool = std::make_shared<InspectionPool>((*target)["script"].get<std::string>(), storage_root_.string());
                prepared->pool->warm();
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
                    if (runtimes_[key]->pool) runtimes_[key]->pool->retire();
                }
                runtimes_.erase(key);
            }
        }
        if (prepared) runtimes_[prepared_id] = std::move(prepared);
        if (legacy_pool_) { legacy_pool_->retire(); legacy_pool_.reset(); }
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
                         {"network", false}, {"processes", false}, {"filesystem", "runtime-readonly + shared-storage"}}},
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
nlohmann::json Inspection::run(nlohmann::json request) {
    request.erase("translate_state");
    request.erase("translate_control");
    request.erase("translate_allowed");
    request.erase("translate_active");
    request.erase("held_parts");
    request.erase("peer_held_parts");
    request.erase("hold_allowed"); // Preview never creates a transport hold.
    request.erase("hold_credit_available");
    request.erase("hold_credit_reserved");
    auto result = run_request(std::move(request), nullptr);
    result.erase("held_parts");
    result.erase("peer_held_parts");
    result.erase("translate_state");
    result.erase("translate_control");
    return result;
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
    std::scoped_lock lock(mutex_);
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
    summary.erase("translate_control");
    summary.erase("hold_credit_reservation");
    recent_.push_back(std::move(summary));
    if (recent_.size() > 20) recent_.erase(recent_.begin());
    return result;
}
std::size_t Inspection::state_charge(const nlohmann::json& state, const nlohmann::json& holds,
                                     const nlohmann::json& translations, bool reserved) {
    auto bytes = state.dump().size() + holds.dump().size() + translations.dump().size();
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
        if (it->second.used < cutoff) it = runtime.states.erase(it); else ++it;
    }
    std::uint64_t bytes = 0;
    for (const auto& [key, instance] : runtime.states) bytes += instance.bytes;
    runtime.instances = static_cast<unsigned>(runtime.states.size()); runtime.state_bytes = bytes;
}

void Inspection::clear_flow(const std::string& id) {
    if (id.empty()) return;
    std::scoped_lock lock(mutex_);
    translations_.erase(id);
    closed_flows_.insert(id);
    if (closed_flows_.size() > 10000) closed_flows_.erase(closed_flows_.begin());
    for (auto& [key, runtime] : runtimes_) {
        std::unique_lock serial(runtime->serial, std::try_to_lock);
        if (!serial) continue; // In-flight runs check closed_flows_ before committing.
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
            created->pool = std::make_shared<InspectionPool>(item["script"].get<std::string>(), storage_root_.string());
            try { created->pool->warm(); }
            catch (const std::exception& error) { return failure(error.what()); }
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
    if (translate_active && translations.empty()) return failure("Translate state expired or was lost");
    const bool previously_reserved = !key.empty() && runtime->states.contains(key) &&
        runtime->states.at(key).hold_credit_reserved;
    const auto side = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("side", "");
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
        {"translate_control", translations.value("settings", nlohmann::json(nullptr))},
        {"instance", {{"mode", mode}, {"key", key}, {"deployment_id", id}, {"version", item["version"]}}}}, runtime->pool);
    --runtime->active;
    if (!serial.owns_lock()) serial.lock();
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
        const auto settings = result.value("translate_control", nlohmann::json(nullptr));

        if (!translated.is_null()) {
            translations[side] = translated;
            translations["settings"] = settings;
        }

        const bool reserved = result.value("hold_credit_reservation", previously_reserved);
        const auto bytes = state_charge(next, holds, translations, reserved);
        const auto previous_bytes = runtime->states.contains(key) ? runtime->states.at(key).bytes : 0;
        const bool invalid_state = !next.is_object() || state_size > 65536;
        const bool invalid_translation = !translated.is_null() && (
            !(translate_allowed || translate_active) || mode != "flow" ||
            !translated.is_object() || translated.dump().size() > 65536 ||
            !settings.is_object() || settings.dump().size() > 1024 * 1024);
        const bool invalid_hold = !held.is_null() && (
            !hold_allowed || mode != "flow" || !held.is_object() || held.dump().size() > 1024 * 1024);
        const bool invalid_peer_hold = peer_changed && (
            !hold_allowed || mode != "flow" || translated.is_null() ||
            (!peer_held.is_null() && (!peer_held.is_object() || peer_held.dump().size() > 1024 * 1024)));
        const bool invalid_reservation = reserved &&
            (!hold_allowed || mode != "flow" || translated.is_null() || !settings.is_object());
        const bool deployment_full = !key.empty() &&
            runtime->state_bytes.load() - previous_bytes + bytes > 4 * 1024 * 1024;

        if (invalid_state || invalid_translation || invalid_hold || invalid_peer_hold || invalid_reservation || deployment_full) {
            result = failure("Instance state / hold exceeds allowed mode or 64 KiB state / 1 MiB hold / 4 MiB deployment quota");
        } else if (!key.empty()) {
            std::scoped_lock lock(mutex_);
            const bool closed = mode == "flow" && closed_flows_.contains(event.value("id", ""));

            // A replacement must never outlive the checkpoint it depends on.
            if ((translate_active || !translated.is_null()) && (runtime->retired || closed))
                result = failure("Translate owner retired or connection closed during callback");
            else if (!runtime->retired && !closed)
                runtime->states[key] = Instance{next, std::chrono::steady_clock::now(), bytes, holds, translations, reserved};
        }
    }
    if (!result.value("ok", false) && runtime->states.contains(key)) {
        auto& instance = runtime->states.at(key);
        if (instance.holds.erase(side)) {
            // Current policy remains fail-open. Do not replay stale held bytes
            // after the failing callback has already been passed through.
            result["hold"] = {{"state", "abandoned"}, {"reason", "script failure; fail-open"}};
            instance.bytes = state_charge(instance.state, instance.holds, instance.translations,
                                          instance.hold_credit_reserved);
        }
    }
    result.erase("instance_state");
    result.erase("held_parts"); // Never publish checkpoint bytes into GUI/events.
    result.erase("peer_held_parts");
    result.erase("translate_state");
    result.erase("translate_control");
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
                if (runtime->pool) runtime->pool->retire();
                notifications_.push_back({{"id", ++next_notification_}, {"script_id", id},
                    {"name", live["name"]}, {"version", item["version"]}, {"reason", reason}});
                if (notifications_.size() > 20) notifications_.erase(notifications_.begin());
                ++revision_;
            }
        }
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
                }
            }
            auto step = result; step.erase("replacement");
            step.erase("replacement_reverse");
            step["script_id"] = item["id"]; step["version"] = item["version"];
            steps.push_back(step);
            // Fail open with the ORIGINAL payload, never a partially applied chain.
            if (!result.value("ok", false)) { result["replacement"] = nullptr; result["steps"] = steps; return result; }
            rewrite_requested = rewrite_requested || result.value("rewrite_requested", false);
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
            result["replacement"] = replacement;
            result["steps"] = steps;
            if (setup) result["rewrite_requested"] = rewrite_requested;
        }
        return result;
    }
    auto result = run_request({{"script", script}, {"event", event}, {"enrichments", enrichments}}, legacy_pool);
    result.erase("instance_state");
    result.erase("held_parts");
    return result;
}
}
