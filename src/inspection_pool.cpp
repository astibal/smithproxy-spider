#include "inspection_pool.hpp"
#include "inspection_worker.hpp"
#include "inspection_cpu_guard.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <cerrno>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <stdexcept>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace spider {
namespace {
using Clock = std::chrono::steady_clock;
using json = nlohmann::json;
json failed(const std::string& message, const char* kind = "worker") {
    return {{"ok", false}, {"replacement", nullptr}, {"logs", json::array()},
            {"error", message}, {"error_kind", kind}};
}

class Worker {
public:
    ~Worker() { stop(); }
    bool generation() const { return generation_; }
    json retire() {
        json report = nullptr;
        if (generation_ && cpu_guard_ && fd_ >= 0) {
            try {
                const auto grace = std::chrono::milliseconds(500);
                const auto deadline = Clock::now() + grace;
                report = exchange({{"_shutdown", true}}, deadline, true);
                if (!report.value("_shutdown", false) || !report.contains("ok") ||
                    !report["ok"].is_boolean() || !report.contains("logs") || !report["logs"].is_array()) {
                    throw std::runtime_error("Invalid worker shutdown report");
                }
                std::size_t log_bytes = 0;
                for (const auto& line : report["logs"]) {
                    if (!line.is_string()) throw std::runtime_error("Invalid worker shutdown log entry");
                    log_bytes += line.get_ref<const std::string&>().size();
                }
                if (log_bytes > 256 * 1024) {
                    throw std::runtime_error("Worker shutdown logs exceed 256 KiB");
                }
                report.erase("_shutdown");
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
                if (!cpu_guard_->wait_for_exit(remaining)) {
                    throw std::runtime_error("Worker did not exit within its cleanup budget");
                }
            } catch (const std::exception& error) {
                report = failed(error.what(), "shutdown");
            }
        }
        stop();
        return report;
    }
    void stop() {
        if (fd_ >= 0) { close(fd_); fd_ = -1; }
        cpu_guard_.reset();
    }
    std::string start(const std::string& source, const std::string& storage,
                      const std::string& script_api, const json& addon_options, bool network_enabled,
                      Clock::time_point deadline) {
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0)
            throw std::runtime_error("Cannot create worker channel");
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, sockets[1], STDIN_FILENO);
        posix_spawn_file_actions_adddup2(&actions, sockets[1], STDOUT_FILENO);
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
        argv.push_back(const_cast<char*>("--persistent"));
        argv.push_back(const_cast<char*>("--cpu-supervised"));
        argv.push_back(nullptr);
        char path[] = "PATH=/usr/bin:/bin";
        char* env[] = {path, nullptr};
        try {
            // The guard owns spawning and reaping on one stable thread. This
            // also gives PR_SET_PDEATHSIG a stable parent thread to observe.
            cpu_guard_ = std::make_unique<InspectionCpuGuard>([&] {
                pid_t child = -1;
                const int error = posix_spawn(&child, SPIDER_PYTHON, &actions,
                                              &attributes, argv.data(), env);
                if (error) throw std::runtime_error("Cannot start pool worker");
                return child;
            });
        } catch (...) {
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attributes);
            close(sockets[0]);
            close(sockets[1]);
            throw;
        }
        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attributes);
        close(sockets[1]);
        fd_ = sockets[0];
        fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL) | O_NONBLOCK);
        json initialization = {{"script", source}, {"storage_directory", storage},
                               {"network_enabled", network_enabled}};
        if (script_api != "spider") {
            initialization["script_api"] = script_api;
        }
        if (!addon_options.empty()) {
            initialization["addon_options"] = addon_options;
        }
        const auto ready = exchange(initialization, deadline);
        if (!ready.value("ready", false))
            throw std::runtime_error(ready.value("error", "Worker sandbox/compile initialization failed"));
        const auto effective_api = ready.value("script_api", "spider");
        if (effective_api != "spider" && effective_api != "mitmproxy") {
            throw std::runtime_error("Worker returned an unknown script API");
        }
        generation_ = effective_api == "mitmproxy" || ready.value("native_lifecycle", false);
        return effective_api;
    }
    json exchange(const json& request, Clock::time_point deadline, bool finishing = false) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        cpu_guard_->grant(std::min(remaining, std::chrono::milliseconds(3000)));
        const auto wire = request.dump() + '\n';
        if (wire.size() > 64 * 1024 * 1024) throw std::runtime_error("Worker request exceeds 64 MiB");
        std::size_t offset = 0;
        while (offset < wire.size()) {
            wait(POLLOUT, deadline);
            const auto n = send(fd_, wire.data() + offset, wire.size() - offset, MSG_NOSIGNAL);
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (n <= 0) {
                if (cpu_guard_->exhausted()) {
                    throw std::runtime_error("Worker exceeded its callback CPU budget before request delivery");
                }
                if (!cpu_guard_->alive()) {
                    throw std::runtime_error("Worker exited before request delivery");
                }
                throw std::runtime_error("Worker channel closed during request delivery");
            }
            offset += static_cast<std::size_t>(n);
        }
        std::string response;
        char bytes[8192];
        for (;;) {
            wait(POLLIN, deadline);
            const auto n = recv(fd_, bytes, sizeof(bytes), 0);
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (n <= 0) {
                if (cpu_guard_->exhausted()) {
                    throw std::runtime_error("Worker exceeded its callback CPU budget");
                }
                if (!cpu_guard_->alive()) {
                    throw std::runtime_error("Worker exited while processing a callback");
                }
                throw std::runtime_error("Worker channel closed while processing a callback");
            }
            response.append(bytes, static_cast<std::size_t>(n));
            if (response.size() > 2 * 1024 * 1024) throw std::runtime_error("Worker response exceeds 2 MiB");
            const auto end = response.find('\n');
            if (end == std::string::npos) continue;
            if (end != response.size() - 1) throw std::runtime_error("Unexpected data after worker response");
            auto parsed = json::parse(response, nullptr, false);
            if (!parsed.is_object()) throw std::runtime_error("Invalid worker response");
            // Idle asyncio tasks must remain bounded as well. A callback gets
            // a fresh allowance only if the preceding budget was not exceeded.
            if (!finishing) cpu_guard_->grant(std::chrono::milliseconds(100));
            return parsed;
        }
    }
private:
    void wait(short events, Clock::time_point deadline) {
        for (;;) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
            if (remaining <= 0) throw std::runtime_error("Python exceeded the execution wall-clock budget");
            pollfd descriptor{fd_, events, 0};
            const auto result = poll(&descriptor, 1, static_cast<int>(remaining));
            if (result < 0 && errno == EINTR) continue;
            if (result < 0) throw std::runtime_error("Worker channel poll failed");
            if (result == 0) throw std::runtime_error("Python exceeded the execution wall-clock budget");
            if (descriptor.revents & events) return;
            throw std::runtime_error("Worker channel closed");
        }
    }
    int fd_{-1};
    std::unique_ptr<InspectionCpuGuard> cpu_guard_;
    bool generation_{};
};
}

struct InspectionPool::Impl {
    struct Slot {
        std::unique_ptr<Worker> worker;
        bool busy{}, starting{}, rotation_due{};
        unsigned calls{};
    };
    mutable std::mutex mutex;
    std::condition_variable available;
    std::array<Slot, 2> slots;
    std::string source, storage, script_api;
    json addon_options = json::array();
    Lifetime lifetime{Lifetime::Rotating};
    bool network_enabled{false};
    bool generation_lost{};
    bool warmed{};
    bool retired{};
    std::atomic_uint starts{}, completed{}, restarts{};
    unsigned next{}, sequence{};
    std::uint64_t queue_wait_us{}, max_queue_wait_us{}, cold_waits{};
    std::uint64_t next_ticket{}, rotations{}, forced_recycles{};
    std::deque<std::uint64_t> waiters;
    std::thread maintenance;
    json shutdown_report = nullptr;
    bool shutdown_report_taken{};

    // Planned retirement must leave the other execution slot alive, even when
    // that worker also requested retirement. Failure recovery has priority.
    int maintenance_slot() const {
        for (int i = 0; i < 2; ++i)
            if (!slots[i].busy && !slots[i].worker) return i;
        for (int i = 0; i < 2; ++i)
            if (!slots[i].busy && slots[i].rotation_due && slots[1 - i].worker)
                return i;
        return -1;
    }
};
InspectionPool::InspectionPool(std::string source, std::string storage, Lifetime lifetime,
                               std::string script_api, json addon_options, bool network_enabled)
    : impl_(std::make_unique<Impl>()) {
    impl_->source = std::move(source); impl_->storage = std::move(storage);
    impl_->lifetime = lifetime;
    impl_->script_api = std::move(script_api);
    impl_->addon_options = std::move(addon_options);
    impl_->network_enabled = network_enabled;
}
InspectionPool::~InspectionPool() {
    retire();
    if (impl_->maintenance.joinable()) impl_->maintenance.join();
}

void InspectionPool::warm() {
    std::scoped_lock lock(impl_->mutex);
    if (impl_->warmed || impl_->retired) {
        throw std::runtime_error("Deployment pool cannot be warmed again");
    }
    impl_->warmed = true;
    const auto deadline = Clock::now() + std::chrono::seconds(3);
    const unsigned capacity = impl_->lifetime == Lifetime::Generation ? 1 : 2;
    for (unsigned index = 0; index < capacity; ++index) {
        auto& slot = impl_->slots[index];
        auto worker = std::make_unique<Worker>();
        const auto effective_api = worker->start(
            impl_->source, impl_->storage, impl_->script_api,
            impl_->addon_options, impl_->network_enabled, deadline);
        impl_->script_api = effective_api;
        slot.worker = std::move(worker);
        ++impl_->starts;
        if (slot.worker->generation()) {
            // Resolve lifecycle ownership at startup. Neither native hooks nor
            // addons may create a second worker with independent Python state.
            impl_->lifetime = Lifetime::Generation;
            break;
        }
    }
    // Stateful scripts belong to one process for their entire generation. A
    // maintenance replacement would discard Python state while looking healthy.
    if (impl_->lifetime == Lifetime::Generation) {
        return;
    }
    impl_->maintenance = std::thread([state = impl_.get()] {
        std::unique_lock lock(state->mutex);
        for (;;) {
            state->available.wait(lock, [&] {
                return state->retired || state->maintenance_slot() >= 0;
            });
            if (state->retired) return;
            auto& slot = state->slots[state->maintenance_slot()];
            slot.busy = slot.starting = true;
            slot.rotation_due = false;
            slot.calls = 0;
            auto previous = std::move(slot.worker);
            if (previous) ++state->rotations;
            lock.unlock();
            // Reap before spawning: never exceed two processes per pool. Do not
            // hold the pool lock during process teardown or sandbox startup.
            previous.reset();
            std::unique_ptr<Worker> replacement;
            try {
                replacement = std::make_unique<Worker>();
                replacement->start(
                    state->source, state->storage, state->script_api,
                    state->addon_options, state->network_enabled, Clock::now() + std::chrono::seconds(3));
                ++state->starts; ++state->restarts;
            } catch (const std::exception&) { replacement.reset(); }
            lock.lock();
            const bool retry = !replacement;
            if (!state->retired) slot.worker = std::move(replacement);
            slot.busy = slot.starting = false;
            state->available.notify_all();
            // Resource exhaustion must not become a respawn busy loop.
            if (retry && !state->retired)
                state->available.wait_for(lock, std::chrono::milliseconds(500), [&] { return state->retired; });
        }
    });
}
void InspectionPool::retire() {
    std::array<std::unique_ptr<Worker>, 2> retiring;
    {
        std::scoped_lock lock(impl_->mutex);
        impl_->retired = true;
        for (unsigned index = 0; index < impl_->slots.size(); ++index) {
            if (!impl_->slots[index].busy) retiring[index] = std::move(impl_->slots[index].worker);
        }
        impl_->available.notify_all();
    }
    for (auto& worker : retiring) {
        if (worker) {
            const auto report = worker->retire();
            if (!report.is_null()) {
                std::scoped_lock lock(impl_->mutex);
                impl_->shutdown_report = report;
            }
        }
    }
}
json InspectionPool::run(json request, int timeout_ms) {
    const auto queued_at = Clock::now();
    const auto deadline = queued_at + std::chrono::milliseconds(timeout_ms);
    unsigned index, sequence;
    {
        std::unique_lock lock(impl_->mutex);
        if (impl_->retired) return failed("Deployment pool retired", "capacity");
        if (impl_->generation_lost) {
            return failed("Deployment worker state was lost; redeploy required", "worker_state_lost");
        }
        const auto ticket = ++impl_->next_ticket;
        impl_->waiters.push_back(ticket);
        // Distinguish a cold pool (both processes absent) from occupied workers.
        if (!impl_->retired && std::none_of(impl_->slots.begin(), impl_->slots.end(),
                [](const auto& slot) { return bool(slot.worker); }))
            ++impl_->cold_waits;
        const auto wait_until = std::min(deadline, Clock::now() + std::chrono::milliseconds(250));
        if (!impl_->available.wait_until(lock, wait_until, [&] {
                return impl_->retired || impl_->generation_lost || (impl_->waiters.front() == ticket &&
                    std::any_of(impl_->slots.begin(), impl_->slots.end(),
                        [](const auto& slot) { return !slot.busy && slot.worker; }));
            })) {
            impl_->waiters.erase(std::find(impl_->waiters.begin(), impl_->waiters.end(), ticket));
            impl_->available.notify_all();
            return failed("Deployment pool wait exceeded 250 ms", "capacity");
        }
        // FIFO admission prevents a fast returning producer from repeatedly
        // taking the only available worker ahead of already waiting requests.
        impl_->waiters.erase(std::find(impl_->waiters.begin(), impl_->waiters.end(), ticket));
        impl_->available.notify_all();
        if (impl_->retired) return failed("Deployment pool retired", "capacity");
        if (impl_->generation_lost) {
            return failed("Deployment worker state was lost; redeploy required", "worker_state_lost");
        }
        const auto waited = static_cast<std::uint64_t>(std::chrono::duration_cast<
            std::chrono::microseconds>(Clock::now() - queued_at).count());
        impl_->queue_wait_us += waited;
        impl_->max_queue_wait_us = std::max(impl_->max_queue_wait_us, waited);
        index = 0;
        if (impl_->lifetime == Lifetime::Rotating) {
            index = impl_->next++ % 2;
            if (impl_->slots[index].busy || !impl_->slots[index].worker) index = 1 - index;
            const auto& other = impl_->slots[1 - index];
            if (impl_->slots[index].rotation_due && other.worker && !other.busy && !other.rotation_due)
                index = 1 - index;
        }
        impl_->slots[index].busy = true;
        sequence = ++impl_->sequence;
    }
    // This slot belongs exclusively to this invocation until the final lock.
    auto& slot = impl_->slots[index];
    json result;
    bool recycle = false;
    bool rotate = false;
    std::unique_ptr<Worker> retiring;
    try {
        request["_request_id"] = sequence;
        result = slot.worker->exchange(request, deadline);
        if (!result.contains("ok") || !result["ok"].is_boolean() ||
            result.value("_request_id", 0U) != sequence || !result.contains("replacement"))
            throw std::runtime_error("Invalid worker response identity");
        // A well-formed negative callback result is not an IPC failure. The
        // worker decides whether its in-process state is still valid; channel,
        // protocol and resource failures reach the exception path below.
        recycle = result.value("_worker_recycle", false);
        rotate = result.value("_worker_rotate", false);
        result.erase("_request_id"); result.erase("_worker_recycle");
        result.erase("_worker_rotate");
        ++impl_->completed;
    } catch (const std::exception& error) {
        result = failed(error.what());
        recycle = true;
    }
    {
        std::scoped_lock lock(impl_->mutex);
        ++slot.calls;
        if (impl_->lifetime == Lifetime::Rotating) {
            slot.rotation_due = slot.rotation_due || rotate || slot.calls >= 256;
        }
        // Rotating workers keep their count cap. Stateful generations instead
        // have per-invocation CPU supervision and may not lose state on a timer.
        const bool count_limit = impl_->lifetime == Lifetime::Rotating && slot.calls >= 4096;
        if (recycle || count_limit) ++impl_->forced_recycles;
        if (recycle || count_limit) {
            if (impl_->lifetime == Lifetime::Generation) {
                impl_->generation_lost = true;
                result["worker_state_lost"] = true;
                if (impl_->retired) {
                    // Retirement raced with a failed callback. Do not retry
                    // cleanup in a corrupted process, but make that omission
                    // explicit instead of leaving a missing lifecycle report.
                    impl_->shutdown_report = failed(
                        "Addon cleanup skipped after worker failure: " +
                        result.value("error", "worker state lost"), "shutdown");
                    impl_->shutdown_report["cleanup_skipped"] = true;
                }
            }
        }
        if (recycle || count_limit) {
            slot.worker.reset();
        } else if (impl_->retired) {
            retiring = std::move(slot.worker);
        }
        slot.busy = false;
        impl_->available.notify_all();
    }
    if (retiring) {
        const auto report = retiring->retire();
        if (!report.is_null()) {
            std::scoped_lock lock(impl_->mutex);
            impl_->shutdown_report = report;
        }
    }
    return result;
}
json InspectionPool::take_shutdown_report() {
    std::scoped_lock lock(impl_->mutex);
    if (impl_->shutdown_report_taken || impl_->shutdown_report.is_null()) return nullptr;
    impl_->shutdown_report_taken = true;
    return impl_->shutdown_report;
}

json InspectionPool::status() const {
    std::scoped_lock lock(impl_->mutex);
    // Busy slots may be replacing their process; do not inspect their pointers.
    unsigned idle = 0, busy = 0, starting = 0;
    for (const auto& slot : impl_->slots) {
        if (slot.starting) ++starting;
        else if (slot.busy) ++busy;
        else if (slot.worker) ++idle;
    }
    const bool generation = impl_->lifetime == Lifetime::Generation;
    return {{"capacity", generation ? 1 : 2}, {"lifetime", generation ? "generation" : "rotating"},
            {"script_api", impl_->script_api}, {"network_enabled", impl_->network_enabled},
            {"shutdown", impl_->shutdown_report},
            {"state_lost", impl_->generation_lost},
            {"idle", idle}, {"busy", busy}, {"starting", starting}, {"starts", impl_->starts.load()},
            {"restarts", impl_->restarts.load()}, {"completed", impl_->completed.load()},
            {"queue_wait_us", impl_->queue_wait_us}, {"max_queue_wait_us", impl_->max_queue_wait_us},
            {"cold_waits", impl_->cold_waits}, {"rotations", impl_->rotations},
            {"forced_recycles", impl_->forced_recycles}, {"queued", impl_->waiters.size()}};
}
}
