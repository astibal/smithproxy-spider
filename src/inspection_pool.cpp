#include "inspection_pool.hpp"
#include "inspection_worker.hpp"
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
    void stop() {
        if (fd_ >= 0) { close(fd_); fd_ = -1; }
        if (pid_ > 0) {
            kill(-pid_, SIGKILL);
            while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {}
            pid_ = -1;
        }
    }
    void start(const std::string& source, const std::string& storage, Clock::time_point deadline) {
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
        char* argv[] = {const_cast<char*>(SPIDER_PYTHON), const_cast<char*>("-I"),
                       const_cast<char*>("-c"), const_cast<char*>(inspection_worker_source),
                       const_cast<char*>("--persistent"), nullptr};
        char path[] = "PATH=/usr/bin:/bin";
        char* env[] = {path, nullptr};
        const int error = posix_spawn(&pid_, SPIDER_PYTHON, &actions, &attributes, argv, env);
        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attributes);
        close(sockets[1]);
        if (error) { close(sockets[0]); pid_ = -1; throw std::runtime_error("Cannot start pool worker"); }
        fd_ = sockets[0];
        fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL) | O_NONBLOCK);
        const auto ready = exchange({{"script", source}, {"storage_directory", storage}}, deadline);
        if (!ready.value("ready", false))
            throw std::runtime_error(ready.value("error", "Worker sandbox/compile initialization failed"));
    }
    json exchange(const json& request, Clock::time_point deadline) {
        const auto wire = request.dump() + '\n';
        if (wire.size() > 64 * 1024 * 1024) throw std::runtime_error("Worker request exceeds 64 MiB");
        std::size_t offset = 0;
        while (offset < wire.size()) {
            wait(POLLOUT, deadline);
            const auto n = send(fd_, wire.data() + offset, wire.size() - offset, MSG_NOSIGNAL);
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (n <= 0) throw std::runtime_error("Worker closed during request");
            offset += static_cast<std::size_t>(n);
        }
        std::string response;
        char bytes[8192];
        for (;;) {
            wait(POLLIN, deadline);
            const auto n = recv(fd_, bytes, sizeof(bytes), 0);
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (n <= 0) throw std::runtime_error("Worker exited or exceeded a resource limit");
            response.append(bytes, static_cast<std::size_t>(n));
            if (response.size() > 2 * 1024 * 1024) throw std::runtime_error("Worker response exceeds 2 MiB");
            const auto end = response.find('\n');
            if (end == std::string::npos) continue;
            if (end != response.size() - 1) throw std::runtime_error("Unexpected data after worker response");
            auto parsed = json::parse(response, nullptr, false);
            if (!parsed.is_object()) throw std::runtime_error("Invalid worker response");
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
    pid_t pid_{-1};
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
    std::string source, storage;
    bool retired{};
    std::atomic_uint starts{}, completed{}, restarts{};
    unsigned next{}, sequence{};
    std::uint64_t queue_wait_us{}, max_queue_wait_us{}, cold_waits{};
    std::uint64_t next_ticket{}, rotations{}, forced_recycles{};
    std::deque<std::uint64_t> waiters;
    std::thread maintenance;

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
InspectionPool::InspectionPool(std::string source, std::string storage) : impl_(std::make_unique<Impl>()) {
    impl_->source = std::move(source); impl_->storage = std::move(storage);
}
InspectionPool::~InspectionPool() {
    retire();
    if (impl_->maintenance.joinable()) impl_->maintenance.join();
}

void InspectionPool::warm() {
    std::scoped_lock lock(impl_->mutex);
    const auto deadline = Clock::now() + std::chrono::seconds(3);
    for (auto& slot : impl_->slots) {
        auto worker = std::make_unique<Worker>();
        worker->start(impl_->source, impl_->storage, deadline);
        slot.worker = std::move(worker);
        ++impl_->starts;
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
                replacement->start(state->source, state->storage, Clock::now() + std::chrono::seconds(3));
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
    std::scoped_lock lock(impl_->mutex);
    impl_->retired = true;
    for (auto& slot : impl_->slots) if (!slot.busy) slot.worker.reset();
    impl_->available.notify_all();
}
json InspectionPool::run(json request, int timeout_ms) {
    const auto queued_at = Clock::now();
    const auto deadline = queued_at + std::chrono::milliseconds(timeout_ms);
    unsigned index, sequence;
    {
        std::unique_lock lock(impl_->mutex);
        if (impl_->retired) return failed("Deployment pool retired", "capacity");
        const auto ticket = ++impl_->next_ticket;
        impl_->waiters.push_back(ticket);
        // Distinguish a cold pool (both processes absent) from occupied workers.
        if (!impl_->retired && std::none_of(impl_->slots.begin(), impl_->slots.end(),
                [](const auto& slot) { return bool(slot.worker); }))
            ++impl_->cold_waits;
        const auto wait_until = std::min(deadline, Clock::now() + std::chrono::milliseconds(250));
        if (!impl_->available.wait_until(lock, wait_until, [&] {
                return impl_->retired || (impl_->waiters.front() == ticket &&
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
        const auto waited = static_cast<std::uint64_t>(std::chrono::duration_cast<
            std::chrono::microseconds>(Clock::now() - queued_at).count());
        impl_->queue_wait_us += waited;
        impl_->max_queue_wait_us = std::max(impl_->max_queue_wait_us, waited);
        index = impl_->next++ % 2;
        if (impl_->slots[index].busy || !impl_->slots[index].worker) index = 1 - index;
        const auto& other = impl_->slots[1 - index];
        if (impl_->slots[index].rotation_due && other.worker && !other.busy && !other.rotation_due)
            index = 1 - index;
        impl_->slots[index].busy = true;
        sequence = ++impl_->sequence;
    }
    // This slot belongs exclusively to this invocation until the final lock.
    auto& slot = impl_->slots[index];
    json result;
    bool recycle = false;
    bool rotate = false;
    try {
        request["_request_id"] = sequence;
        result = slot.worker->exchange(request, deadline);
        if (!result.contains("ok") || !result["ok"].is_boolean() ||
            result.value("_request_id", 0U) != sequence || !result.contains("replacement"))
            throw std::runtime_error("Invalid worker response identity");
        recycle = result.value("_worker_recycle", false) || !result.value("ok", false);
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
        slot.rotation_due = slot.rotation_due || rotate || slot.calls >= 256;
        // Parent-side count bound also applies if a script corrupts Python's
        // bookkeeping. Kernel CPU/memory limits remain independent of both.
        if (recycle || slot.calls >= 4096) ++impl_->forced_recycles;
        if (recycle || impl_->retired || slot.calls >= 4096) slot.worker.reset();
        slot.busy = false;
        impl_->available.notify_all();
    }
    return result;
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
    return {{"capacity", 2}, {"idle", idle}, {"busy", busy}, {"starting", starting}, {"starts", impl_->starts.load()},
            {"restarts", impl_->restarts.load()}, {"completed", impl_->completed.load()},
            {"queue_wait_us", impl_->queue_wait_us}, {"max_queue_wait_us", impl_->max_queue_wait_us},
            {"cold_waits", impl_->cold_waits}, {"rotations", impl_->rotations},
            {"forced_recycles", impl_->forced_recycles}, {"queued", impl_->waiters.size()}};
}
}
