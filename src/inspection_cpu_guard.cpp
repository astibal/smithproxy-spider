#include "inspection_cpu_guard.hpp"

#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

namespace spider {

struct InspectionCpuGuard::Impl {
    mutable std::mutex mutex;
    std::condition_variable changed;
    std::thread supervisor;
    pid_t child{-1};
    clockid_t cpu_clock{};
    std::chrono::nanoseconds deadline{std::chrono::seconds(3)};
    bool stopping{};
    bool dead{};
    bool expired{};
    bool clock_failed{};

    std::chrono::nanoseconds cpu_time() const {
        timespec value{};
        if (clock_gettime(cpu_clock, &value) != 0) {
            throw std::runtime_error("Cannot read inspection worker CPU clock");
        }
        return std::chrono::seconds(value.tv_sec) + std::chrono::nanoseconds(value.tv_nsec);
    }

    void kill_and_reap() {
        // The child has not been reaped elsewhere: its PID cannot be recycled.
        kill(child, SIGKILL);
        while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        dead = true;
        changed.notify_all();
    }

    void supervise() {
        std::unique_lock lock(mutex);
        for (;;) {
            int status{};
            const auto reaped = waitpid(child, &status, WNOHANG);
            if (reaped == child) {
                dead = true;
                changed.notify_all();
                return;
            }
            if (reaped < 0 && errno != EINTR) {
                // Ownership was lost externally. Never signal a possibly
                // recycled PID, and never issue a fresh budget for it.
                dead = true;
                clock_failed = true;
                changed.notify_all();
                return;
            }
            try {
                expired = expired || cpu_time() >= deadline;
            } catch (const std::exception&) {
                clock_failed = true;
            }
            if (stopping || expired || clock_failed) {
                kill_and_reap();
                return;
            }
            changed.wait_for(lock, std::chrono::milliseconds(10));
        }
    }
};

InspectionCpuGuard::InspectionCpuGuard(std::function<pid_t()> spawn)
    : impl_(std::make_unique<Impl>()) {
    std::promise<void> ready;
    auto initialized = ready.get_future();
    impl_->supervisor = std::thread([state = impl_.get(), spawn = std::move(spawn),
                                   ready = std::move(ready)]() mutable {
        bool owned = false;
        try {
            const auto child = spawn();
            if (child <= 1 || child == getpid()) {
                throw std::runtime_error("Spawner did not return a child process");
            }
            siginfo_t info{};
            if (waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT) != 0) {
                throw std::runtime_error("Inspection CPU guard requires an owned child");
            }
            state->child = child;
            owned = true;
            if (clock_getcpuclockid(child, &state->cpu_clock) != 0) {
                throw std::runtime_error("Cannot acquire inspection worker CPU clock");
            }
            state->cpu_time();
            ready.set_value();
        } catch (...) {
            if (owned) state->kill_and_reap();
            ready.set_exception(std::current_exception());
            return;
        }
        state->supervise();
    });
    try {
        initialized.get();
    } catch (...) {
        impl_->supervisor.join();
        throw;
    }
}

InspectionCpuGuard::~InspectionCpuGuard() {
    {
        std::scoped_lock lock(impl_->mutex);
        impl_->stopping = true;
        impl_->changed.notify_all();
    }
    impl_->supervisor.join();
}

void InspectionCpuGuard::grant(std::chrono::milliseconds budget) {
    if (budget <= std::chrono::milliseconds(0) || budget > std::chrono::seconds(3)) {
        throw std::invalid_argument("Inspection CPU budget must be between 1 and 3000 ms");
    }
    std::scoped_lock lock(impl_->mutex);
    if (impl_->dead || impl_->expired || impl_->clock_failed || impl_->stopping) {
        throw std::runtime_error("Inspection worker CPU supervision is no longer available");
    }
    std::chrono::nanoseconds used;
    try {
        used = impl_->cpu_time();
    } catch (...) {
        impl_->clock_failed = true;
        impl_->changed.notify_all();
        throw;
    }
    if (used >= impl_->deadline) {
        impl_->expired = true;
        impl_->changed.notify_all();
        throw std::runtime_error("Inspection worker exceeded its CPU budget");
    }
    impl_->deadline = used + budget;
    impl_->changed.notify_all();
}

bool InspectionCpuGuard::alive() const {
    std::scoped_lock lock(impl_->mutex);
    return !impl_->dead && !impl_->expired && !impl_->clock_failed && !impl_->stopping;
}

bool InspectionCpuGuard::exhausted() const {
    std::scoped_lock lock(impl_->mutex);
    return impl_->expired;
}

bool InspectionCpuGuard::wait_for_exit(std::chrono::milliseconds timeout) {
    std::unique_lock lock(impl_->mutex);
    return impl_->changed.wait_for(lock, timeout, [&] { return impl_->dead; });
}

}
