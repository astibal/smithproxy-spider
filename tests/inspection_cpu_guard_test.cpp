#include "inspection_cpu_guard.hpp"

#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <memory>
#include <poll.h>
#include <stdexcept>
#include <thread>
#include <time.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std::chrono_literals;

std::chrono::nanoseconds cpu_time() {
    timespec value{};
    assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) == 0);
    return std::chrono::seconds(value.tv_sec) + std::chrono::nanoseconds(value.tv_nsec);
}

struct Harness {
    int commands[2]{};
    int replies[2]{};
    pid_t child{-1};
    std::unique_ptr<spider::InspectionCpuGuard> guard;

    Harness() {
        assert(pipe(commands) == 0);
        assert(pipe(replies) == 0);
        guard = std::make_unique<spider::InspectionCpuGuard>([this] {
            const auto parent = getpid();
            child = fork();
            assert(child >= 0);
            if (child != 0) return child;
            // The guard's stable thread, not the temporary constructing thread,
            // must be our parent for this lifetime signal to be useful.
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(2);
            close(commands[1]);
            close(replies[0]);
            char command{};
            while (read(commands[0], &command, 1) == 1) {
                if (command == 'q') _exit(0);
                const auto end = cpu_time() + 100ms;
                while (command == 'x' || cpu_time() < end) {
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                }
                if (write(replies[1], "a", 1) != 1) _exit(3);
            }
            _exit(0);
        });
    }

    ~Harness() {
        guard.reset();
        close(commands[0]);
        close(commands[1]);
        close(replies[0]);
        close(replies[1]);
    }

    void send(char command) {
        assert(write(commands[1], &command, 1) == 1);
    }

    void acknowledged() {
        pollfd ready{replies[0], POLLIN, 0};
        assert(poll(&ready, 1, 2000) == 1);
        char reply{};
        assert(read(replies[0], &reply, 1) == 1 && reply == 'a');
    }

    void await_exit() {
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (guard->alive() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(5ms);
        }
        assert(!guard->alive());
    }
};

int main() {
    {
        std::unique_ptr<Harness> child;
        std::thread temporary([&] { child = std::make_unique<Harness>(); });
        temporary.join();
        child->guard->grant(50ms);
        std::this_thread::sleep_for(150ms);
        assert(child->guard->alive()); // Wall time is not CPU consumption.
        for (unsigned index = 0; index < 25; ++index) {
            child->guard->grant(500ms);
            child->send('w');
            child->acknowledged();
            child->guard->grant(50ms);
        }
        assert(child->guard->alive()); // More than two cumulative CPU seconds.
        child->guard->grant(20ms);
        child->send('x');
        child->await_exit();
        assert(child->guard->exhausted());
        bool refused = false;
        try {
            child->guard->grant(500ms);
        } catch (const std::runtime_error&) {
            refused = true;
        }
        assert(refused);
        const auto pid = child->child;
        child.reset();
        assert(waitpid(pid, nullptr, WNOHANG) == -1 && errno == ECHILD);
    }
    {
        Harness child;
        for (const auto invalid : {0ms, 3001ms}) {
            bool refused = false;
            try {
                child.guard->grant(invalid);
            } catch (const std::invalid_argument&) {
                refused = true;
            }
            assert(refused);
        }
        child.send('q');
        child.await_exit();
        assert(!child.guard->exhausted());
    }
    bool refused = false;
    try {
        spider::InspectionCpuGuard invalid([] { return getpid(); });
    } catch (const std::runtime_error&) {
        refused = true;
    }
    assert(refused); // A bad spawner must never make the guard signal its owner.
}
