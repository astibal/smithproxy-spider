#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <sys/types.h>

namespace spider {

// Owns a child from spawn through reap. The stable supervising thread is also
// its spawning thread, so a worker can safely use PR_SET_PDEATHSIG later.
class InspectionCpuGuard {
public:
    explicit InspectionCpuGuard(std::function<pid_t()> spawn);
    ~InspectionCpuGuard();
    InspectionCpuGuard(const InspectionCpuGuard&) = delete;
    InspectionCpuGuard& operator=(const InspectionCpuGuard&) = delete;

    // Grants CPU time, not elapsed time. Call before work and after a response
    // with a small idle allowance. An already exceeded budget cannot be renewed.
    void grant(std::chrono::milliseconds budget);
    bool alive() const;
    bool exhausted() const;
    bool wait_for_exit(std::chrono::milliseconds timeout);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
