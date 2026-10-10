#pragma once

#include "smithproxy_client.hpp"

#include <atomic>
#include <mutex>
#include <thread>

namespace spider {

class SessionStore;

class SmithproxyManager {
public:
    explicit SmithproxyManager(SessionStore& store);
    ~SmithproxyManager();

    SmithproxyManager(const SmithproxyManager&) = delete;
    SmithproxyManager& operator=(const SmithproxyManager&) = delete;

    void configure(SmithproxyConfig config);
    void stop();

private:
    SessionStore& store_;
    std::mutex mutex_;
    std::atomic_bool client_stop_{true};
    std::thread worker_;
};

} // namespace spider
