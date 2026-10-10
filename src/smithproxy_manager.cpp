#include "smithproxy_manager.hpp"

#include "session_store.hpp"

#include <utility>

namespace spider {

SmithproxyManager::SmithproxyManager(SessionStore& store) : store_(store) {}

SmithproxyManager::~SmithproxyManager() { stop(); }

void SmithproxyManager::configure(SmithproxyConfig config) {
    auto lock = std::scoped_lock(mutex_);
    client_stop_.store(true);
    if (worker_.joinable()) worker_.join();

    client_stop_.store(false);
    worker_ = std::thread([this, config = std::move(config)]() mutable {
        SmithproxyClient(std::move(config), store_).run(client_stop_);
    });
}

void SmithproxyManager::stop() {
    auto lock = std::scoped_lock(mutex_);
    client_stop_.store(true);
    if (worker_.joinable()) worker_.join();
}

} // namespace spider
