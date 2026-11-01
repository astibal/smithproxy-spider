#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace spider {

enum class AuthStatus { accepted, rejected, unavailable };

struct AuthResult {
    AuthStatus status{AuthStatus::unavailable};
    std::string identity;
    std::vector<std::string> groups;
};

// Host-owned transport. Script workers never receive a socket or permission
// to create one. Configuration is immutable and each call owns its connection.
class AuthBrokerClient {
public:
    explicit AuthBrokerClient(std::string socket_path, long timeout_ms = 1500);
    AuthResult verify(std::string_view username, std::string_view password) const;

private:
    std::string socket_path_;
    long timeout_ms_;
};

} // namespace spider
