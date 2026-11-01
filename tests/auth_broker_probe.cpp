// Test-only driver: retain one client across daemon failure and restart.
#include "auth_broker.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

int main(int argc, char** argv) {
    if(argc != 2) {
        return 2;
    }
    try {
        spider::AuthBrokerClient client(argv[1], 250);
        std::string line;
        while(std::getline(std::cin, line)) {
            const auto input = nlohmann::json::parse(line);
            const auto result = client.verify(input.at("username").get<std::string>(),
                                              input.at("password").get<std::string>());
            std::string status = "unavailable";
            if(result.status == spider::AuthStatus::accepted) {
                status = "accepted";
            } else if(result.status == spider::AuthStatus::rejected) {
                status = "rejected";
            }
            std::cout << nlohmann::json{{"status", status}, {"identity", result.identity},
                                        {"groups", result.groups}}.dump() << std::endl;
        }
    } catch(...) {
        return 2;
    }
}
