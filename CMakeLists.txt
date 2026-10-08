cmake_minimum_required(VERSION 3.20)
project(smithproxy_spider VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
find_package(nlohmann_json 3.10 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(spider_core
    src/session_store.cpp
    src/smithproxy_client.cpp
    src/webhook.cpp
)
target_include_directories(spider_core PUBLIC src)
target_link_libraries(spider_core PUBLIC nlohmann_json::nlohmann_json PkgConfig::CURL)
target_compile_options(spider_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(smithproxy-spider
    src/main.cpp
    src/http_server.cpp
)
target_include_directories(smithproxy-spider PRIVATE
    src
    external/lmhpp/include
)
target_link_libraries(smithproxy-spider PRIVATE spider_core PkgConfig::MICROHTTPD OpenSSL::Crypto)
target_compile_options(smithproxy-spider PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

include(CTest)
if(BUILD_TESTING)
    add_executable(spider_tests tests/session_store_test.cpp)
    target_link_libraries(spider_tests PRIVATE spider_core)
    add_test(NAME spider_tests COMMAND spider_tests)
endif()

install(TARGETS smithproxy-spider RUNTIME DESTINATION bin)
