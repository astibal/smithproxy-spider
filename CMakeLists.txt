cmake_minimum_required(VERSION 3.20)
project(smithproxy_spider VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
find_package(nlohmann_json 3.10 QUIET)
if(NOT nlohmann_json_FOUND)
    add_library(spider_nlohmann_json INTERFACE)
    target_include_directories(spider_nlohmann_json INTERFACE external/nlohmann/include)
    add_library(nlohmann_json::nlohmann_json ALIAS spider_nlohmann_json)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(spider_protocol
    src/binary_envelope.cpp
)
target_include_directories(spider_protocol PUBLIC src)
target_link_libraries(spider_protocol PUBLIC nlohmann_json::nlohmann_json)
target_compile_options(spider_protocol PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_library(spider_core
    src/decision_broker.cpp
    src/session_filter.cpp
    src/session_store.cpp
    src/smithproxy_client.cpp
    src/smithproxy_manager.cpp
    src/webhook.cpp
)
target_include_directories(spider_core PUBLIC src)
target_link_libraries(spider_core PUBLIC spider_protocol nlohmann_json::nlohmann_json PkgConfig::CURL)
target_compile_options(spider_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(smithproxy-spider
    src/main.cpp
    src/http_server.cpp
    src/websocket_hub.cpp
)
target_include_directories(smithproxy-spider PRIVATE
    src
    external/lmhpp/include
)
target_link_libraries(smithproxy-spider PRIVATE spider_core PkgConfig::MICROHTTPD OpenSSL::Crypto)
target_compile_options(smithproxy-spider PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_executable(spider_tests tests/session_store_test.cpp)
    target_link_libraries(spider_tests PRIVATE spider_core)
    add_test(NAME spider_tests COMMAND spider_tests)
    add_test(NAME spider_chain_test
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_chain.py
                     $<TARGET_FILE:smithproxy-spider>)
    set_tests_properties(spider_chain_test PROPERTIES TIMEOUT 15)
    find_program(NODE_EXECUTABLE node)
    if(NODE_EXECUTABLE)
        add_test(NAME spider_pcapng_test
                 COMMAND ${NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/pcapng_test.js)
        add_test(NAME spider_sxbn_test
                 COMMAND ${NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/sxbn_test.js)
    endif()
endif()

install(TARGETS smithproxy-spider RUNTIME DESTINATION bin)
install(FILES deploy/smithproxy-spider.service DESTINATION lib/systemd/system)
