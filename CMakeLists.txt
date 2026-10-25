cmake_minimum_required(VERSION 3.20)
project(smithproxy_spider VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json 3.10 QUIET)
if(NOT nlohmann_json_FOUND)
    add_library(spider_nlohmann_json INTERFACE)
    target_include_directories(spider_nlohmann_json INTERFACE external/nlohmann/include)
    add_library(nlohmann_json::nlohmann_json ALIAS spider_nlohmann_json)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_worker.py" INSPECTION_WORKER_SOURCE)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_api.py" INSPECTION_API_SOURCE)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_h2.py" INSPECTION_H2_SOURCE)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_hold.py" INSPECTION_HOLD_SOURCE)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_language.py" INSPECTION_LANGUAGE_SOURCE)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_sandbox.py" INSPECTION_SANDBOX_SOURCE)
set(INSPECTION_WORKER_SOURCE "${INSPECTION_API_SOURCE}\n${INSPECTION_H2_SOURCE}\n${INSPECTION_HOLD_SOURCE}\n${INSPECTION_LANGUAGE_SOURCE}\n${INSPECTION_SANDBOX_SOURCE}\n${INSPECTION_WORKER_SOURCE}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/inspection_hold.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/inspection_h2.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/inspection_worker.py src/inspection_api.py src/inspection_language.py src/inspection_sandbox.py tools/generate-inspection-schema.py)
configure_file(src/inspection_worker.hpp.in generated/inspection_worker.hpp @ONLY)
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate-inspection-schema.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_api.py" "${CMAKE_CURRENT_BINARY_DIR}/generated/inspection_schema.hpp"
    COMMAND_ERROR_IS_FATAL ANY)

add_library(spider_protocol
    src/binary_envelope.cpp
)
target_include_directories(spider_protocol PUBLIC src)
target_link_libraries(spider_protocol PUBLIC nlohmann_json::nlohmann_json)
target_compile_options(spider_protocol PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_library(spider_core
    src/inspection.cpp
    src/inspection_pool.cpp
    src/collection.cpp
    src/decision_broker.cpp
    src/content_decoding_enrichment.cpp
    src/enrichment.cpp
    src/http2_enrichment.cpp
    src/session_filter.cpp
    src/session_store.cpp
    src/smithproxy_client.cpp
    src/smithproxy_manager.cpp
    src/webhook.cpp
)
target_include_directories(spider_core PUBLIC src)
target_include_directories(spider_core PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(spider_core PRIVATE SPIDER_PYTHON="${Python3_EXECUTABLE}")
target_link_libraries(spider_core PUBLIC spider_protocol nlohmann_json::nlohmann_json
    PkgConfig::CURL PkgConfig::NGHTTP2)
target_link_libraries(spider_core PUBLIC ZLIB::ZLIB)
target_compile_options(spider_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(smithproxy-spider
    src/main.cpp
    src/http_server.cpp
    src/websocket_hub.cpp
)
target_include_directories(smithproxy-spider PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
    src
    external/lmhpp/include
)
target_link_libraries(smithproxy-spider PRIVATE spider_core PkgConfig::MICROHTTPD OpenSSL::Crypto)
target_compile_options(smithproxy-spider PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

include(CTest)
if(BUILD_TESTING)
    add_executable(inspection_tests tests/inspection_test.cpp)
    target_link_libraries(inspection_tests PRIVATE spider_core)
    target_compile_options(inspection_tests PRIVATE -UNDEBUG)
    add_test(NAME inspection_tests COMMAND inspection_tests)
    add_test(NAME inspection_api_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_api_test.py)
    add_test(NAME inspection_cookbook_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_cookbook_test.py)
    set_tests_properties(inspection_cookbook_tests PROPERTIES TIMEOUT 45)
    add_test(NAME inspection_parts_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_parts_test.py)
    add_test(NAME inspection_h2_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_h2_test.py)
    add_test(NAME inspection_hold_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_hold_test.py)
    add_test(NAME inspection_h1_corpus_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_h1_corpus_test.py)
    add_test(NAME inspection_h2_corpus_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_h2_corpus_test.py)
    set_tests_properties(inspection_h1_corpus_tests inspection_h2_corpus_tests
                        PROPERTIES TIMEOUT 30)
    add_executable(inspection_hold_live_tests tests/inspection_hold_live_test.cpp)
    target_link_libraries(inspection_hold_live_tests PRIVATE spider_core)
    target_compile_options(inspection_hold_live_tests PRIVATE -UNDEBUG)
    add_test(NAME inspection_hold_live_tests COMMAND inspection_hold_live_tests)
    set_tests_properties(inspection_hold_live_tests PROPERTIES TIMEOUT 30)
    add_test(NAME inspection_language_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_language_test.py)
    add_test(NAME inspection_storage_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_storage_test.py)
    add_test(NAME inspection_sandbox_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_sandbox_test.py)
    set_tests_properties(inspection_sandbox_tests PROPERTIES TIMEOUT 45)
    add_test(NAME frontend_server_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/frontend_server_test.py)
    add_test(NAME webhook_benchmark_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/webhook_benchmark_test.py)
    set_tests_properties(webhook_benchmark_tests PROPERTIES TIMEOUT 15)
    add_executable(inspection_instances_tests tests/inspection_instances_test.cpp)
    target_link_libraries(inspection_instances_tests PRIVATE spider_core)
    target_compile_options(inspection_instances_tests PRIVATE -UNDEBUG)
    add_test(NAME inspection_instances_tests COMMAND inspection_instances_tests)
    add_executable(inspection_pool_tests tests/inspection_pool_test.cpp)
    target_link_libraries(inspection_pool_tests PRIVATE spider_core)
    target_compile_options(inspection_pool_tests PRIVATE -UNDEBUG)
    add_test(NAME inspection_pool_tests COMMAND inspection_pool_tests)
    set_tests_properties(inspection_pool_tests PROPERTIES TIMEOUT 45)
    add_executable(heavy_traffic_tests tests/heavy_traffic_test.cpp)
    target_link_libraries(heavy_traffic_tests PRIVATE spider_core)
    target_compile_options(heavy_traffic_tests PRIVATE -UNDEBUG)
    add_test(NAME heavy_traffic_tests COMMAND heavy_traffic_tests)
    add_executable(capture_library_tests tests/capture_library_test.cpp)
    target_link_libraries(capture_library_tests PRIVATE spider_core)
    target_compile_options(capture_library_tests PRIVATE -UNDEBUG)
    add_test(NAME capture_library_tests COMMAND capture_library_tests)
    set_tests_properties(inspection_instances_tests PROPERTIES TIMEOUT 45)
    set_tests_properties(inspection_tests PROPERTIES TIMEOUT 15)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_executable(spider_tests tests/session_store_test.cpp)
    target_link_libraries(spider_tests PRIVATE spider_core)
    # The test harness uses assert() for both checks and test fixture setup.
    # Keep those expressions active when the project is built in Release mode.
    target_compile_options(spider_tests PRIVATE -UNDEBUG)
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
