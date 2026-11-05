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
set(ADDON_WORKER_MODULE_MANIFEST
    "${CMAKE_CURRENT_SOURCE_DIR}/src/addon_worker_modules.txt")
file(STRINGS "${ADDON_WORKER_MODULE_MANIFEST}" ADDON_WORKER_MODULE_NAMES)
set(ADDON_WORKER_MODULES)
foreach(module_name IN LISTS ADDON_WORKER_MODULE_NAMES)
    if(NOT module_name MATCHES "^[A-Za-z_][A-Za-z0-9_]*\\.py$")
        message(FATAL_ERROR "Invalid addon worker module in manifest: ${module_name}")
    endif()
    list(APPEND ADDON_WORKER_MODULES "src/${module_name}")
endforeach()
set(ADDON_WORKER_ARGUMENTS)
foreach(module IN LISTS ADDON_WORKER_MODULES)
    list(APPEND ADDON_WORKER_ARGUMENTS --module "${CMAKE_CURRENT_SOURCE_DIR}/${module}")
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${ADDON_WORKER_MODULE_MANIFEST}" ${ADDON_WORKER_MODULES})
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/pack-inspection-worker.py"
    --arguments-json
    ${ADDON_WORKER_ARGUMENTS}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_api.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_h2.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_hold.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_chunked.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_translate.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_language.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_sandbox.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/inspection_worker.py"
    OUTPUT_VARIABLE INSPECTION_WORKER_ARGUMENT_JSON RESULT_VARIABLE WORKER_PACK_RESULT)
if(NOT WORKER_PACK_RESULT EQUAL 0)
    message(FATAL_ERROR "Cannot package inspection worker")
endif()
string(JSON INSPECTION_WORKER_ARGUMENT_COUNT LENGTH "${INSPECTION_WORKER_ARGUMENT_JSON}")
if(INSPECTION_WORKER_ARGUMENT_COUNT LESS 3)
    message(FATAL_ERROR "Inspection worker package has no payload")
endif()
string(JSON INSPECTION_WORKER_LOADER GET "${INSPECTION_WORKER_ARGUMENT_JSON}" 0)
math(EXPR INSPECTION_WORKER_LAST_ARGUMENT "${INSPECTION_WORKER_ARGUMENT_COUNT} - 1")
set(INSPECTION_WORKER_DATA_ARGUMENTS "")
foreach(index RANGE 1 ${INSPECTION_WORKER_LAST_ARGUMENT})
    string(JSON argument GET "${INSPECTION_WORKER_ARGUMENT_JSON}" ${index})
    string(APPEND INSPECTION_WORKER_DATA_ARGUMENTS
        "    R\"SPIDER_ARG(${argument})SPIDER_ARG\",\n")
endforeach()
math(EXPR INSPECTION_WORKER_DATA_ARGUMENT_COUNT
    "${INSPECTION_WORKER_ARGUMENT_COUNT} - 1")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS tools/pack-inspection-worker.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/inspection_translate.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/inspection_hold.py)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/inspection_chunked.py)
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

add_library(spider_auth src/auth_broker.cpp)
target_include_directories(spider_auth PUBLIC src)
target_link_libraries(spider_auth PUBLIC PkgConfig::CURL nlohmann_json::nlohmann_json)
target_compile_options(spider_auth PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_library(spider_core
    src/inspection.cpp
    src/inspection_pool.cpp
    src/inspection_cpu_guard.cpp
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
target_link_libraries(spider_core PUBLIC spider_auth spider_protocol nlohmann_json::nlohmann_json
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
    add_executable(addon_selection_tests tests/addon_selection_test.cpp)
    target_link_libraries(addon_selection_tests PRIVATE spider_core)
    target_compile_options(addon_selection_tests PRIVATE -UNDEBUG)
    add_test(NAME addon_selection_tests COMMAND addon_selection_tests)
    set_tests_properties(addon_selection_tests PROPERTIES TIMEOUT 20)
    add_executable(addon_deployment_tests tests/addon_deployment_test.cpp)
    target_link_libraries(addon_deployment_tests PRIVATE spider_core)
    target_compile_options(addon_deployment_tests PRIVATE -UNDEBUG)
    add_test(NAME addon_deployment_tests COMMAND addon_deployment_tests)
    set_tests_properties(addon_deployment_tests PROPERTIES TIMEOUT 30)
    add_executable(inspection_cpu_guard_tests tests/inspection_cpu_guard_test.cpp)
    target_link_libraries(inspection_cpu_guard_tests PRIVATE spider_core)
    target_compile_options(inspection_cpu_guard_tests PRIVATE -UNDEBUG)
    add_test(NAME inspection_cpu_guard_tests COMMAND inspection_cpu_guard_tests)
    set_tests_properties(inspection_cpu_guard_tests PROPERTIES TIMEOUT 15)
    add_test(NAME addon_loader_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_loader_test.py)
    add_test(NAME addon_contentviews_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_contentviews_test.py)
    add_test(NAME addon_http_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_http_test.py)
    add_test(NAME addon_message_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_message_test.py)
    add_test(NAME addon_flow_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_flow_test.py)
    add_test(NAME addon_flow_state_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_flow_state_test.py)
    add_test(NAME addon_public_surface_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_public_surface_test.py)
    add_test(NAME addon_official_examples_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_official_examples_test.py)
    add_test(NAME addon_websocket_events_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_websocket_events_test.py)
    add_test(NAME addon_websocket_control_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_websocket_control_contract_test.py)
    add_test(NAME addon_websocket_error_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_websocket_error_contract_test.py)
    add_test(NAME addon_websocket_concurrent_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_websocket_concurrent_contract_test.py)
    add_test(NAME addon_websocket_compression_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_websocket_compression_contract_test.py)
    add_test(NAME addon_dns_events_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_events_test.py)
    add_test(NAME addon_dns_forward_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_forward_contract_test.py)
    add_test(NAME addon_dns_error_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_error_contract_test.py)
    add_test(NAME addon_dns_tcp_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_tcp_contract_test.py)
    add_test(NAME addon_dns_concurrent_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_concurrent_contract_test.py)
    add_test(NAME addon_dns_malformed_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_malformed_contract_test.py)
    add_test(NAME addon_dns_local_error_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_local_error_contract_test.py)
    add_test(NAME addon_dns_complex_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_complex_contract_test.py)
    add_test(NAME addon_dns_rdata_compression_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_rdata_compression_contract_test.py)
    add_test(NAME addon_dns_control_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_control_contract_test.py)
    add_test(NAME addon_intercept_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_intercept_contract_test.py)
    add_test(NAME addon_termination_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_termination_contract_test.py)
    add_test(NAME addon_streaming_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_streaming_contract_test.py)
    add_test(NAME addon_response_pipeline_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_response_pipeline_contract_test.py)
    add_test(NAME addon_reroute_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_reroute_contract_test.py)
    add_test(NAME addon_transport_reference_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_transport_reference_contract_test.py)
    add_test(NAME addon_corpus_inventory_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_corpus_inventory_test.py)
    add_test(NAME addon_transport_envelope_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_transport_envelope_test.py)
    add_test(NAME addon_clean_room_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_clean_room_test.py)
    add_test(NAME addon_serializable_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_serializable_test.py)
    add_test(NAME addon_io_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_io_test.py)
    add_test(NAME addon_concurrent_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_concurrent_test.py)
    add_test(NAME addon_connection_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_connection_test.py)
    add_test(NAME addon_encoding_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_encoding_test.py)
    add_test(NAME addon_human_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_human_test.py)
    add_test(NAME addon_typecheck_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_typecheck_test.py)
    add_test(NAME addon_signal_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_signal_test.py)
    add_test(NAME addon_socks5_auth_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_socks5_auth_test.py)
    add_test(NAME addon_socks5_events_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_socks5_events_test.py)
    add_test(NAME addon_connect_transport_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_connect_transport_contract_test.py)
    add_test(NAME addon_connect_worker_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_connect_worker_test.py)
    add_test(NAME addon_quic_native_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_quic_native_test.py)
    add_test(NAME addon_tls_native_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_tls_native_test.py)
    add_test(NAME addon_server_native_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_server_native_test.py)
    add_test(NAME addon_connect_native_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_connect_native_test.py)
    add_test(NAME addon_connect_events_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_connect_events_test.py)
    add_test(NAME addon_raw_control_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_raw_control_contract_test.py)
    add_test(NAME addon_raw_error_contract_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_raw_error_contract_test.py)
    add_test(NAME addon_tls_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_tls_test.py)
    add_test(NAME addon_tls_hooks_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_tls_hooks_test.py)
    add_test(NAME addon_quic_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_quic_test.py)
    add_test(NAME addon_server_hooks_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_server_hooks_test.py)
    add_test(NAME addon_http_hooks_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_http_hooks_test.py)
    add_test(NAME addon_protocol_hooks_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_protocol_hooks_test.py)
    add_test(NAME addon_version_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_version_test.py)
    add_test(NAME addon_http_header_helpers_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_http_header_helpers_test.py)
    add_test(NAME addon_http_validate_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_http_validate_test.py)
    add_test(NAME addon_multipart_helpers_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_multipart_helpers_test.py)
    add_test(NAME addon_status_codes_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_status_codes_test.py)
    add_test(NAME addon_cookie_helpers_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_cookie_helpers_test.py)
    add_test(NAME addon_url_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_url_test.py)
    add_test(NAME addon_server_spec_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_server_spec_test.py)
    add_test(NAME addon_runtime_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_runtime_test.py)
    add_test(NAME addon_options_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_options_test.py)
    add_test(NAME addon_sandbox_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_sandbox_test.py)
    set_tests_properties(addon_sandbox_tests PROPERTIES TIMEOUT 30)
    option(SPIDER_TEST_ADDON_COMPAT "Run addon contracts (requires tests/requirements-addon.txt)" ON)
    if(SPIDER_TEST_ADDON_COMPAT)
        execute_process(COMMAND ${Python3_EXECUTABLE} -c "import h2.connection, hpack, brotli, zstandard, wsproto.frame_protocol; from cryptography import x509; assert tuple(int(item) for item in brotli.__version__.split('.')[:3]) >= (1, 2, 1); assert hasattr(x509.Certificate, 'not_valid_after_utc')"
                        RESULT_VARIABLE ADDON_TEST_IMPORT_RESULT ERROR_QUIET)
        if(NOT ADDON_TEST_IMPORT_RESULT EQUAL 0)
            message(FATAL_ERROR "Addon protocol tests require tests/requirements-addon.txt; no mitmproxy package is needed")
        endif()
        add_test(NAME addon_parts_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_parts_test.py)
        add_test(NAME addon_h2_suspend_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_h2_suspend_test.py)
        set_tests_properties(addon_h2_suspend_tests PROPERTIES TIMEOUT 45)
        add_test(NAME addon_h1_suspend_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_h1_suspend_test.py)
        add_test(NAME addon_raw_events_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_raw_events_test.py)
        add_test(NAME addon_command_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_command_test.py)
        add_test(NAME addon_log_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_log_test.py)
        add_test(NAME addon_flowfilter_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_flowfilter_test.py)
        add_test(NAME addon_strutils_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_strutils_test.py)
        add_test(NAME addon_certs_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_certs_test.py)
    add_test(NAME addon_websocket_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_websocket_test.py)
    add_test(NAME addon_dns_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_dns_test.py)
        add_test(NAME addon_worker_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_worker_test.py --group runtime)
        add_test(NAME addon_worker_http1_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_worker_test.py --group http1)
        add_test(NAME addon_worker_http2_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_worker_test.py --group http2)
        add_test(NAME inspection_translate_message_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_message_test.py)
        set_tests_properties(addon_parts_tests addon_raw_events_tests addon_dns_tests
                             addon_worker_tests addon_worker_http1_tests addon_worker_http2_tests inspection_translate_message_tests
                             PROPERTIES TIMEOUT 45 LABELS "addon;protocol")
    endif()
    add_executable(inspection_tests tests/inspection_test.cpp)
    target_link_libraries(inspection_tests PRIVATE spider_core)
    target_compile_options(inspection_tests PRIVATE -UNDEBUG)
    add_test(NAME inspection_tests COMMAND inspection_tests)
    add_test(NAME inspection_api_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_api_test.py)
    add_test(NAME hook_examples_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/hook_examples_test.py)
    set_tests_properties(hook_examples_tests PROPERTIES TIMEOUT 45)

    add_test(NAME inspection_cookbook_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_cookbook_test.py)
    set_tests_properties(inspection_cookbook_tests PROPERTIES TIMEOUT 45)
    option(SPIDER_TEST_TRANSLATE_POC "Enable isolated python-hpack translate experiment" OFF)
    option(SPIDER_TEST_FLOW_CONTROL_POC "Enable independent hyper-h2 flow-control design probes" OFF)
    if(SPIDER_TEST_FLOW_CONTROL_POC)
        execute_process(COMMAND ${Python3_EXECUTABLE} -c "import h2.connection"
                        RESULT_VARIABLE H2_IMPORT_RESULT)
        if(NOT H2_IMPORT_RESULT EQUAL 0)
            message(FATAL_ERROR "Flow-control probes require python-h2; production does not")
        endif()
        add_test(NAME inspection_translate_flow_control_tests
                 COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_flow_control_test.py)
        set_tests_properties(inspection_translate_flow_control_tests
                             PROPERTIES TIMEOUT 30 LABELS "experimental;protocol")
        add_test(NAME inspection_translate_windows_easy_tests
                 COMMAND Python3::Interpreter
                         ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_windows_test.py
                         WindowsTests)
        add_test(NAME inspection_translate_windows_expert_tests
                 COMMAND Python3::Interpreter
                         ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_windows_test.py
                         ExpertWindowsTests)
        set_tests_properties(
            inspection_translate_windows_easy_tests
            inspection_translate_windows_expert_tests
            PROPERTIES TIMEOUT 45 LABELS "experimental;protocol"
        )
    endif()
    set(SPIDER_E2E_SMITHPROXY_SOURCE "" CACHE PATH "Smithproxy source for optional real proxy E2E")
    set(SPIDER_E2E_SMITHPROXY_BINARY "" CACHE FILEPATH "Built Smithproxy with webhook control/sequence support")
    option(SPIDER_TEST_H1_E2E "Run H1 suspension against real Smithproxy and Spider" OFF)
    if(SPIDER_TEST_H1_E2E)
        if(NOT SPIDER_TEST_ADDON_COMPAT OR NOT SPIDER_E2E_SMITHPROXY_SOURCE OR NOT SPIDER_E2E_SMITHPROXY_BINARY)
            message(FATAL_ERROR "H1 E2E requires addon tests and explicit Smithproxy source/binary paths")
        endif()
        foreach(scenario peer both kill fragmented pipeline encoded)
            add_test(NAME inspection_h1_suspension_e2e_${scenario}
                COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/h1_suspension_e2e.py
                    --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                    --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                    --spider $<TARGET_FILE:smithproxy-spider> --scenario ${scenario})
            set_tests_properties(inspection_h1_suspension_e2e_${scenario}
                PROPERTIES TIMEOUT 90 LABELS "integration" RUN_SERIAL TRUE)
        endforeach()
    endif()

    if(SPIDER_TEST_TRANSLATE_POC)
        execute_process(COMMAND ${Python3_EXECUTABLE} -c "import hpack"
                        RESULT_VARIABLE HPACK_IMPORT_RESULT)
        if(NOT HPACK_IMPORT_RESULT EQUAL 0)
            message(FATAL_ERROR "Translate POC tests require python-hpack; production does not")
        endif()
        add_test(NAME inspection_translate_poc_tests
                 COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_poc_test.py)
        set_tests_properties(inspection_translate_poc_tests PROPERTIES TIMEOUT 30 LABELS "experimental")
        add_executable(inspection_translate_live_tests tests/inspection_translate_live_test.cpp)
        target_link_libraries(inspection_translate_live_tests PRIVATE spider_core)
        target_compile_options(inspection_translate_live_tests PRIVATE -UNDEBUG)
        add_test(NAME inspection_translate_live_tests COMMAND inspection_translate_live_tests)
        set_tests_properties(inspection_translate_live_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_translate_worker_tests
                 COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_worker_test.py)
        set_tests_properties(inspection_translate_worker_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_translate_hold_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_hold_test.py)
        set_tests_properties(inspection_translate_hold_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_translate_part_buffers_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_part_buffers_test.py)
        set_tests_properties(inspection_translate_part_buffers_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_suspend_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_suspend_test.py)
        set_tests_properties(inspection_suspend_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_protocol_state_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_protocol_state_test.py)
        set_tests_properties(inspection_protocol_state_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_protocol_worker_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_protocol_worker_test.py)
        set_tests_properties(inspection_protocol_worker_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_translate_settings_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_settings_test.py)
        set_tests_properties(inspection_translate_settings_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_translate_data_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_data_test.py)
        set_tests_properties(inspection_translate_data_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        add_test(NAME inspection_translate_push_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_translate_push_test.py)
        set_tests_properties(inspection_translate_push_tests PROPERTIES TIMEOUT 45 LABELS "experimental")
        if(SPIDER_E2E_SMITHPROXY_SOURCE AND SPIDER_E2E_SMITHPROXY_BINARY)
            if(SPIDER_TEST_FLOW_CONTROL_POC)
                foreach(safety easy expert)
                    add_test(NAME inspection_translate_e2e_windows_${safety}
                        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                            --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                            --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                            --spider $<TARGET_FILE:smithproxy-spider> --windows --safety ${safety})
                    set_tests_properties(inspection_translate_e2e_windows_${safety}
                        PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
                    add_test(NAME inspection_translate_e2e_goaway_${safety}
                        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                            --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                            --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                            --spider $<TARGET_FILE:smithproxy-spider> --goaway --safety ${safety})
                    set_tests_properties(inspection_translate_e2e_goaway_${safety}
                        PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
                    foreach(transport json sxbn)
                        set(reserved_transport_args)
                        if(transport STREQUAL "json")
                            list(APPEND reserved_transport_args --json)
                        endif()
                        add_test(NAME inspection_translate_e2e_reserved_${transport}_${safety}
                            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                                --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                                --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                                --spider $<TARGET_FILE:smithproxy-spider> --reserved --safety ${safety}
                                ${reserved_transport_args})
                        set_tests_properties(inspection_translate_e2e_reserved_${transport}_${safety}
                            PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
                    endforeach()
                endforeach()
            endif()
            foreach(failure exception missing-translate)
                add_test(NAME inspection_translate_e2e_${failure}
                    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                        --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                        --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                        --spider $<TARGET_FILE:smithproxy-spider> --failure ${failure})
                set_tests_properties(inspection_translate_e2e_${failure}
                    PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
            endforeach()
            add_test(NAME inspection_translate_e2e_fragmented
                COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                    --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                    --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                    --spider $<TARGET_FILE:smithproxy-spider> --fragmented)
            set_tests_properties(inspection_translate_e2e_fragmented
                PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
            add_test(NAME inspection_translate_e2e_settings
                COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                    --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                    --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                    --spider $<TARGET_FILE:smithproxy-spider> --fragmented --settings)
            set_tests_properties(inspection_translate_e2e_settings
                PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
            add_test(NAME inspection_translate_e2e_policy
                COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                    --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                    --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                    --spider $<TARGET_FILE:smithproxy-spider> --fragmented --policy)
            set_tests_properties(inspection_translate_e2e_policy
                PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
            add_test(NAME inspection_translate_e2e_data
                COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                    --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                    --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                    --spider $<TARGET_FILE:smithproxy-spider> --fragmented --data)
            set_tests_properties(inspection_translate_e2e_data
                PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
            add_test(NAME inspection_translate_e2e_expert
                COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/translate_e2e.py
                    --smithproxy-source ${SPIDER_E2E_SMITHPROXY_SOURCE}
                    --smithproxy ${SPIDER_E2E_SMITHPROXY_BINARY}
                    --spider $<TARGET_FILE:smithproxy-spider> --fragmented --data --settings --safety expert)
            set_tests_properties(inspection_translate_e2e_expert
                PROPERTIES TIMEOUT 90 LABELS "experimental;integration" RUN_SERIAL TRUE)
        endif()
    endif()
    add_test(NAME inspection_parts_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_parts_test.py)
    foreach(safety easy expert)
        add_test(NAME inspection_safety_${safety}_tests
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_safety_test.py ${safety})
        set_tests_properties(inspection_safety_${safety}_tests PROPERTIES TIMEOUT 45)
    endforeach()
    add_test(NAME inspection_worker_bootstrap_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/worker_bootstrap_test.py)
    add_test(NAME inspection_digest_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_digest_test.py)
    add_test(NAME inspection_h2_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_h2_test.py)
    add_test(NAME inspection_hold_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_hold_test.py)
    add_test(NAME inspection_part_buffers_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_part_buffers_test.py)
    add_test(NAME inspection_chunked_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_chunked_test.py)
    add_test(NAME inspection_h2_body_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_h2_body_test.py)
    add_test(NAME inspection_compression_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_compression_test.py)
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
    add_test(NAME inspection_setup_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_setup_test.py)
    add_test(NAME inspection_storage_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/inspection_storage_test.py)
    add_executable(authentication_host_tests tests/authentication_host_test.cpp)
    target_link_libraries(authentication_host_tests PRIVATE spider_core)
    target_compile_options(authentication_host_tests PRIVATE -UNDEBUG)
    add_test(NAME authentication_host_tests COMMAND authentication_host_tests)
    set_tests_properties(authentication_host_tests PROPERTIES TIMEOUT 30)
    add_test(NAME addon_authentication_tests
        COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/addon_authentication_test.py)
    set_tests_properties(addon_authentication_tests PROPERTIES TIMEOUT 45)
    add_test(NAME authentication_worker_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/authentication_worker_test.py)
    set_tests_properties(authentication_worker_tests PROPERTIES TIMEOUT 30)
    add_executable(native_lifecycle_host_tests tests/native_lifecycle_host_test.cpp)
    target_link_libraries(native_lifecycle_host_tests PRIVATE spider_core)
    target_compile_options(native_lifecycle_host_tests PRIVATE -UNDEBUG)
    add_test(NAME native_lifecycle_host_tests COMMAND native_lifecycle_host_tests)
    set_tests_properties(native_lifecycle_host_tests PROPERTIES TIMEOUT 30)
    add_test(NAME native_lifecycle_tests
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/native_lifecycle_test.py)
    set_tests_properties(native_lifecycle_tests PROPERTIES TIMEOUT 45)
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
    # This suite starts many isolated Python workers; a clean baseline takes
    # about 51 seconds on the current test host, before any deliberate load.
    set_tests_properties(inspection_instances_tests PROPERTIES TIMEOUT 90)
    # This integration test intentionally exercises repeated worker startup and
    # teardown. Debug builds are close to 15 seconds on normal developer hosts,
    # so leave scheduling headroom without weakening any internal deadline.
    set_tests_properties(inspection_tests PROPERTIES TIMEOUT 30)
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

# Host authentication is independent of addon imports and worker permissions.
if(BUILD_TESTING)
    add_executable(auth_broker_probe tests/auth_broker_probe.cpp)
    target_link_libraries(auth_broker_probe PRIVATE spider_auth)
    add_test(NAME auth_broker_tests COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/auth_broker_test.py
        --probe $<TARGET_FILE:auth_broker_probe>)
    set_tests_properties(auth_broker_tests PROPERTIES TIMEOUT 30)

    set(SPIDER_AUTH_BROKER_EXECUTABLE "" CACHE FILEPATH "Keyway executable for integration tests")
    set(SPIDER_AUTH_PAM_TEST_MODULE "" CACHE FILEPATH "Keyway test-only PAM module")
    if(SPIDER_AUTH_BROKER_EXECUTABLE AND SPIDER_AUTH_PAM_TEST_MODULE)
        add_test(NAME auth_broker_pam_tests COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/auth_broker_test.py
            --probe $<TARGET_FILE:auth_broker_probe>
            --broker ${SPIDER_AUTH_BROKER_EXECUTABLE}
            --pam-module ${SPIDER_AUTH_PAM_TEST_MODULE})
        set_tests_properties(auth_broker_pam_tests PROPERTIES TIMEOUT 45)
    endif()
    add_test(NAME auth_broker_cli_tests COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/auth_broker_cli_test.py
        $<TARGET_FILE:smithproxy-spider>)
    set_tests_properties(auth_broker_cli_tests PROPERTIES TIMEOUT 30)
endif()
