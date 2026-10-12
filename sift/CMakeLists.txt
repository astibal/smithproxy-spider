pkg_check_modules(HYPERSCAN REQUIRED IMPORTED_TARGET libhs)

add_library(sift_core
    src/engine.cpp
)
target_include_directories(sift_core PUBLIC include)
target_link_libraries(sift_core PUBLIC nlohmann_json::nlohmann_json PkgConfig::HYPERSCAN)
target_compile_options(sift_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(sx-siftd
    src/main.cpp
    src/server.cpp
)
target_include_directories(sx-siftd PRIVATE
    include
    ../src
    ${CMAKE_SOURCE_DIR}/external/lmhpp/include
)
target_link_libraries(sx-siftd PRIVATE
    sift_core spider_protocol PkgConfig::MICROHTTPD nlohmann_json::nlohmann_json)
target_compile_options(sx-siftd PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

if(BUILD_TESTING)
    add_executable(sift_tests tests/engine_tests.cpp)
    target_include_directories(sift_tests PRIVATE ../src)
    target_link_libraries(sift_tests PRIVATE sift_core spider_protocol)
    add_test(NAME sift_tests COMMAND sift_tests)
endif()

install(TARGETS sx-siftd RUNTIME DESTINATION bin)
