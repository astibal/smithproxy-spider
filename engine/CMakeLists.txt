add_library(spider_engine_core
    src/engine.cpp
)
target_include_directories(spider_engine_core PUBLIC include)
target_link_libraries(spider_engine_core PUBLIC nlohmann_json::nlohmann_json)
target_compile_options(spider_engine_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(sx-spiderd
    src/main.cpp
    src/server.cpp
)
target_include_directories(sx-spiderd PRIVATE
    include
    ../src
    ${CMAKE_SOURCE_DIR}/external/lmhpp/include
)
target_link_libraries(sx-spiderd PRIVATE
    spider_engine_core spider_protocol PkgConfig::MICROHTTPD nlohmann_json::nlohmann_json)
target_compile_options(sx-spiderd PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

if(BUILD_TESTING)
    add_executable(spider_engine_tests tests/engine_tests.cpp)
    target_include_directories(spider_engine_tests PRIVATE ../src)
    target_link_libraries(spider_engine_tests PRIVATE spider_engine_core spider_protocol)
    add_test(NAME spider_engine_tests COMMAND spider_engine_tests)
endif()

install(TARGETS sx-spiderd RUNTIME DESTINATION bin)
