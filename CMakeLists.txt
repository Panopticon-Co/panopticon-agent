cmake_minimum_required(VERSION 3.20)

project(eyetrace_query VERSION 0.1.0 LANGUAGES CXX)

find_package(tinyxml2 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(eyetrace-query
    src/main.cpp
    src/event_log_reader.cpp
    src/sysmon_parser.cpp
)

target_include_directories(eyetrace-query PRIVATE include)

target_compile_features(eyetrace-query PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(eyetrace-query PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

# winevt.h declares the Windows Event Log API.  Wevtapi.lib provides its
# import-library entries, which the linker uses to resolve the API calls.
target_link_libraries(eyetrace-query PRIVATE
    wevtapi
    tinyxml2::tinyxml2
    nlohmann_json::nlohmann_json
)

enable_testing()

add_executable(parser-tests
    tests/parser_tests.cpp
    src/sysmon_parser.cpp
)

target_include_directories(parser-tests PRIVATE include)
target_compile_features(parser-tests PRIVATE cxx_std_20)
target_link_libraries(parser-tests PRIVATE tinyxml2::tinyxml2)
target_compile_definitions(parser-tests PRIVATE EYETRACE_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")

if(MSVC)
    target_compile_options(parser-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

add_test(NAME parser-tests COMMAND parser-tests)

add_test(NAME cli-help COMMAND eyetrace-query --help)
add_test(NAME cli-invalid-limit COMMAND eyetrace-query --limit 0)
set_tests_properties(cli-invalid-limit PROPERTIES WILL_FAIL TRUE)
add_test(NAME cli-invalid-event-id COMMAND eyetrace-query --event-id 999)
set_tests_properties(cli-invalid-event-id PROPERTIES WILL_FAIL TRUE)
