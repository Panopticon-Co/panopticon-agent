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
