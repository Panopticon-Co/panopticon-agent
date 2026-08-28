cmake_minimum_required(VERSION 3.20)

project(officer VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(tinyxml2 CONFIG REQUIRED)

add_library(officer-core STATIC
    src/core/entity_id.cpp
    src/pipeline/normalizer.cpp
    src/pipeline/serializer.cpp
)

target_include_directories(officer-core PUBLIC include)
target_compile_features(officer-core PUBLIC cxx_std_20)
target_link_libraries(officer-core
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE bcrypt
)

add_library(officer-collectors STATIC
    src/collectors/etw_process_collector.cpp
    src/collectors/sysmon_event_collector.cpp
    src/collectors/sysmon_process_decoder.cpp
    src/collectors/sysmon_telemetry_decoder.cpp
)

target_include_directories(officer-collectors PUBLIC include)
target_compile_features(officer-collectors PUBLIC cxx_std_20)
target_link_libraries(officer-collectors
    PUBLIC officer-core
    PRIVATE advapi32 tdh wevtapi tinyxml2::tinyxml2
)

add_executable(officer-agent
    src/main.cpp
)

target_link_libraries(officer-agent PRIVATE officer-core officer-collectors advapi32)

add_custom_command(
    TARGET officer-agent
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:tinyxml2::tinyxml2>
            $<TARGET_FILE_DIR:officer-agent>
)

if(MSVC)
    target_compile_options(officer-core PRIVATE /W4 /permissive- /EHsc /utf-8)
    target_compile_options(officer-collectors PRIVATE /W4 /permissive- /EHsc /utf-8)
    target_compile_options(officer-agent PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

if(BUILD_TESTING)
    add_executable(officer-core-tests tests/contract_tests.cpp)
    target_link_libraries(officer-core-tests PRIVATE officer-core)
    target_compile_definitions(
        officer-core-tests
        PRIVATE OFFICER_EVENT_SCHEMA_PATH="${CMAKE_CURRENT_SOURCE_DIR}/schema/event.schema.json"
    )
    if(MSVC)
        target_compile_options(officer-core-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-core-contract-tests COMMAND officer-core-tests)

    add_executable(officer-collector-tests tests/collector_tests.cpp)
    target_link_libraries(officer-collector-tests PRIVATE officer-collectors officer-core)
    target_compile_definitions(
        officer-collector-tests
        PRIVATE
            OFFICER_SYSMON_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/sysmon_process_create.xml"
            OFFICER_SYSMON_NETWORK_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/sysmon_network_connect.xml"
            OFFICER_SYSMON_FILE_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/sysmon_file_create.xml"
            OFFICER_SYSMON_REGISTRY_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/sysmon_registry_set_value.xml"
            OFFICER_SYSMON_IMAGE_LOAD_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/sysmon_image_load.xml"
    )
    add_custom_command(
        TARGET officer-collector-tests
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:tinyxml2::tinyxml2>
                $<TARGET_FILE_DIR:officer-collector-tests>
    )
    if(MSVC)
        target_compile_options(officer-collector-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-live-collector-decoder-tests COMMAND officer-collector-tests)
    add_test(NAME officer-agent-cli-help COMMAND officer-agent --help)
endif()

add_subdirectory(tools/query)
