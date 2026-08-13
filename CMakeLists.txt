cmake_minimum_required(VERSION 3.20)

project(officer VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(nlohmann_json CONFIG REQUIRED)

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

add_executable(officer-agent
    src/main.cpp
)

target_link_libraries(officer-agent PRIVATE officer-core)

if(MSVC)
    target_compile_options(officer-core PRIVATE /W4 /permissive- /EHsc /utf-8)
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
endif()

add_subdirectory(tools/query)
