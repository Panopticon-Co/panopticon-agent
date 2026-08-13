find_package(tinyxml2 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(officer-query
    src/main.cpp
    src/event_log_reader.cpp
    src/sysmon_parser.cpp
)

target_include_directories(officer-query PRIVATE include)
target_compile_features(officer-query PRIVATE cxx_std_20)
target_link_libraries(officer-query PRIVATE
    wevtapi
    tinyxml2::tinyxml2
    nlohmann_json::nlohmann_json
)

add_custom_command(
    TARGET officer-query
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:tinyxml2::tinyxml2>
            $<TARGET_FILE_DIR:officer-query>
)

if(MSVC)
    target_compile_options(officer-query PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

if(BUILD_TESTING)
    add_executable(officer-tests
        tests/parser_tests.cpp
        src/sysmon_parser.cpp
    )

    target_include_directories(officer-tests PRIVATE include)
    target_compile_features(officer-tests PRIVATE cxx_std_20)
    target_link_libraries(officer-tests PRIVATE tinyxml2::tinyxml2)
    add_custom_command(
        TARGET officer-tests
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:tinyxml2::tinyxml2>
                $<TARGET_FILE_DIR:officer-tests>
    )
    target_compile_definitions(
        officer-tests
        PRIVATE OFFICER_QUERY_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures"
    )

    if(MSVC)
        target_compile_options(officer-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()

    add_test(NAME officer-query-parser-tests COMMAND officer-tests)
    add_test(NAME officer-query-cli-help COMMAND officer-query --help)
    add_test(NAME officer-query-cli-invalid-limit COMMAND officer-query --limit 0)
    set_tests_properties(officer-query-cli-invalid-limit PROPERTIES WILL_FAIL TRUE)
    add_test(NAME officer-query-cli-invalid-event-id COMMAND officer-query --event-id 999)
    set_tests_properties(officer-query-cli-invalid-event-id PROPERTIES WILL_FAIL TRUE)
endif()
