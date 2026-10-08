cmake_minimum_required(VERSION 3.20)

project(officer VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(tinyxml2 CONFIG REQUIRED)

add_library(officer-core STATIC
    src/core/entity_id.cpp
    src/core/process_instance.cpp
    src/core/process_graph.cpp
    src/health/coverage.cpp
    src/health/state_freshness.cpp
    src/health/source_supervisor.cpp
    src/pipeline/normalizer.cpp
    src/pipeline/endpoint_record.cpp
    src/pipeline/source_facts.cpp
    src/pipeline/raw_handoff.cpp
    src/pipeline/diagnostic_output.cpp
    src/pipeline/serializer.cpp
    src/state/host_inventory.cpp
    src/state/process_inventory.cpp
    src/state/thread_inventory.cpp
    src/state/memory_inventory.cpp
    src/state/process_token.cpp
    src/state/service_inventory.cpp
    src/state/service_triggers.cpp
    src/state/service_security.cpp
    src/state/driver_inventory.cpp
    src/state/socket_inventory.cpp
    src/state/route_inventory.cpp
    src/state/ip_interface.cpp
    src/state/ip_interface_inventory.cpp
    src/state/firewall_profiles.cpp
    src/state/firewall_exclusions.cpp
    src/state/firewall_rules.cpp
    src/state/security_center.cpp
    src/state/defender_status.cpp
    src/state/device_guard.cpp
    src/state/persistence_inventory.cpp
    src/state/scheduled_task_inventory.cpp
    src/state/wmi_subscription_inventory.cpp
    src/state/startup_inventory.cpp
    src/state/identity_inventory.cpp
    src/state/software_inventory.cpp
    src/runtime/service_host.cpp
)

target_include_directories(officer-core PUBLIC include)
target_compile_features(officer-core PUBLIC cxx_std_20)
target_link_libraries(officer-core
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE bcrypt advapi32 iphlpapi ws2_32 netapi32 ole32 oleaut32 wbemuuid taskschd shell32 secur32 wtsapi32 msi tinyxml2::tinyxml2
)

add_library(officer-collectors STATIC
    src/collectors/etw_process_collector.cpp
    src/collectors/process_image_cache.cpp
    src/collectors/sysmon_event_collector.cpp
    src/collectors/sysmon_process_decoder.cpp
    src/collectors/sysmon_telemetry_decoder.cpp
    src/collectors/windows_event_decoder.cpp
    src/collectors/windows_event_log.cpp
    src/collectors/usn_decoder.cpp
    src/collectors/usn_journal.cpp
)

target_include_directories(officer-collectors PUBLIC include)
target_compile_features(officer-collectors PUBLIC cxx_std_20)
target_link_libraries(officer-collectors
    PUBLIC officer-core
    PRIVATE advapi32 tdh wevtapi tinyxml2::tinyxml2
)

add_library(officer-delivery STATIC
    src/delivery/http_client.cpp
    src/delivery/journal.cpp
    src/delivery/spool.cpp
    src/delivery/uploader.cpp
)

target_include_directories(officer-delivery PUBLIC include)
target_compile_features(officer-delivery PUBLIC cxx_std_20)
target_link_libraries(officer-delivery
    PUBLIC officer-core
    PRIVATE winhttp bcrypt winsqlite3 crypt32 advapi32
)

add_library(officer-response STATIC
    src/response/identity.cpp
    src/response/keypair.cpp
    src/response/replay_ledger.cpp
    src/response/command.cpp
    src/response/process_actions.cpp
    src/response/network_evidence.cpp
    src/response/file_evidence.cpp
    src/response/isolation.cpp
    src/response/transport.cpp
)

target_include_directories(officer-response PUBLIC include)
target_compile_features(officer-response PUBLIC cxx_std_20)
target_link_libraries(officer-response
    PUBLIC officer-core officer-delivery
    PRIVATE advapi32 iphlpapi ws2_32 fwpuclnt crypt32
)

add_executable(officer-agent
    src/main.cpp
)

target_link_libraries(officer-agent PRIVATE officer-core officer-collectors officer-delivery officer-response advapi32)

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
    target_compile_options(officer-delivery PRIVATE /W4 /permissive- /EHsc /utf-8)
    target_compile_options(officer-response PRIVATE /W4 /permissive- /EHsc /utf-8)
    target_compile_options(officer-agent PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

if(BUILD_TESTING)
    add_executable(officer-process-graph-tests tests/process_graph_tests.cpp)
    target_link_libraries(officer-process-graph-tests PRIVATE officer-core officer-delivery winsqlite3)
    add_test(NAME officer-process-graph-tests COMMAND officer-process-graph-tests)
    add_executable(officer-device-guard-tests tests/device_guard_tests.cpp)
    target_link_libraries(officer-device-guard-tests PRIVATE officer-core)
    add_test(NAME officer-device-guard-tests COMMAND officer-device-guard-tests)
    add_executable(officer-identity-inventory-tests tests/identity_inventory_tests.cpp)
    add_executable(officer-software-inventory-tests tests/software_inventory_tests.cpp)
    add_executable(officer-service-host-tests tests/service_host_tests.cpp)
    add_executable(officer-process-lifecycle-tests tests/process_lifecycle_tests.cpp)
    target_link_libraries(officer-process-lifecycle-tests PRIVATE officer-core officer-collectors tdh)
    add_test(NAME officer-process-lifecycle-tests COMMAND officer-process-lifecycle-tests)
    target_link_libraries(officer-service-host-tests PRIVATE officer-core)
    add_test(NAME officer-service-host-tests COMMAND officer-service-host-tests)
    target_link_libraries(officer-software-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-software-inventory-tests COMMAND officer-software-inventory-tests)
    set_tests_properties(officer-software-inventory-tests PROPERTIES TIMEOUT 90)
    target_link_libraries(officer-identity-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-identity-inventory-tests COMMAND officer-identity-inventory-tests)
    set_tests_properties(officer-identity-inventory-tests PROPERTIES TIMEOUT 90)
    add_executable(officer-persistence-inventory-tests tests/persistence_inventory_tests.cpp)
    target_link_libraries(officer-persistence-inventory-tests PRIVATE officer-core)
    add_custom_command(TARGET officer-persistence-inventory-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:tinyxml2::tinyxml2> $<TARGET_FILE_DIR:officer-persistence-inventory-tests>)
    add_test(NAME officer-persistence-inventory-tests COMMAND officer-persistence-inventory-tests)
    set_tests_properties(officer-persistence-inventory-tests PROPERTIES TIMEOUT 90)
    add_executable(officer-windows-event-log-tests tests/windows_event_log_tests.cpp)
    target_link_libraries(officer-windows-event-log-tests PRIVATE officer-collectors officer-delivery wevtapi advapi32)
    add_custom_command(TARGET officer-windows-event-log-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:tinyxml2::tinyxml2> $<TARGET_FILE_DIR:officer-windows-event-log-tests>)
    add_test(NAME officer-windows-event-log-tests COMMAND officer-windows-event-log-tests)
    set_tests_properties(officer-windows-event-log-tests PROPERTIES TIMEOUT 60)
    add_executable(officer-ip-interface-inventory-tests tests/ip_interface_inventory_tests.cpp)
    target_link_libraries(officer-ip-interface-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-ip-interface-inventory-tests COMMAND officer-ip-interface-inventory-tests)
    add_executable(officer-route-inventory-tests tests/route_inventory_tests.cpp)
    target_link_libraries(officer-route-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-route-inventory-tests COMMAND officer-route-inventory-tests)
    add_executable(officer-socket-inventory-tests tests/socket_inventory_tests.cpp)
    target_link_libraries(officer-socket-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-socket-inventory-tests COMMAND officer-socket-inventory-tests)
    add_executable(officer-driver-inventory-tests tests/driver_inventory_tests.cpp)
    target_link_libraries(officer-driver-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-driver-inventory-tests COMMAND officer-driver-inventory-tests)
    add_executable(officer-service-inventory-tests tests/service_inventory_tests.cpp)
    target_link_libraries(officer-service-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-service-inventory-tests COMMAND officer-service-inventory-tests)
    add_executable(officer-process-inventory-tests tests/process_inventory_tests.cpp)
    target_link_libraries(officer-process-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-process-inventory-tests COMMAND officer-process-inventory-tests)
    add_executable(officer-thread-inventory-tests tests/thread_inventory_tests.cpp)
    add_executable(officer-memory-inventory-tests tests/memory_inventory_tests.cpp)
    target_link_libraries(officer-memory-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-memory-inventory-tests COMMAND officer-memory-inventory-tests)
    set_tests_properties(officer-memory-inventory-tests PROPERTIES TIMEOUT 90)
    target_link_libraries(officer-thread-inventory-tests PRIVATE officer-core)
    add_test(NAME officer-thread-inventory-tests COMMAND officer-thread-inventory-tests)
    add_executable(officer-usn-journal-tests tests/usn_journal_tests.cpp)
    target_link_libraries(officer-usn-journal-tests PRIVATE officer-core officer-collectors officer-delivery)
    add_test(NAME officer-usn-journal-tests COMMAND officer-usn-journal-tests)
    set_tests_properties(officer-usn-journal-tests PROPERTIES TIMEOUT 60)
    set_tests_properties(officer-thread-inventory-tests PROPERTIES TIMEOUT 90)
    add_executable(officer-raw-handoff-tests tests/raw_handoff_tests.cpp)
    target_link_libraries(officer-raw-handoff-tests PRIVATE officer-core officer-delivery)
    add_test(NAME officer-raw-handoff-tests COMMAND officer-raw-handoff-tests)
    set_tests_properties(officer-raw-handoff-tests PROPERTIES TIMEOUT 15)
    add_executable(officer-response-runtime-tests tests/response_runtime_tests.cpp)
    target_link_libraries(officer-response-runtime-tests PRIVATE officer-core officer-collectors officer-delivery officer-response advapi32)
    if(MSVC)
        target_compile_options(officer-response-runtime-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-response-runtime-tests COMMAND officer-response-runtime-tests)
    add_executable(officer-process-action-tests tests/process_action_tests.cpp)
    target_link_libraries(officer-process-action-tests PRIVATE officer-response officer-core)
    if(MSVC)
        target_compile_options(officer-process-action-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-process-action-tests COMMAND officer-process-action-tests)
    add_executable(officer-host-inventory-tests tests/host_inventory_tests.cpp)
    target_link_libraries(officer-host-inventory-tests PRIVATE officer-core officer-delivery)
    if(MSVC)
        target_compile_options(officer-host-inventory-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-host-inventory-tests COMMAND officer-host-inventory-tests)
    add_executable(officer-source-facts-tests tests/source_facts_tests.cpp)
    target_link_libraries(officer-source-facts-tests PRIVATE officer-core officer-delivery)
    if(MSVC)
        target_compile_options(officer-source-facts-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-source-facts-tests COMMAND officer-source-facts-tests)
    add_executable(officer-source-supervisor-tests tests/source_supervisor_tests.cpp)
    target_link_libraries(officer-source-supervisor-tests PRIVATE officer-core officer-collectors officer-delivery)
    add_custom_command(TARGET officer-source-supervisor-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:tinyxml2::tinyxml2> $<TARGET_FILE_DIR:officer-source-supervisor-tests>)
    add_test(NAME officer-source-supervisor-tests COMMAND officer-source-supervisor-tests)
    add_executable(officer-endpoint-tests tests/endpoint_tests.cpp)
    target_link_libraries(officer-endpoint-tests PRIVATE officer-core officer-delivery)
    add_test(NAME officer-endpoint-tests COMMAND officer-endpoint-tests)
    add_executable(officer-journal-tests tests/journal_tests.cpp)
    target_link_libraries(officer-journal-tests PRIVATE officer-delivery)
    add_test(NAME officer-journal-tests COMMAND officer-journal-tests)
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

    add_executable(officer-state-freshness-tests tests/state_freshness_tests.cpp)
    add_executable(officer-defender-status-tests tests/defender_status_tests.cpp)
    target_link_libraries(officer-defender-status-tests PRIVATE officer-core)
    add_test(NAME officer-defender-status-tests COMMAND officer-defender-status-tests)
    add_executable(officer-security-center-tests tests/security_center_tests.cpp)
    target_link_libraries(officer-security-center-tests PRIVATE officer-core)
    add_test(NAME officer-security-center-tests COMMAND officer-security-center-tests)
    target_link_libraries(officer-state-freshness-tests PRIVATE officer-core officer-delivery)
    add_test(NAME officer-state-freshness-tests COMMAND officer-state-freshness-tests)

    add_executable(officer-firewall-rules-tests tests/firewall_rules_tests.cpp)
    target_link_libraries(officer-firewall-rules-tests PRIVATE officer-core)
    add_test(NAME officer-firewall-rules-tests COMMAND officer-firewall-rules-tests)

    add_executable(officer-firewall-profiles-tests tests/firewall_profiles_tests.cpp)
    target_link_libraries(officer-firewall-profiles-tests PRIVATE officer-core)
    add_test(NAME officer-firewall-profiles-tests COMMAND officer-firewall-profiles-tests)

    add_executable(officer-diagnostic-output-tests tests/diagnostic_output_tests.cpp)
    target_link_libraries(officer-diagnostic-output-tests PRIVATE officer-core)
    add_test(NAME officer-diagnostic-output-tests COMMAND officer-diagnostic-output-tests)

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

    add_executable(officer-delivery-tests tests/delivery_tests.cpp)
    target_link_libraries(officer-delivery-tests PRIVATE officer-delivery)
    if(MSVC)
        target_compile_options(officer-delivery-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-delivery-tests COMMAND officer-delivery-tests)

    add_executable(officer-spool-tests tests/spool_tests.cpp)
    target_link_libraries(officer-spool-tests PRIVATE officer-delivery)
    if(MSVC)
        target_compile_options(officer-spool-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-spool-tests COMMAND officer-spool-tests)

    add_executable(officer-response-tests tests/response_tests.cpp)
    target_link_libraries(officer-response-tests PRIVATE officer-response officer-core)
    # panopticon-contracts is a sibling checkout (see .github/workflows/ci.yml),
    # the same convention panopticon-manager already uses for cross-repo schema
    # contract tests. Tests that read fixtures under this path skip gracefully
    # (not fail) when it does not exist, e.g. a local dev checkout without the
    # sibling repo cloned.
    target_compile_definitions(
        officer-response-tests
        PRIVATE PANOPTICON_CONTRACTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../panopticon-contracts"
    )
    if(MSVC)
        target_compile_options(officer-response-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-response-tests COMMAND officer-response-tests)

    add_executable(officer-keypair-tests tests/keypair_tests.cpp)
    target_link_libraries(officer-keypair-tests PRIVATE officer-response officer-core)
    if(MSVC)
        target_compile_options(officer-keypair-tests PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()
    add_test(NAME officer-keypair-tests COMMAND officer-keypair-tests)
endif()

add_subdirectory(tools/query)
