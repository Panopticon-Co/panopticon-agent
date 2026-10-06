#include "panopticon/officer/core/process_instance.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/health/coverage.hpp"
#include "panopticon/officer/delivery/uploader.hpp"
#include <fstream>
#include <thread>
#include <iostream>
#include <chrono>
#include <stdexcept>

namespace {
namespace core = panopticon::officer::core;
namespace pipeline = panopticon::officer::pipeline;
namespace telemetry = panopticon::officer::telemetry;
int failures = 0;
void expect(bool condition, const char* text) { if (!condition) { ++failures; std::cerr << "FAIL: " << text << '\n'; } }
const std::string boot = "boot_" + std::string(64, 'a');
pipeline::NormalizationContext context() { return {{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}}; }

nlohmann::json samples(std::uint64_t generation = 1) {
    pipeline::EndpointRecordFactory factory{context(), "device-1", std::string(64, 'b'), boot, generation};
    telemetry::RawProcessEvent raw;
    raw.source.provider = "Microsoft-Windows-Kernel-Process";
    raw.pid = 1234;
    raw.start_time_ticks = 133700000000000001ull;
    raw.command_line = "whoami /priv"; // benign fixture for actual Manager rule reachability
    raw.process_start_time = telemetry::UtcTimestamp{std::chrono::nanoseconds{1725526400000000100ll}};
    panopticon::officer::enrichment::EnrichedProcessEvent enriched;
    enriched.raw = raw;
    enriched.process_name = "whoami.exe";
    std::string error;
    auto normalized = pipeline::normalize_process_event(enriched, context(), error);
    auto result = nlohmann::json::array();
    result.push_back(factory.observation(telemetry::RawEvent{raw}, *normalized));
    raw.command_line.reset();
    enriched.process_name.reset();
    raw.source.kind = telemetry::TelemetrySourceKind::sysmon;
    raw.source.provider = "Microsoft-Windows-Sysmon";
    raw.source.channel = "Microsoft-Windows-Sysmon/Operational";
    raw.source.record_id = 18446744073709551615ull;
    raw.process_guid = "{source-instance-guid}";
    raw.start_time_ticks.reset();
    enriched.raw = raw;
    normalized = pipeline::normalize_process_event(enriched, context(), error);
    result.push_back(factory.observation(telemetry::RawEvent{raw}, *normalized));
    telemetry::RawNetworkEvent network;
    network.source = raw.source;
    network.timestamp = raw.process_start_time;
    network.process.pid = raw.pid;
    network.process.process_guid = raw.process_guid;
    const auto normalized_network = pipeline::normalize_network_event(network, context(), error);
    result.push_back(factory.observation(telemetry::RawEvent{network}, *normalized_network));
    network.process.process_guid.reset();
    result.push_back(factory.observation(telemetry::RawEvent{network}, *normalized_network));
    panopticon::officer::health::CoverageRegistry coverage;
    result.push_back(factory.health(coverage.snapshot("agent-1", "host-1")));
    result.push_back(factory.state("host", {{"hostname", "LAB"}, {"inventory_complete", false}}));
    return result;
}
void test_exact_identity() {
    core::ProcessInstanceStore first{"host-1", boot};
    const auto a = first.observe(42, 133700000000000001ull, std::nullopt, "native");
    const auto repeated = first.observe(42, 133700000000000001ull, std::nullopt, "another-native-provider");
    const auto reused = first.observe(42, 133700000000000002ull, std::nullopt, "native");
    expect(a.entity_id && a.entity_id == repeated.entity_id, "exact native instance is independent of collector provider");
    expect(a.entity_id != reused.entity_id, "100ns PID reuse separation is preserved without millisecond rounding");
    core::ProcessInstanceStore second{"host-1", "boot_" + std::string(64, 'c')};
    expect(a.entity_id != second.observe(42, 133700000000000001ull, std::nullopt, "native").entity_id, "boot identity prevents cross-boot process collision");
    core::ProcessInstanceStore unknown{"host-1", std::nullopt};
    const auto unscoped = unknown.observe(42, 133700000000000001ull, std::nullopt, "native");
    expect(!unscoped.entity_id && unscoped.resolution == "native_unscoped", "missing boot identity cannot invent a native canonical entity");
    const auto unresolved = first.observe(42, std::nullopt, std::nullopt, "sysmon");
    expect(!unresolved.entity_id && unresolved.resolution == "unresolved", "PID alone is explicitly unresolved");
    first.terminate(a, telemetry::UtcTimestamp{std::chrono::seconds{10}});
    expect(first.snapshot().size() == 2, "termination retains the instance tombstone");
    core::ProcessInstanceStore bounded{"host-1", boot, 1};
    (void)bounded.observe(1, 1, std::nullopt, "native");
    expect(bounded.observe(2, 2, std::nullopt, "native").entity_id.has_value() && bounded.admission_failures() == 1 && bounded.snapshot().size() == 1,
           "state cap accounts for missing residency without suppressing exact observation identity");
}
void test_canonical_records() {
    const auto records = samples();
    expect(records[0]["subject"]["resolution"] == "native_exact", "native observation uses exact process identity");
    expect(records[0]["subject"]["native_creation_ticks"] == "133700000000000001", "native token survives JSON without floating-point precision loss");
    expect(records[1]["subject"]["entity_id"] == records[2]["subject"]["entity_id"], "same source process GUID joins process start and network family");
    expect(records[0]["subject"]["entity_id"] != records[1]["subject"]["entity_id"], "different sources are not merged by PID or timestamp proximity");
    expect(records[3]["subject"]["entity_id"].is_null() && records[3]["data"]["process"]["entity_id"].is_null(), "unknown instance is preserved without the legacy PID-only entity");
    expect(records[1]["provenance"]["native_record_id"] == "18446744073709551615", "native record token is lossless at uint64 maximum");
    expect(records[0]["endpoint"]["device_id"] != records[0]["endpoint"]["host_id"], "device and enrolled host identity remain distinct");
    expect(records[0]["provenance"]["sequence"] == "1" && records[5]["provenance"]["sequence"] == "6", "observation epoch preserves source order across record kinds");
    expect(records[0]["provenance"]["collector_generation"] == "1" && samples(18446744073709551615ull)[0]["provenance"]["collector_generation"] == "18446744073709551615", "committed generation is lossless and independent of timestamps");
    expect(records[0]["provenance"]["event_time_ns"] == "1725526400000000100", "native event time precision is retained separately from formatted display time");
}
}
int main(int argc, char** argv) {
    if (argc == 5 && std::string{argv[1]} == "--send-fixtures") {
        panopticon::officer::delivery::DeliveryConfig config;
        config.manager_url = argv[2];
        config.spool_directory = argv[3];
        config.verify_tls = false; // isolated test server only; no trust-store mutation
        config.flush_interval_ms = 20;
        config.spool_base_backoff_ms = 25;
        std::ifstream token(argv[4]);
        if (!std::getline(token, config.bearer_token) || config.bearer_token.empty()) return 2;
        panopticon::officer::delivery::Uploader uploader{config, "agent-1"};
        const auto fixtures = samples(uploader.next_collector_generation());
        uploader.set_capture_scope({{"installation_id", fixtures[0]["endpoint"]["installation_id"]},
            {"boot_id", fixtures[0]["endpoint"]["boot_id"]},
            {"collector_generation", fixtures[0]["provenance"]["collector_generation"]},
            {"collector_epoch", fixtures[0]["provenance"]["collector_epoch"]}});
        for (const auto& record : fixtures) if (!uploader.enqueue(record.dump())) return 3;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
        while (uploader.journal_stats().pending_events && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        uploader.stop();
        const auto stats = uploader.journal_stats();
        const auto health = uploader.health();
        std::cout << nlohmann::json{{"pending", stats.pending_events}, {"acknowledged", stats.acknowledged_events},
            {"dead_letters", stats.dead_letter_events}, {"invalid_receipts", health.invalid_receipts},
            {"transport_state", health.transport_state}, {"capture_age_state", health.capture_age_state},
            {"freshness_challenge_failures", health.freshness_challenge_failures}}.dump() << '\n';
        return stats.pending_events == 0 && stats.acknowledged_events == fixtures.size() && !stats.dead_letter_events ? 0 : 4;
    }
    if (argc == 2 && std::string{argv[1]} == "--probe-boot") {
        std::string error;
        const auto first = core::query_native_boot_id(error);
        const auto second = core::query_native_boot_id(error);
        std::cout << nlohmann::json{{"native_boot_available", first.has_value()}, {"consistent", first == second}, {"error", error}}.dump() << '\n';
        return first == second ? 0 : 1;
    }
    if (argc == 2 && std::string{argv[1]} == "--emit-fixtures") { std::cout << samples().dump(2) << '\n'; return 0; }
    try { test_exact_identity(); test_canonical_records(); }
    catch (const std::exception& error) { expect(false, error.what()); }
    return failures ? 1 : 0;
}
