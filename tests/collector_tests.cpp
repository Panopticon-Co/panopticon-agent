#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/collectors/sysmon_process_decoder.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

namespace collectors = panopticon::officer::collectors;
namespace core = panopticon::officer::core;
namespace pipeline = panopticon::officer::pipeline;
namespace telemetry = panopticon::officer::telemetry;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

std::string read_fixture() {
    std::ifstream file(OFFICER_SYSMON_FIXTURE_PATH);
    return {std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
}

void test_sysmon_process_decoder() {
    std::string error;
    const auto event = collectors::SysmonProcessDecoder::decode_xml(read_fixture(), error);
    expect(event.has_value(), "sanitized Sysmon process fixture decodes");
    if (!event) {
        std::cerr << "Decoder error: " << error << '\n';
        return;
    }
    expect(event->source.kind == telemetry::TelemetrySourceKind::sysmon, "source kind is Sysmon");
    expect(event->source.provider == "Microsoft-Windows-Sysmon", "provider is preserved");
    expect(event->source.channel == "Microsoft-Windows-Sysmon/Operational", "channel is preserved");
    expect(event->source.record_id == 100, "record ID is preserved");
    expect(event->pid == 4242 && event->parent_pid == 1000, "process identifiers decode");
    expect(event->executable && event->executable->ends_with("officer-demo.exe"), "image path decodes");
    expect(event->parent_executable && event->parent_executable->ends_with("powershell.exe"), "parent image decodes");
    expect(event->command_line && event->command_line->find("--safe-test") != std::string::npos, "command line decodes");
    expect(event->user_name == "LAB\\analyst", "observed account name decodes");
    expect(event->sha256 == std::string(64, 'A'), "source-provided SHA-256 decodes");
    expect(
        pipeline::format_utc_timestamp(event->process_start_time) ==
            "2026-08-14T12:00:00.123Z",
        "Sysmon UTC timestamp decodes and formats consistently");
}

void test_sysmon_decoder_rejects_wrong_event_and_bad_numbers() {
    std::string xml = read_fixture();
    std::string error;
    xml.replace(xml.find("<EventID>1</EventID>"), 20, "<EventID>3</EventID>");
    expect(!collectors::SysmonProcessDecoder::decode_xml(xml, error), "non-process Sysmon event is rejected");

    xml = read_fixture();
    const std::size_t pid = xml.find(">4242<");
    xml.replace(pid, 6, ">bad<");
    expect(!collectors::SysmonProcessDecoder::decode_xml(xml, error), "invalid Sysmon PID is rejected");
}

void test_cross_source_entity_identity() {
    std::string error;
    const auto sysmon = collectors::SysmonProcessDecoder::decode_xml(read_fixture(), error);
    expect(sysmon.has_value(), "fixture is available for identity test");
    if (!sysmon) {
        return;
    }
    const auto etw_time = sysmon->process_start_time + std::chrono::nanoseconds{299};
    const auto sysmon_id = core::derive_process_entity_id(
        "host-sanitized-001", sysmon->pid, sysmon->process_start_time, error);
    const auto etw_id = core::derive_process_entity_id(
        "host-sanitized-001", sysmon->pid, etw_time, error);
    expect(sysmon_id && etw_id && *sysmon_id == *etw_id, "sub-millisecond source precision converges to one entity ID");

    auto etw_observation = *sysmon;
    etw_observation.source.kind = telemetry::TelemetrySourceKind::etw;
    etw_observation.source.provider = "Microsoft-Windows-Kernel-Process";
    etw_observation.source.channel.reset();
    etw_observation.source.record_id.reset();
    etw_observation.process_start_time = etw_time;
    const auto sysmon_event_id = core::derive_process_event_id(
        "host-sanitized-001", *sysmon, error);
    const auto etw_event_id = core::derive_process_event_id(
        "host-sanitized-001", etw_observation, error);
    expect(
        sysmon_event_id && etw_event_id && *sysmon_event_id != *etw_event_id,
        "separate source observations retain separate event IDs");
}

void test_collectors_share_the_generic_interface() {
    collectors::EtwProcessCollector etw;
    collectors::SysmonEventCollector sysmon;
    collectors::TelemetryCollector& first = etw;
    collectors::TelemetryCollector& second = sysmon;
    expect(first.name() == "etw" && second.name() == "sysmon", "both sources implement TelemetryCollector");
    expect(!first.running() && !second.running(), "collectors begin stopped");
}

}  // namespace

int main() {
    test_sysmon_process_decoder();
    test_sysmon_decoder_rejects_wrong_event_and_bad_numbers();
    test_cross_source_entity_identity();
    test_collectors_share_the_generic_interface();
    if (failures == 0) {
        std::cout << "All Officer Phase 2 collector tests passed.\n";
        return 0;
    }
    return 1;
}
