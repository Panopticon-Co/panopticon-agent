#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/collectors/process_image_cache.hpp"
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/collectors/sysmon_process_decoder.hpp"
#include "panopticon/officer/collectors/sysmon_telemetry_decoder.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include "panopticon/officer/pipeline/serializer.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <variant>

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

// -- V3 telemetry-family decode + normalize ---------------------------
std::string read_named_fixture(const char* path) {
    std::ifstream file(path);
    return {std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
}

pipeline::NormalizationContext family_context() {
    pipeline::NormalizationContext context;
    context.agent = {"agent-sanitized-001", telemetry::kAgentVersion};
    context.host = {"host-sanitized-001", "OFFICER-LAB", {"Windows 11", "26100"}};
    return context;
}

void expect_round_trips(const telemetry::PanopticonEvent& event, const char* label) {
    std::string error;
    const auto back = pipeline::deserialize_event(pipeline::serialize_event(event), error);
    if (!back) {
        std::cerr << "Round-trip parse error for " << label << ": " << error << '\n';
    }
    expect(back && *back == event, label);
}

void test_sysmon_network_family() {
    std::string error;
    const auto raw = collectors::SysmonTelemetryDecoder::decode_xml(
        read_named_fixture(OFFICER_SYSMON_NETWORK_FIXTURE_PATH), error);
    expect(raw.has_value(), "network fixture decodes to a raw event");
    if (!raw) { std::cerr << "decode error: " << error << '\n'; return; }
    expect(std::holds_alternative<telemetry::RawNetworkEvent>(*raw), "EID 3 decodes to RawNetworkEvent");
    const auto& n = std::get<telemetry::RawNetworkEvent>(*raw);
    expect(n.direction == telemetry::NetworkDirection::outbound, "Initiated=true -> outbound");
    expect(n.protocol == telemetry::NetworkProtocol::tcp, "protocol tcp decodes");
    expect(n.destination_ip == std::optional<std::string>{"203.0.113.10"}, "destination IP decodes");
    expect(n.destination_port == std::optional<std::uint16_t>{443}, "destination port decodes");
    expect(n.process.pid == 4242, "process context PID decodes");

    const auto normalized = pipeline::normalize_network_event(n, family_context(), error);
    expect(normalized.has_value(), "network event normalizes");
    if (!normalized) { std::cerr << "normalize error: " << error << '\n'; return; }
    expect(normalized->event.category == "network" && normalized->event.type == "connect", "network category/type");
    expect(normalized->network && normalized->network->destination_ip == std::optional<std::string>{"203.0.113.10"}, "family block populated");
    expect(!normalized->file && !normalized->registry && !normalized->image_load, "only the network block is set");
    expect(normalized->process.entity_id.starts_with("proc_"), "process-context entity ID derived");
    expect_round_trips(*normalized, "normalized network event round-trips through the 0.3 serializer");
}

void test_sysmon_file_family() {
    std::string error;
    const auto raw = collectors::SysmonTelemetryDecoder::decode_xml(
        read_named_fixture(OFFICER_SYSMON_FILE_FIXTURE_PATH), error);
    expect(raw && std::holds_alternative<telemetry::RawFileEvent>(*raw), "EID 11 decodes to RawFileEvent");
    if (!raw) { std::cerr << "decode error: " << error << '\n'; return; }
    const auto& f = std::get<telemetry::RawFileEvent>(*raw);
    expect(f.operation == telemetry::FileOperation::create, "EID 11 -> create");
    expect(f.path && f.path->ends_with("stage.txt"), "target filename decodes");

    const auto normalized = pipeline::normalize_file_event(f, family_context(), error);
    expect(normalized.has_value(), "file event normalizes");
    if (!normalized) { std::cerr << "normalize error: " << error << '\n'; return; }
    expect(normalized->event.category == "file" && normalized->event.type == "create", "file category/type");
    expect(normalized->file && normalized->file->operation == "create", "file block populated");
    expect_round_trips(*normalized, "normalized file event round-trips through the 0.3 serializer");
}

void test_sysmon_registry_family_is_metadata_only() {
    std::string error;
    const auto raw = collectors::SysmonTelemetryDecoder::decode_xml(
        read_named_fixture(OFFICER_SYSMON_REGISTRY_FIXTURE_PATH), error);
    expect(raw && std::holds_alternative<telemetry::RawRegistryEvent>(*raw), "EID 13 decodes to RawRegistryEvent");
    if (!raw) { std::cerr << "decode error: " << error << '\n'; return; }
    const auto& r = std::get<telemetry::RawRegistryEvent>(*raw);
    expect(r.operation == telemetry::RegistryOperation::set_value, "EID 13 -> set_value");
    expect(r.key_path && r.key_path->find("CurrentVersion\\Run") != std::string::npos, "Run key path decodes");
    expect(r.value_name == std::optional<std::string>{"Updater"}, "value name is the key leaf");
    expect(r.value_type == std::optional<std::string>{"REG_BINARY"}, "value type derived from Details token");
    expect(!r.value_data.has_value(), "value_data is never populated (metadata-only)");

    const auto normalized = pipeline::normalize_registry_event(r, family_context(), error);
    expect(normalized.has_value(), "registry event normalizes");
    if (!normalized) { std::cerr << "normalize error: " << error << '\n'; return; }
    expect(normalized->registry && !normalized->registry->value_data.has_value(), "normalized registry stays metadata-only");
    expect_round_trips(*normalized, "normalized registry event round-trips through the 0.3 serializer");
}

void test_sysmon_image_load_family() {
    std::string error;
    const auto raw = collectors::SysmonTelemetryDecoder::decode_xml(
        read_named_fixture(OFFICER_SYSMON_IMAGE_LOAD_FIXTURE_PATH), error);
    expect(raw && std::holds_alternative<telemetry::RawImageLoadEvent>(*raw), "EID 7 decodes to RawImageLoadEvent");
    if (!raw) { std::cerr << "decode error: " << error << '\n'; return; }
    const auto& im = std::get<telemetry::RawImageLoadEvent>(*raw);
    expect(im.path && im.path->ends_with("payload.dll"), "ImageLoaded decodes");
    expect(im.is_signed == std::optional<bool>{false}, "Signed=false decodes");
    expect(im.sha256 && im.sha256->size() == 64, "SHA-256 extracted from Hashes");

    const auto normalized = pipeline::normalize_image_load_event(im, family_context(), error);
    expect(normalized.has_value(), "image load event normalizes");
    if (!normalized) { std::cerr << "normalize error: " << error << '\n'; return; }
    expect(normalized->event.category == "image_load" && normalized->event.type == "load", "image_load category/type");
    expect(normalized->image_load && normalized->image_load->is_signed == std::optional<bool>{false}, "image block populated");
    expect_round_trips(*normalized, "normalized image load event round-trips through the 0.3 serializer");
}

void test_process_image_cache_backfills_unknown_process() {
    collectors::ProcessImageCache cache;

    telemetry::RawProcessEvent eid1;
    eid1.pid = 12516;
    eid1.executable = "C:\\Windows\\System32\\certutil.exe";
    eid1.user_name = "PICASSO\\stati";
    eid1.user_sid = "S-1-5-21-1-2-3-1001";
    cache.remember(eid1);

    // A Sysmon EID 3 that lost its image ("<unknown process>") is backfilled.
    telemetry::RawNetworkEvent unresolved;
    unresolved.process.pid = 12516;
    unresolved.process.executable = std::string{collectors::ProcessImageCache::kUnknownProcessSentinel};
    expect(cache.enrich(unresolved.process), "unknown-process context is enriched from a cached EID 1");
    expect(
        unresolved.process.executable == std::optional<std::string>{"C:\\Windows\\System32\\certutil.exe"},
        "cached image path is backfilled");
    expect(unresolved.process.user_name == std::optional<std::string>{"PICASSO\\stati"}, "cached user backfilled");

    // A context that already has a real image is left untouched.
    telemetry::RawNetworkEvent resolved;
    resolved.process.pid = 12516;
    resolved.process.executable = "C:\\Windows\\explorer.exe";
    expect(!cache.enrich(resolved.process), "an already-resolved context is not touched");
    expect(resolved.process.executable == std::optional<std::string>{"C:\\Windows\\explorer.exe"},
           "resolved image path is preserved");

    // An unknown PID that was never seen as EID 1 cannot be enriched.
    telemetry::RawFileEvent miss;
    miss.process.pid = 999999;
    miss.process.executable = std::nullopt;
    expect(!cache.enrich(miss.process), "a PID with no remembered EID 1 is left alone");

    // The cold generation still answers after the hot generation rolls over.
    collectors::ProcessImageCache small{2};
    telemetry::RawProcessEvent a;
    a.pid = 1;
    a.executable = "a.exe";
    small.remember(a);
    telemetry::RawProcessEvent b;
    b.pid = 2;
    b.executable = "b.exe";
    small.remember(b);
    telemetry::RawProcessEvent c;
    c.pid = 3;
    c.executable = "c.exe";
    small.remember(c);  // rolls: {1,2} -> cold, {3} -> hot
    telemetry::RawNetworkEvent from_cold;
    from_cold.process.pid = 1;
    from_cold.process.executable = std::string{collectors::ProcessImageCache::kUnknownProcessSentinel};
    expect(small.enrich(from_cold.process), "an entry demoted to the cold generation is still found");
}

void test_sysmon_telemetry_decoder_rejects_process_and_unknown_ids() {
    std::string error;
    // Event ID 1 belongs to SysmonProcessDecoder, not this one.
    std::string xml = read_named_fixture(OFFICER_SYSMON_NETWORK_FIXTURE_PATH);
    const auto pos = xml.find("<EventID>3</EventID>");
    xml.replace(pos, 20, "<EventID>1</EventID>");
    expect(!collectors::SysmonTelemetryDecoder::decode_xml(xml, error), "EID 1 is rejected by the family decoder");

    xml = read_named_fixture(OFFICER_SYSMON_NETWORK_FIXTURE_PATH);
    xml.replace(xml.find("<EventID>3</EventID>"), 20, "<EventID>99</EventID>");
    expect(!collectors::SysmonTelemetryDecoder::decode_xml(xml, error), "an unsupported EID is rejected");
}

}  // namespace

int main() {
    test_sysmon_process_decoder();
    test_sysmon_decoder_rejects_wrong_event_and_bad_numbers();
    test_cross_source_entity_identity();
    test_collectors_share_the_generic_interface();
    test_sysmon_network_family();
    test_sysmon_file_family();
    test_sysmon_registry_family_is_metadata_only();
    test_sysmon_image_load_family();
    test_process_image_cache_backfills_unknown_process();
    test_sysmon_telemetry_decoder_rejects_process_and_unknown_ids();
    if (failures == 0) {
        std::cout << "All Officer Phase 2 collector tests passed.\n";
        return 0;
    }
    return 1;
}
