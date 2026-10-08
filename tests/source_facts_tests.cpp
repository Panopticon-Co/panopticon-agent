#include "panopticon/officer/pipeline/source_facts.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
using namespace panopticon::officer;
using Json = nlohmann::json;
namespace fs = std::filesystem;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
pipeline::NormalizationContext context() { return {{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}}; }
const std::string boot = "boot_" + std::string(64, 'a');
telemetry::RawProcessEvent process() {
    telemetry::RawProcessEvent raw;
    raw.source = {telemetry::TelemetrySourceKind::etw, "Microsoft-Windows-Kernel-Process", std::nullopt, std::numeric_limits<std::uint64_t>::max()};
    raw.pid = 1234;
    raw.start_time_ticks = 133700000000000001ull;
    raw.process_start_time = telemetry::UtcTimestamp{std::chrono::nanoseconds{1725526400000000100ll}};
    raw.executable = "C:\\Example\\tool.exe";
    raw.command_line = std::string{"argument\0tail", 13};
    raw.parent_pid = 17;
    raw.parent_process_guid = "parent-source-guid";
    raw.parent_executable = "parent.exe";
    raw.user_sid = "S-1-5-18";
    raw.user_name = "NT AUTHORITY\\SYSTEM";
    raw.sha256 = "invalid-source-hash";
    return raw;
}
Json failure_fixtures() {
    pipeline::EndpointRecordFactory factory{context(), "device-1", std::string(64, 'b'), boot, 1};
    auto result = Json::array();
    auto raw = process();
    result.push_back(factory.normalization_failure(raw, "invalid hash"));
    telemetry::RawNetworkEvent network;
    network.source = {telemetry::TelemetrySourceKind::sysmon, "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 2};
    network.timestamp = raw.process_start_time;
    network.process.pid = raw.pid;
    network.process.process_guid = std::string(1, static_cast<char>(0xff));
    network.process.process_name = "untrusted source name";
    network.source_ip = "192.0.2.1";
    network.source_port = 1234;
    network.destination_ip = "198.51.100.7";
    network.destination_port = 443;
    network.destination_hostname = "example.invalid";
    network.protocol = telemetry::NetworkProtocol::tcp;
    result.push_back(factory.normalization_failure(network, "invalid source GUID encoding"));
    telemetry::RawFileEvent file;
    file.source = network.source;
    file.timestamp = network.timestamp;
    file.process.pid = 22;
    file.process.process_guid = "file-source-guid";
    file.operation = telemetry::FileOperation::rename;
    file.path = "source.txt";
    file.target_path = "target.txt";
    file.previous_path = "previous.txt";
    file.sha256 = "invalid-file-hash";
    result.push_back(factory.normalization_failure(file, "invalid file hash"));
    telemetry::RawRegistryEvent registry;
    registry.source = network.source;
    registry.timestamp = network.timestamp;
    registry.process.pid = 23;
    registry.key_path = "HKCU\\Software\\Example";
    registry.value_name = "";
    registry.value_type = "REG_SZ";
    registry.value_data = std::string{"a\0b", 3};
    result.push_back(factory.normalization_failure(registry, "fixture capture failure"));
    telemetry::RawImageLoadEvent image;
    image.source = network.source;
    image.timestamp = network.timestamp;
    image.process.pid = 24;
    image.path = "example.dll";
    image.is_signed = false;
    image.signature_status = "invalid source signature status";
    image.sha256 = "invalid-image-hash";
    result.push_back(factory.normalization_failure(image, "invalid image hash"));
    raw.source.provider = std::string(1025, 'p');
    raw.process_start_time = telemetry::UtcTimestamp{std::chrono::nanoseconds{std::numeric_limits<std::int64_t>::min()}};
    result.push_back(factory.normalization_failure(raw, "oversized provider and unrenderable source date"));
    return result;
}
void native_field_scope_tests() {
    auto event=process(); event.native_fields.emplace(); event.native_fields->event_id=1;
    event.native_fields->event_version=3;
    auto& field=event.native_fields->fields[0];
    field.state=telemetry::EtwUIntFieldState::copied; field.value=UINT64_MAX;
    field.in_type=10; field.reported_bytes=8; field.native_status=0;
    const auto facts=pipeline::source_facts(telemetry::RawEvent{event});
    require(facts["process"]["native_fields"]["fields"]["ProcessSequenceNumber"]["value"]=="18446744073709551615",
        "native sequence carrier lost precision");
    const auto refused=[&] {
        try { (void)pipeline::source_facts(telemetry::RawEvent{event}); }
        catch(const std::invalid_argument&) {return true;}
        return false;
    };
    event.source.kind=telemetry::TelemetrySourceKind::sysmon;
    require(refused(),"native fields accepted from another source");
    event.source.kind=telemetry::TelemetrySourceKind::etw;
    event.native_fields->event_id=2;
    require(refused(),"native field operation scope mismatch accepted");
    event.native_fields->event_id=1; field.native_status=5;
    require(refused(),"failed native read advertised a copied value");
    field.state=telemetry::EtwUIntFieldState::query_failed;
    require(refused(),"refused native read retained a value");
    field.value.reset();
    const auto failed=pipeline::source_facts(telemetry::RawEvent{event});
    require(failed["process"]["native_fields"]["fields"]["ProcessSequenceNumber"]["native_status"]=="5" &&
        failed["process"]["native_fields"]["fields"]["ProcessSequenceNumber"]["value"].is_null(),
        "native failure status/null evidence changed");
}
struct Scratch {
    fs::path root = fs::weakly_canonical(fs::temp_directory_path());
    fs::path path = root / ("officer-source-facts-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Scratch() { require(fs::create_directory(path), "test scratch must be newly owned"); }
    ~Scratch() {
        std::error_code error;
        if (path.parent_path() == root && path.filename().string().starts_with("officer-source-facts-")) fs::remove_all(path, error);
    }
};
int main(int argc, char** argv) {
    try {
        native_field_scope_tests();
        const auto fixtures = failure_fixtures();
        if (argc == 2 && std::string{argv[1]} == "--emit-fixtures") { std::cout << fixtures.dump() << '\n'; return 0; }
        const auto& raw = fixtures[0]["data"]["source_facts"];
        require(raw["process"]["sha256"] == "invalid-source-hash", "rejected hash must remain unchanged");
        require(raw["process"]["command_line"].get<std::string>() == std::string{"argument\0tail", 13}, "embedded NUL must survive JSON");
        require(raw["source"]["record_id"] == "18446744073709551615", "native record token retains all bits");
        require(fixtures[0]["subject"]["native_creation_ticks"] == "133700000000000001", "invalid hash cannot erase exact process identity");
        require(fixtures[1]["data"]["source_facts"]["process"]["process_guid"]["bytes"] == "ff" && fixtures[1]["subject"]["entity_id"].is_null(), "invalid GUID bytes survive without guessed alias");
        require(fixtures[2]["data"]["source_facts"]["file"]["previous_path"] == "previous.txt", "all decoded file paths retained");
        require(fixtures[3]["data"]["source_facts"]["registry"]["value_name"] == "" && fixtures[3]["data"]["source_facts"]["registry"]["value_data"].get<std::string>() == std::string{"a\0b", 3}, "empty values and configured registry data remain exact");
        require(fixtures[4]["data"]["source_facts"]["image"]["is_signed"] == false, "false is distinct from absent signature data");
        require(fixtures[5]["data"]["source_facts"]["event_time_ns"] == "-9223372036854775808" && fixtures[5]["subject"]["resolution"] == "native_exact", "unrenderable date preserves native time and identity");
        require(!pipeline::valid_utf8(std::string{"\xed\xa0\x80", 3}) && !pipeline::valid_utf8(std::string{"\xc0\xaf", 2}), "surrogate and overlong UTF-8 must not be silently repaired");
        require(pipeline::lossless_text("valid UTF-8 \xc3\xa9") == "valid UTF-8 \xc3\xa9", "valid unicode text remains text");
        auto event = process();
        enrichment::EnrichedProcessEvent enriched;
        enriched.raw = event;
        enriched.sha256 = event.sha256;
        std::string error;
        require(!pipeline::normalize_process_event(enriched, context(), error) && !error.empty(), "fixture must exercise actual normalizer refusal");
        event.sha256 = std::string(64, 'A');
        enriched.raw = event;
        enriched.sha256 = event.sha256;
        const auto normalized = pipeline::normalize_process_event(enriched, context(), error);
        require(normalized.has_value(), "valid hash normalizes");
        pipeline::EndpointRecordFactory factory{context(), "device-1", std::string(64, 'b'), boot, 1};
        const auto successful = factory.observation(event, *normalized);
        require(successful["data"]["source_facts"]["process"]["sha256"] == std::string(64, 'A'), "normalization must not replace original decoded hash");
        telemetry::RawNetworkEvent cached_event;
        cached_event.source = event.source;
        cached_event.timestamp = event.process_start_time;
        cached_event.process.pid = event.pid;
        cached_event.process.process_guid = "source-instance";
        cached_event.process.executable = "<unknown process>";
        cached_event.process.cached_context = telemetry::CachedProcessContext{event.source, event.process_start_time,
            event.pid, "source-instance", "cached-tool.exe", "cached-user", "S-1-5-18"};
        const auto enriched_network = pipeline::normalize_network_event(cached_event, context(), error);
        require(enriched_network && enriched_network->process.executable == std::optional<std::string>{"cached-tool.exe"}, "matching cached context remains useful to fleet normalization");
        const auto enriched_record = factory.observation(cached_event, *enriched_network);
        require(enriched_record["data"]["source_facts"]["process"]["executable"] == "<unknown process>" &&
            enriched_record["data"]["enrichment"]["cached_process_context"]["executable"] == "cached-tool.exe", "observed and cached context remain distinguishable");
        cached_event.process.cached_context->source.provider = "different provider";
        const auto wrong_source = pipeline::normalize_network_event(cached_event, context(), error);
        require(wrong_source && wrong_source->process.executable == std::optional<std::string>{"<unknown process>"}, "different source cannot supply cached process facts");
        require(!pipeline::enrichment_facts(cached_event)["cached_process_context"]["applicable"].get<bool>(), "rejected cached hints stay distinguishable from applied enrichment");
        Scratch scratch;
        { delivery::DurableJournal journal{{scratch.path}}; for (const auto& record : fixtures) journal.append(record.dump()); }
        { delivery::DurableJournal recovered{{scratch.path}};
          const auto batch = recovered.peek(1000, 8u * 1024 * 1024);
          require(batch && batch->protocol == 2 && batch->entries.size() == fixtures.size(), "failure evidence survives journal reopen");
          for (std::size_t index = 0; index < fixtures.size(); ++index)
              require(batch->entries[index].body == fixtures[index].dump(), "failure evidence bytes must survive durable recovery exactly"); }
        std::cout << "source facts preservation tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
