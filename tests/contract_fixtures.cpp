// Generates canonical endpoint-record 1.0 fixtures for every event family that
// Officer emits, using the production decoders, normalizers and record factory.
// Inputs are synthetic (sample Sysmon XML or constructed raw events); outputs
// are never real captures and say so in their metadata.
//
//   officer-contract-fixtures <output-directory>
//
// Writes one <family>.json per family: {"fixture": {...}, "records": [...]}.
#include "panopticon/officer/collectors/sysmon_process_decoder.hpp"
#include "panopticon/officer/collectors/sysmon_telemetry_decoder.hpp"
#include "panopticon/officer/health/coverage.hpp"
#include "panopticon/officer/health/source_supervisor.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace panopticon::officer;
using Json = nlohmann::json;
namespace fs = std::filesystem;

namespace {
constexpr char kGenerator[] = "officer-contract-fixtures";

void require(bool value, const std::string& message) { if (!value) throw std::runtime_error(message); }

pipeline::NormalizationContext context() { return {{"agent-fixture", "1.0-dev"}, {"host-fixture", "FIXTURE-HOST", {"Windows", "26100"}}}; }

std::string read_sample(const std::string& name) {
    std::ifstream file(fs::path(OFFICER_SYSMON_FIXTURE_DIR) / name, std::ios::binary);
    require(file.good(), "missing Sysmon sample " + name);
    std::ostringstream text; text << file.rdbuf(); return text.str();
}

// Mirrors the agent's process enrichment (main.cpp): leaf image name and
// DOMAIN\user split. Enrichment never replaces decoded source facts.
enrichment::EnrichedProcessEvent enrich(const telemetry::RawProcessEvent& raw) {
    enrichment::EnrichedProcessEvent enriched;
    enriched.raw = raw;
    const auto leaf = [](const std::optional<std::string>& path) -> std::optional<std::string> {
        if (!path || path->empty()) return std::nullopt;
        const auto separator = path->find_last_of("\\/");
        return separator == std::string::npos ? *path : path->substr(separator + 1);
    };
    enriched.process_name = leaf(raw.executable);
    enriched.parent_name = leaf(raw.parent_executable);
    enriched.sha256 = raw.sha256;
    if (raw.user_name) {
        const auto separator = raw.user_name->find('\\');
        if (separator == std::string::npos) enriched.user.name = *raw.user_name;
        else { enriched.user.domain = raw.user_name->substr(0, separator); enriched.user.name = raw.user_name->substr(separator + 1); }
    }
    return enriched;
}

Json observe(pipeline::EndpointRecordFactory& factory, const telemetry::RawEvent& raw) {
    std::string error;
    const auto normalized = std::visit([&](const auto& event) -> std::optional<telemetry::PanopticonEvent> {
        using Event = std::decay_t<decltype(event)>;
        if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>) return pipeline::normalize_process_event(enrich(event), context(), error);
        else if constexpr (std::is_same_v<Event, telemetry::RawNetworkEvent>) return pipeline::normalize_network_event(event, context(), error);
        else if constexpr (std::is_same_v<Event, telemetry::RawFileEvent>) return pipeline::normalize_file_event(event, context(), error);
        else if constexpr (std::is_same_v<Event, telemetry::RawRegistryEvent>) return pipeline::normalize_registry_event(event, context(), error);
        else if constexpr (std::is_same_v<Event, telemetry::RawImageLoadEvent>) return pipeline::normalize_image_load_event(event, context(), error);
        else if constexpr (std::is_same_v<Event, telemetry::RawSysmonExtendedEvent>) throw std::logic_error("Sysmon extension uses sysmon_extended");
        else static_assert(telemetry::unhandled_raw_event_v<Event>, "fixtures: unhandled RawEvent alternative");
    }, raw);
    require(normalized.has_value(), "fixture normalization refused: " + error);
    return factory.observation(raw, *normalized);
}

telemetry::RawEvent decode_sysmon(const std::string& sample) {
    std::string error;
    const auto xml = read_sample(sample);
    if (sample == "sysmon_process_create.xml") {
        const auto process = collectors::SysmonProcessDecoder::decode_xml(xml, error);
        require(process.has_value(), "process sample decode: " + error);
        return *process;
    }
    const auto event = collectors::SysmonTelemetryDecoder::decode_xml(xml, error);
    require(event.has_value(), sample + " decode: " + error);
    return *event;
}

telemetry::RawProcessEvent etw_process() {
    telemetry::RawProcessEvent raw;
    raw.source = {telemetry::TelemetrySourceKind::etw, "Microsoft-Windows-Kernel-Process", std::nullopt, std::nullopt};
    raw.pid = 4100;
    raw.start_time_ticks = 133735104000000123ull;
    raw.process_start_time = telemetry::UtcTimestamp{std::chrono::nanoseconds{1729036800000012300ll}};
    raw.parent_pid = 812;
    raw.executable = "C:\\Windows\\System32\\cmd.exe";
    raw.command_line = "cmd.exe /c echo fixture";
    raw.user_name = "FIXTURE-HOST\\analyst";
    raw.user_sid = "S-1-5-21-1000-1000-1000-1001";
    return raw;
}

telemetry::RawFileEvent minifilter_file(telemetry::FileOperation operation, telemetry::OperationPhase phase,
                                        std::optional<std::uint32_t> ntstatus, std::uint64_t sequence) {
    const auto actor = etw_process();
    telemetry::RawFileEvent file;
    file.source = {telemetry::TelemetrySourceKind::minifilter, "Panopticon-FsMon", "fsmon-v1", sequence};
    file.timestamp = actor.process_start_time + std::chrono::milliseconds{sequence};
    file.process.pid = actor.pid;
    file.process.start_time_ticks = actor.start_time_ticks;
    file.operation = operation;
    file.path = "\\Device\\HarddiskVolume3\\Users\\analyst\\fixture.txt";
    if (operation == telemetry::FileOperation::rename) file.target_path = "\\Device\\HarddiskVolume3\\Users\\analyst\\fixture-renamed.txt";
    file.phase = phase;
    if (ntstatus) file.status = telemetry::NativeStatus{telemetry::NativeStatus::Kind::ntstatus, *ntstatus};
    return file;
}

void write_family(const fs::path& directory, const std::string& family, Json fixture, Json records) {
    fixture["family"] = family;
    fixture["generated_by"] = kGenerator;
    fixture["real_capture"] = false;
    fixture["record_count"] = records.size();
    std::ofstream out(directory / (family + ".json"), std::ios::binary);
    out << Json{{"fixture", std::move(fixture)}, {"records", std::move(records)}}.dump(2) << '\n';
    require(bool(out), "fixture write failed for " + family);
}

Json from_sample(const std::string& sample, const std::string& chain) {
    return {{"input", "sysmon_xml_sample:tests/fixtures/" + sample}, {"producer_chain", chain}, {"provisional", false}};
}
}  // namespace

int main(int argc, char** argv) {
    try {
        require(argc == 2, "usage: officer-contract-fixtures <output-directory>");
        const fs::path out = argv[1];
        fs::create_directories(out);
        pipeline::EndpointRecordFactory factory{context(), "device-fixture", std::string(64, 'b'), "boot_" + std::string(64, 'a'), 1};

        // process start: ETW native-exact and Sysmon source-scoped references.
        const auto etw = etw_process();
        write_family(out, "process", {{"input", "synthetic_raw_event (ETW start) + sysmon_xml_sample:tests/fixtures/sysmon_process_create.xml"},
            {"producer_chain", "RawProcessEvent -> normalize_process_event -> EndpointRecordFactory::observation"}, {"provisional", false}},
            Json::array({observe(factory, etw), observe(factory, decode_sysmon("sysmon_process_create.xml"))}));

        auto stopped = etw;
        stopped.terminated = true;
        stopped.termination_time = etw.process_start_time + std::chrono::seconds{5};
        stopped.termination_time_ticks = *etw.start_time_ticks + 50000000ull;
        stopped.exit_code = 0;
        write_family(out, "process_stop", {{"input", "synthetic_raw_event (ETW stop)"},
            {"producer_chain", "RawProcessEvent{terminated} -> EndpointRecordFactory::process_stop"}, {"provisional", false}},
            Json::array({factory.process_stop(stopped)}));

        // network: one source-scoped, one with the source GUID absent (unresolved actor).
        auto network = std::get<telemetry::RawNetworkEvent>(decode_sysmon("sysmon_network_connect.xml"));
        auto unattributed = network; unattributed.process.process_guid.reset();
        write_family(out, "network", from_sample("sysmon_network_connect.xml",
            "SysmonTelemetryDecoder -> normalize_network_event -> EndpointRecordFactory::observation; second record drops the source GUID to show an unresolved actor"),
            Json::array({observe(factory, network), observe(factory, unattributed)}));

        write_family(out, "file", from_sample("sysmon_file_create.xml",
            "SysmonTelemetryDecoder -> normalize_file_event -> EndpointRecordFactory::observation"),
            Json::array({observe(factory, decode_sysmon("sysmon_file_create.xml"))}));

        Json minifilter = Json::array();
        using Op = telemetry::FileOperation; using Phase = telemetry::OperationPhase;
        minifilter.push_back(observe(factory, minifilter_file(Op::create, Phase::completed, 0x00000000u, 1)));
        minifilter.push_back(observe(factory, minifilter_file(Op::open, Phase::completed, 0x00000000u, 2)));
        minifilter.push_back(observe(factory, minifilter_file(Op::write, Phase::attempted, std::nullopt, 3)));
        minifilter.push_back(observe(factory, minifilter_file(Op::overwrite, Phase::completed, 0x00000000u, 4)));
        minifilter.push_back(observe(factory, minifilter_file(Op::set_information, Phase::completed, 0xC0000022u, 5)));
        minifilter.push_back(observe(factory, minifilter_file(Op::rename, Phase::completed, 0x00000000u, 6)));
        minifilter.push_back(observe(factory, minifilter_file(Op::remove, Phase::completed, 0x00000000u, 7)));
        write_family(out, "file_minifilter", {{"input", "synthetic_raw_event (minifilter)"},
            {"producer_chain", "RawFileEvent{source=minifilter} -> normalize_file_event -> EndpointRecordFactory::observation"},
            {"provisional", true}, {"provisional_reason", "panopticon-fsmon.sys and MinifilterCollector are not implemented; shape fixed by the pipeline, semantics subject to Wave 2"}},
            std::move(minifilter));

        write_family(out, "registry", from_sample("sysmon_registry_set_value.xml",
            "SysmonTelemetryDecoder -> normalize_registry_event -> EndpointRecordFactory::observation"),
            Json::array({observe(factory, decode_sysmon("sysmon_registry_set_value.xml"))}));
        write_family(out, "image_load", from_sample("sysmon_image_load.xml",
            "SysmonTelemetryDecoder -> normalize_image_load_event -> EndpointRecordFactory::observation"),
            Json::array({observe(factory, decode_sysmon("sysmon_image_load.xml"))}));

        for (const auto& [family, sample] : {std::pair{"dns", "sysmon_dns_query.xml"},
                                             std::pair{"process_access", "sysmon_process_access.xml"},
                                             std::pair{"remote_thread", "sysmon_remote_thread.xml"}}) {
            const auto raw = decode_sysmon(sample);
            write_family(out, family, from_sample(sample, "SysmonTelemetryDecoder -> EndpointRecordFactory::sysmon_extended"),
                Json::array({factory.sysmon_extended(std::get<telemetry::RawSysmonExtendedEvent>(raw))}));
        }

        collectors::CollectorStatus previous{true, false, true, 0, 0, 0, 10u, 0u, 0u, {}};
        collectors::CollectorStatus current{true, false, true, 0, 0, 0, 17u, 0u, 0u, {}};
        auto gap = health::source_gap_since(previous, current);
        require(gap.has_value(), "loss delta must produce a source gap");
        (*gap)["source"] = "etw";
        write_family(out, "source_loss", {{"input", "synthetic collector status samples (events_lost 10 -> 17)"},
            {"producer_chain", "health::source_gap_since -> EndpointRecordFactory::gap"}, {"provisional", false}},
            Json::array({factory.gap("etw", std::move(*gap))}));

        auto invalid = etw; invalid.sha256 = "not-a-sha256";
        std::string error;
        require(!pipeline::normalize_process_event(enrich(invalid), context(), error), "invalid hash must be refused");
        write_family(out, "normalization_failure", {{"input", "synthetic_raw_event with an invalid SHA-256"},
            {"producer_chain", "normalize_process_event refusal -> EndpointRecordFactory::normalization_failure"}, {"provisional", false}},
            Json::array({factory.normalization_failure(invalid, error)}));

        health::CoverageRegistry coverage;
        write_family(out, "endpoint_health", {{"input", "default coverage registry"},
            {"producer_chain", "CoverageRegistry::snapshot -> EndpointRecordFactory::health"}, {"provisional", false}},
            Json::array({factory.health(coverage.snapshot("agent-fixture", "host-fixture"))}));

        std::cout << "contract fixtures written to " << out.string() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
