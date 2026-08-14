#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include "panopticon/officer/pipeline/serializer.hpp"
#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <variant>

namespace {

using namespace std::chrono_literals;
namespace enrichment = panopticon::officer::enrichment;
namespace pipeline = panopticon::officer::pipeline;
namespace telemetry = panopticon::officer::telemetry;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

telemetry::RawProcessEvent make_raw_process() {
    telemetry::RawProcessEvent raw;
    raw.source.kind = telemetry::TelemetrySourceKind::etw;
    raw.source.provider = "Microsoft-Windows-Kernel-Process";
    raw.source.record_id = 42;
    raw.process_start_time = telemetry::UtcTimestamp{123ms};
    raw.pid = 4242;
    raw.parent_pid = 1000;
    raw.executable = R"(C:\Sanitized\officer-demo.exe)";
    raw.command_line = R"("C:\Sanitized\officer-demo.exe" --safe-test)";
    raw.user_sid = "S-1-5-21-1000000000-1000000001-1000000002-1001";
    return raw;
}

pipeline::NormalizationContext make_context() {
    pipeline::NormalizationContext context;
    context.agent = {"agent-sanitized-001", telemetry::kAgentVersion};
    context.host = {"host-sanitized-001", "OFFICER-LAB", {"Windows 11", "26100"}};
    return context;
}

enrichment::EnrichedProcessEvent make_enriched_process() {
    enrichment::EnrichedProcessEvent enriched;
    enriched.raw = make_raw_process();
    enriched.user.name = "analyst";
    enriched.user.domain = "LAB";
    enriched.process_name = "officer-demo.exe";
    enriched.sha256 = std::string(64, 'A');
    enriched.parent_name = "powershell.exe";
    enriched.parent_start_time = telemetry::UtcTimestamp{100ms};
    return enriched;
}

telemetry::PanopticonEvent make_normalized_process() {
    std::string error;
    const auto normalized = pipeline::normalize_process_event(
        make_enriched_process(), make_context(), error);
    expect(normalized.has_value(), "valid enriched process normalizes");
    if (!normalized) {
        std::cerr << "Normalizer error: " << error << '\n';
        return {};
    }
    return *normalized;
}

void test_entity_identity_is_stable_and_pid_reuse_safe() {
    std::string error;
    const auto start = telemetry::UtcTimestamp{123ms};
    const auto first = panopticon::officer::core::derive_process_entity_id(
        "host-sanitized-001", 4242, start, error);
    const auto repeated = panopticon::officer::core::derive_process_entity_id(
        "host-sanitized-001", 4242, start, error);
    const auto reused_pid = panopticon::officer::core::derive_process_entity_id(
        "host-sanitized-001", 4242, start + 1ms, error);
    const auto source_precision = panopticon::officer::core::derive_process_entity_id(
        "host-sanitized-001", 4242, start + 999us, error);
    const auto different_host = panopticon::officer::core::derive_process_entity_id(
        "host-sanitized-002", 4242, start, error);

    expect(first && repeated && *first == *repeated, "identical process facts give a stable entity ID");
    expect(first && reused_pid && *first != *reused_pid, "PID reuse at a new start time changes entity ID");
    expect(first && source_precision && *first == *source_precision, "sub-millisecond source precision does not split entity identity");
    expect(first && different_host && *first != *different_host, "host identity participates in entity ID");
    expect(first && first->starts_with("proc_") && first->size() == 69, "entity ID has the documented format");
}

void test_raw_contract_and_normalization() {
    telemetry::RawEvent event = make_raw_process();
    expect(std::holds_alternative<telemetry::RawProcessEvent>(event), "raw event variant accepts a process event");

    const auto normalized = make_normalized_process();
    expect(normalized.schema_version == "0.2", "normalizer sets the current schema version");
    expect(normalized.event.category == "process" && normalized.event.type == "start", "normalizer sets process/start semantics");
    expect(normalized.event.timestamp == "1970-01-01T00:00:00.123Z", "timestamp is UTC with millisecond precision");
    expect(normalized.process.pid == 4242, "normalizer preserves PID");
    expect(normalized.source.kind == "etw" && normalized.source.provider == "Microsoft-Windows-Kernel-Process", "normalizer preserves source provenance");
    expect(normalized.process.parent.entity_id.has_value(), "known parent start time produces parent entity ID");
    expect(normalized.process.hash.sha256 == std::optional<std::string>{std::string(64, 'a')}, "SHA-256 is canonical lowercase");
    expect(normalized.user.sid == make_raw_process().user_sid, "raw SID is retained when enrichment has no replacement");

    auto no_parent_start = make_enriched_process();
    no_parent_start.parent_start_time.reset();
    std::string error;
    const auto partial_parent = pipeline::normalize_process_event(
        no_parent_start, make_context(), error);
    expect(partial_parent && !partial_parent->process.parent.entity_id, "parent PID alone never creates an unsafe entity ID");

    auto invalid_hash = make_enriched_process();
    invalid_hash.sha256 = "not-a-sha256";
    expect(!pipeline::normalize_process_event(invalid_hash, make_context(), error), "invalid SHA-256 enrichment is rejected");
}

void test_json_round_trip_and_validation() {
    const telemetry::PanopticonEvent original = make_normalized_process();
    const nlohmann::json json = pipeline::event_to_json(original);
    expect(json.size() == 7, "serialized event has exactly the seven top-level contract fields");
    expect(json.at("source").at("kind") == "etw", "source kind serializes explicitly");
    expect(json.at("process").at("pid").is_number_unsigned(), "PID serializes as a JSON number");
    expect(json.at("process").at("parent").contains("entity_id"), "parent shape is explicit");

    std::string error;
    const auto round_trip = pipeline::deserialize_event(pipeline::serialize_event(original), error);
    if (!round_trip) {
        std::cerr << "Round-trip parse error: " << error << '\n';
    } else if (*round_trip != original) {
        std::cerr << "Original:   " << pipeline::serialize_event(original) << '\n';
        std::cerr << "Round trip: " << pipeline::serialize_event(*round_trip) << '\n';
    }
    expect(round_trip && *round_trip == original, "serialized event round-trips without losing optional fields");

    auto invalid_pid = json;
    invalid_pid["process"]["pid"] = "4242";
    expect(!pipeline::deserialize_event(invalid_pid.dump(), error), "string PID is rejected");

    auto unknown_field = json;
    unknown_field["process"]["surprise"] = true;
    expect(!pipeline::deserialize_event(unknown_field.dump(), error), "unknown contract fields are rejected");

    auto future_schema = json;
    future_schema["schema_version"] = "9.9";
    expect(!pipeline::deserialize_event(future_schema.dump(), error), "unsupported schema version is rejected");
    expect(!pipeline::deserialize_event("{not-json", error) && !error.empty(), "malformed JSON fails with an error");
}

void test_schema_document_is_present_and_sane() {
    std::ifstream file(OFFICER_EVENT_SCHEMA_PATH);
    expect(file.good(), "JSON Schema file is available to the test suite");
    if (!file) {
        return;
    }
    const nlohmann::json schema = nlohmann::json::parse(
        std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{});
    expect(schema.at("$schema") == "https://json-schema.org/draft/2020-12/schema", "schema uses JSON Schema 2020-12");
    expect(schema.at("properties").at("schema_version").at("const") == "0.2", "schema version is current at 0.2");
    expect(schema.at("additionalProperties") == false, "schema rejects unknown top-level fields");
}

}  // namespace

int main() {
    test_entity_identity_is_stable_and_pid_reuse_safe();
    test_raw_contract_and_normalization();
    test_json_round_trip_and_validation();
    test_schema_document_is_present_and_sane();

    if (failures == 0) {
        std::cout << "All Officer contract tests passed.\n";
        return 0;
    }
    return 1;
}
