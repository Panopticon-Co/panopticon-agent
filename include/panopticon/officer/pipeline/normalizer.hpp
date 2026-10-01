#pragma once

#include "panopticon/officer/enrichment/enriched_process_event.hpp"
#include "panopticon/officer/telemetry/panopticon_event.hpp"

#include <optional>
#include <string>

namespace panopticon::officer::pipeline {

struct NormalizationContext {
    telemetry::AgentMetadata agent;
    telemetry::HostMetadata host;
};

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_process_event(
    const enrichment::EnrichedProcessEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

// -- V3 telemetry-family normalizers ----------------------------------
// Each takes a decoded raw family event and produces a Schema 0.3 event with
// the matching family block plus the shared process-context block. They never
// synthesize a field the source did not provide (absent -> null).
[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_network_event(
    const telemetry::RawNetworkEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_file_event(
    const telemetry::RawFileEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_registry_event(
    const telemetry::RawRegistryEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_image_load_event(
    const telemetry::RawImageLoadEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

// -- Schema 0.5 normalizers -------------------------------------------
// Process stop carries no family block (it closes a process interval). The
// cross-process families (process_access, remote_thread) put the SOURCE process
// in the shared process-context block and the other process in the family
// block's ``target``. Script block applies the wire cap to the text and records
// the full length, a truncation flag and a hash of the whole block.
[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_process_stop_event(
    const telemetry::RawProcessStopEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_dns_event(
    const telemetry::RawDnsEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_process_access_event(
    const telemetry::RawProcessAccessEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_remote_thread_event(
    const telemetry::RawRemoteThreadEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::optional<telemetry::PanopticonEvent> normalize_script_block_event(
    const telemetry::RawScriptBlockEvent& event,
    const NormalizationContext& context,
    std::string& error_message);

[[nodiscard]] std::string format_utc_timestamp(telemetry::UtcTimestamp timestamp);

}  // namespace panopticon::officer::pipeline
