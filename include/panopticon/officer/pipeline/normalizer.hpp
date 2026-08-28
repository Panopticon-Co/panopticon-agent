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

[[nodiscard]] std::string format_utc_timestamp(telemetry::UtcTimestamp timestamp);

}  // namespace panopticon::officer::pipeline
