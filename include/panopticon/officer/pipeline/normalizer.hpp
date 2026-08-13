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

[[nodiscard]] std::string format_utc_timestamp(telemetry::UtcTimestamp timestamp);

}  // namespace panopticon::officer::pipeline
