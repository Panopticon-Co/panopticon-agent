#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <optional>
#include <string>

namespace panopticon::officer::enrichment {

struct ResolvedUser {
    std::optional<std::string> name;
    std::optional<std::string> domain;
    std::optional<std::string> sid;

    bool operator==(const ResolvedUser&) const = default;
};

// Enrichers produce this structure before normalization. Parent start time is
// required to derive a safe parent entity ID; parent PID alone is insufficient.
struct EnrichedProcessEvent {
    telemetry::RawProcessEvent raw;
    ResolvedUser user;
    std::optional<std::string> process_name;
    std::optional<std::string> sha256;
    std::optional<std::string> parent_name;
    std::optional<telemetry::UtcTimestamp> parent_start_time;

    bool operator==(const EnrichedProcessEvent&) const = default;
};

}  // namespace panopticon::officer::enrichment
