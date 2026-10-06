#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::telemetry {

using UtcTimestamp = std::chrono::sys_time<std::chrono::nanoseconds>;

enum class TelemetrySourceKind {
    etw,
    sysmon,
    windows_event_log,
};

struct SourceProvenance {
    TelemetrySourceKind kind{TelemetrySourceKind::etw};
    std::string provider;
    std::optional<std::string> channel;
    std::optional<std::uint64_t> record_id;

    bool operator==(const SourceProvenance&) const = default;
};

// Process context carried by every non-process telemetry family. It answers
// "which process did this" without the family collector taking on process-start
// normalization. Primary fields are observed facts; cache evidence is attached
// separately -- no JSON, transport, or detection concerns.
struct CachedProcessContext {
    SourceProvenance source;
    UtcTimestamp process_start_time;
    std::uint32_t pid{};
    std::string process_guid;
    std::optional<std::string> executable;
    std::optional<std::string> user_name;
    std::optional<std::string> user_sid;
    bool operator==(const CachedProcessContext&) const = default;
};

struct RawProcessContext {
    std::uint32_t pid{};
    std::optional<std::string> executable;
    std::optional<std::string> process_name;
    std::optional<std::string> user_name;
    std::optional<std::string> user_sid;
    // Sysmon ProcessGuid string, when the source provides one. Used to derive a
    // stable process-context entity ID for non-process telemetry families.
    std::optional<std::string> process_guid;
    // Separate cache evidence. Never overwrite the fields decoded from this
    // event. Normalization may use this only after GUID/PID/source agreement.
    std::optional<CachedProcessContext> cached_context;

    bool operator==(const RawProcessContext&) const = default;
};

}  // namespace panopticon::officer::telemetry
