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
// normalization. All fields are observed facts only -- no JSON, transport, or
// detection concerns.
struct RawProcessContext {
    std::uint32_t pid{};
    std::optional<std::string> executable;
    std::optional<std::string> process_name;
    std::optional<std::string> user_name;
    std::optional<std::string> user_sid;

    bool operator==(const RawProcessContext&) const = default;
};

}  // namespace panopticon::officer::telemetry
