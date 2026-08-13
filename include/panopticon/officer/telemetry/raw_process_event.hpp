#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>

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

// A source adapter publishes this structure. It contains observed facts only;
// it does not contain JSON, transport, storage, or detection concerns.
struct RawProcessEvent {
    SourceProvenance source;
    UtcTimestamp process_start_time;
    std::uint32_t pid{};
    std::optional<std::uint32_t> parent_pid;
    std::optional<std::string> executable;
    std::optional<std::string> command_line;
    std::optional<std::string> user_sid;

    bool operator==(const RawProcessEvent&) const = default;
};

// New raw event types will be added to this variant without changing collector
// ownership or downstream bus interfaces.
using RawEvent = std::variant<RawProcessEvent>;

}  // namespace panopticon::officer::telemetry
