#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::telemetry {

using UtcTimestamp = std::chrono::sys_time<std::chrono::nanoseconds>;

enum class TelemetrySourceKind {
    etw,
    sysmon,
    windows_event_log,
    // Officer's own FltMgr minifilter (panopticon-fsmon.sys) via its communication port.
    minifilter,
    // Officer's in-process API instrumentation (officer-hook.dll) via its named pipe.
    api_hook,
    // Reserved native kernel telemetry transport; collector validation is separate.
    etw_kernel,
};

// The single kind-to-name mapping. Every serializer, identity and provenance
// path uses this so a new kind cannot be named differently in two places.
constexpr std::string_view source_kind_name(TelemetrySourceKind kind) noexcept {
    switch (kind) {
        case TelemetrySourceKind::etw: return "etw";
        case TelemetrySourceKind::sysmon: return "sysmon";
        case TelemetrySourceKind::windows_event_log: return "windows_event_log";
        case TelemetrySourceKind::minifilter: return "minifilter";
        case TelemetrySourceKind::api_hook: return "api_hook";
        case TelemetrySourceKind::etw_kernel: return "etw_kernel";
    }
    return "unknown";
}

// Whether a source saw an operation before it ran, after it completed, or
// only reports that it happened without that distinction (e.g. Sysmon).
enum class OperationPhase { reported, attempted, completed };

// A native completion code exactly as the source reported it; never interpreted
// as success/failure beyond what the source states.
struct NativeStatus {
    enum class Kind { ntstatus, win32_error };
    Kind kind{Kind::ntstatus};
    std::uint32_t value{};
    bool operator==(const NativeStatus&) const = default;
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
    // Native creation FILETIME ticks, only when the source (or the collector,
    // from a verified handle) obtained them for this exact instance. Enables a
    // native_exact process reference; never derived from PID lookup alone.
    std::optional<std::uint64_t> start_time_ticks;
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
