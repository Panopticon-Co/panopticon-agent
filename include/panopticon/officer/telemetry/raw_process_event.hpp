#pragma once

#include "panopticon/officer/telemetry/raw_event_common.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace panopticon::officer::telemetry {

// A source adapter publishes this structure. It contains observed facts only;
// it does not contain JSON, transport, storage, or detection concerns.
struct RawProcessEvent {
    SourceProvenance source;
    UtcTimestamp process_start_time;
    std::uint32_t pid{};
    // Opaque, OS-native process-creation value (the raw FILETIME the kernel
    // reports, in 100ns ticks since 1601-01-01) -- the same quantity
    // GetProcessTimes() returns for the same process and the same quantity
    // src/response/process_actions.cpp's reobserve_process() independently
    // recomputes for PID-reuse-safe KILL_PROCESS targeting. Never interpreted
    // for its magnitude by anything other than this host's own agent; see
    // panopticon-response-engine/docs/adr/002-terminate-process-start-time-threading.md.
    std::optional<std::uint64_t> start_time_ticks;
    std::optional<std::uint32_t> parent_pid;
    std::optional<std::string> parent_executable;
    std::optional<std::string> executable;
    std::optional<std::string> command_line;
    std::optional<std::string> user_sid;
    std::optional<std::string> user_name;
    std::optional<std::string> sha256;

    bool operator==(const RawProcessEvent&) const = default;
};

// -- V3 telemetry families ------------------------------------------------
// Each family carries its own observed facts plus a RawProcessContext (which
// process did it). Collectors decode native events into these; normalization
// converts them into the common Panopticon representation.

enum class NetworkDirection { inbound, outbound };
enum class NetworkProtocol { tcp, udp, other };

struct RawNetworkEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    NetworkDirection direction{NetworkDirection::outbound};
    NetworkProtocol protocol{NetworkProtocol::other};
    std::optional<std::string> source_ip;
    std::optional<std::uint16_t> source_port;
    std::optional<std::string> destination_ip;
    std::optional<std::uint16_t> destination_port;
    std::optional<std::string> destination_hostname;

    bool operator==(const RawNetworkEvent&) const = default;
};

enum class FileOperation { create, remove, rename };

struct RawFileEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    FileOperation operation{FileOperation::create};
    std::optional<std::string> path;
    std::optional<std::string> target_path;
    std::optional<std::string> previous_path;
    std::optional<std::string> sha256;

    bool operator==(const RawFileEvent&) const = default;
};

enum class RegistryOperation { add_key, delete_key, set_value, rename_key };

struct RawRegistryEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    RegistryOperation operation{RegistryOperation::set_value};
    std::optional<std::string> key_path;
    std::optional<std::string> value_name;
    std::optional<std::string> value_type;
    // Metadata-only policy: value_data stays unset unless a collector was
    // explicitly configured to include it. The normalizer never synthesizes it.
    std::optional<std::string> value_data;

    bool operator==(const RawRegistryEvent&) const = default;
};

struct RawImageLoadEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    std::optional<std::string> path;
    std::optional<bool> is_signed;
    std::optional<std::string> signature_status;
    std::optional<std::string> sha256;

    bool operator==(const RawImageLoadEvent&) const = default;
};

// -- Schema 0.5 telemetry families ------------------------------------------

// Sysmon EID 5: the process in `process` exited.
struct RawProcessStopEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;

    bool operator==(const RawProcessStopEvent&) const = default;
};

// Sysmon EID 22: `process` resolved query_name.
struct RawDnsEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    std::optional<std::string> query_name;
    std::optional<std::uint32_t> query_status;
    // The resolver answer exactly as Sysmon renders it; never parsed here.
    std::optional<std::string> query_results;

    bool operator==(const RawDnsEvent&) const = default;
};

// The other process in a cross-process event (Sysmon EID 8 / 10).
struct RawTargetProcess {
    std::optional<std::uint32_t> pid;
    std::optional<std::string> executable;
    std::optional<std::string> process_guid;
    std::optional<std::string> user_name;

    bool operator==(const RawTargetProcess&) const = default;
};

// Sysmon EID 10: `process` (the source) opened a handle to `target`.
struct RawProcessAccessEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    RawTargetProcess target;
    std::optional<std::string> granted_access;  // "0x1410", as Sysmon renders it
    std::optional<std::string> call_trace;

    bool operator==(const RawProcessAccessEvent&) const = default;
};

// Sysmon EID 8: `process` (the source) created a thread in `target`.
struct RawRemoteThreadEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    RawTargetProcess target;
    std::optional<std::uint32_t> new_thread_id;
    std::optional<std::string> start_address;
    // Unset when Sysmon reports "-": the thread starts in unbacked memory.
    std::optional<std::string> start_module;
    std::optional<std::string> start_function;

    bool operator==(const RawRemoteThreadEvent&) const = default;
};

// PowerShell Operational EID 4104: `process` (a PowerShell host, identified
// only by PID -- the event carries no image) compiled a script block. `text` is
// the full block as logged; the normalizer applies the wire cap.
struct RawScriptBlockEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    std::optional<std::string> script_block_id;
    std::optional<std::uint32_t> message_number;
    std::optional<std::uint32_t> message_total;
    std::optional<std::string> path;
    std::optional<std::string> text;

    bool operator==(const RawScriptBlockEvent&) const = default;
};

// New raw event types are added to this variant without changing collector
// ownership or downstream sink interfaces.
using RawEvent = std::variant<
    RawProcessEvent,
    RawNetworkEvent,
    RawFileEvent,
    RawRegistryEvent,
    RawImageLoadEvent,
    RawProcessStopEvent,
    RawDnsEvent,
    RawProcessAccessEvent,
    RawRemoteThreadEvent,
    RawScriptBlockEvent>;

}  // namespace panopticon::officer::telemetry
