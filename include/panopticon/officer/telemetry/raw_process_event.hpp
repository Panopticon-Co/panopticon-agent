#pragma once

#include "panopticon/officer/telemetry/raw_event_common.hpp"

#include <chrono>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <utility>

namespace panopticon::officer::telemetry {

enum class EtwUIntFieldState { copied, absent, type_refused, size_refused, query_failed };
struct EtwUIntField {
    EtwUIntFieldState state = EtwUIntFieldState::absent;
    std::optional<std::uint16_t> in_type;
    std::optional<std::uint32_t> native_status;
    std::optional<std::uint32_t> reported_bytes;
    std::optional<std::uint64_t> value;
    bool operator==(const EtwUIntField&) const = default;
};
// Fixed selected scalar facts from the source template, not live PID queries.
// Numeric enum/flag values remain uninterpreted; sequence values are not GUIDs.
struct EtwProcessNativeFields {
    static constexpr std::array<std::string_view, 19> names{
        "ProcessSequenceNumber", "ParentProcessSequenceNumber", "SessionID", "Flags",
        "ProcessTokenElevationType", "ProcessTokenIsElevated", "ImageChecksum", "TimeDateStamp",
        "SecurityMitigations", "TokenElevationType", "HandleCount", "CommitCharge", "CommitPeak",
        "CPUCycleCount", "ReadOperationCount", "WriteOperationCount", "ReadTransferKiloBytes",
        "WriteTransferKiloBytes", "HardFaultCount"};
    std::uint16_t event_id = 0;
    std::uint8_t event_version = 0;
    std::array<EtwUIntField, names.size()> fields;
    bool operator==(const EtwProcessNativeFields&) const = default;
};

// A source adapter publishes this structure. It contains observed facts only;
// it does not contain JSON, transport, storage, or detection concerns.
struct SysmonProcessFields {
    // Retain exact source spelling and text, including empty strings and '-'.
    // Nullable entries mean the source field was absent, not a default value.
    static constexpr std::array<std::string_view, 9> names{
        "ParentCommandLine", "IntegrityLevel", "OriginalFileName", "CurrentDirectory",
        "LogonId", "LogonGuid", "TerminalSessionId", "Hashes", "UtcTime"};
    std::array<std::optional<std::string>, names.size()> fields;
    bool operator==(const SysmonProcessFields&) const = default;
};

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
    // Native source aliases are retained exactly; never resolve an instance
    // by PID or by proximity of formatted timestamps.
    std::optional<std::string> process_guid;
    std::optional<std::string> parent_process_guid;
    std::optional<std::uint32_t> parent_pid;
    std::optional<std::string> parent_executable;
    std::optional<std::string> executable;
    std::optional<std::string> command_line;
    std::optional<std::string> user_sid;
    std::optional<std::string> user_name;
    std::optional<std::string> sha256;
    // Stops retain their own clock; never reinterpret exit time as creation.
    bool terminated = false;
    std::optional<UtcTimestamp> termination_time;
    std::optional<std::uint64_t> termination_time_ticks;
    std::optional<std::uint32_t> exit_code;
    std::optional<EtwProcessNativeFields> native_fields;
    std::optional<SysmonProcessFields> sysmon_fields;

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

// open/write/set_information/overwrite are minifilter IRP-level operations:
// open is IRP_MJ_CREATE of an existing file, overwrite a create disposition that
// replaces data, set_information a non-rename/non-delete metadata change.
enum class FileOperation { create, remove, rename, open, write, set_information, overwrite };

struct RawFileEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    FileOperation operation{FileOperation::create};
    std::optional<std::string> path;
    std::optional<std::string> target_path;
    std::optional<std::string> previous_path;
    std::optional<std::string> sha256;
    // Sources without a pre/post split (Sysmon) leave phase=reported and no status.
    OperationPhase phase{OperationPhase::reported};
    std::optional<NativeStatus> status;

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

// Windows-specific canonical families; never serialized as legacy schema 0.4.
// Source fields preserve exact decoded spelling/text within the XML admission cap.
struct RawSysmonExtendedEvent {
    SourceProvenance source;
    UtcTimestamp timestamp;
    RawProcessContext process;
    std::uint16_t event_id = 0; // closed set: 8, 10, 22
    std::string event_time_field;
    std::optional<RawProcessContext> target;
    std::optional<std::uint64_t> granted_access;
    std::optional<std::uint64_t> start_address;
    std::optional<std::uint32_t> new_thread_id;
    std::optional<std::uint32_t> query_status;
    std::optional<std::string> call_trace;
    std::optional<std::string> start_module;
    std::optional<std::string> start_function;
    std::optional<std::string> query_name;
    std::optional<std::string> query_results;
    std::vector<std::pair<std::string, std::string>> source_fields;
    bool operator==(const RawSysmonExtendedEvent&) const = default;
};

// New raw event types are added to this variant without changing collector
// ownership or downstream sink interfaces. Every `if constexpr` chain over it
// ends in `static_assert(unhandled_raw_event_v<T>)` so a new alternative is a
// compile error at each site rather than a silently dropped event.
using RawEvent = std::variant<
    RawProcessEvent,
    RawNetworkEvent,
    RawFileEvent,
    RawRegistryEvent,
    RawImageLoadEvent,
    RawSysmonExtendedEvent>;

template <class> inline constexpr bool unhandled_raw_event_v = false;

}  // namespace panopticon::officer::telemetry
