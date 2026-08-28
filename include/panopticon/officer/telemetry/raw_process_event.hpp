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

// New raw event types are added to this variant without changing collector
// ownership or downstream sink interfaces.
using RawEvent = std::variant<
    RawProcessEvent,
    RawNetworkEvent,
    RawFileEvent,
    RawRegistryEvent,
    RawImageLoadEvent>;

}  // namespace panopticon::officer::telemetry
