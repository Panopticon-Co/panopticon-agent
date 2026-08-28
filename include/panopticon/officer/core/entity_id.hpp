#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::core {

[[nodiscard]] std::optional<std::string> derive_process_entity_id(
    std::string_view host_id,
    std::uint32_t pid,
    telemetry::UtcTimestamp process_start_time,
    std::string& error_message);

[[nodiscard]] std::optional<std::string> derive_process_event_id(
    std::string_view host_id,
    const telemetry::RawProcessEvent& event,
    std::string& error_message);

// -- V3 telemetry-family identities ------------------------------------
// Non-process families (network/file/registry/image_load) do not carry a
// process start time, so they cannot reuse derive_process_entity_id. The
// process-context entity ID is derived from host + PID + Sysmon ProcessGuid
// (falling back to host + PID when no GUID is available). It is stable for the
// life of a process but is not guaranteed to equal the process-start event's
// entity ID; cross-family correlation is by PID/name within a time window.
[[nodiscard]] std::optional<std::string> derive_process_context_entity_id(
    std::string_view host_id,
    std::uint32_t pid,
    std::string_view process_guid,
    std::string& error_message);

[[nodiscard]] std::optional<std::string> derive_telemetry_event_id(
    std::string_view host_id,
    const telemetry::SourceProvenance& source,
    std::string_view category,
    std::string_view type,
    std::uint32_t pid,
    telemetry::UtcTimestamp timestamp,
    std::string& error_message);

}  // namespace panopticon::officer::core
