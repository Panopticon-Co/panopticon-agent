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

}  // namespace panopticon::officer::core
