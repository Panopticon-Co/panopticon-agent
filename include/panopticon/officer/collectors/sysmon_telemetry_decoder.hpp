#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::collectors {

// Decodes a rendered Sysmon Operational event (XML string) into one of the V3
// raw telemetry-family events. Handles:
//   * Event ID 3            -> RawNetworkEvent
//   * Event ID 7            -> RawImageLoadEvent
//   * Event ID 11           -> RawFileEvent (create)
//   * Event ID 23 / 26      -> RawFileEvent (delete)
//   * Event ID 12           -> RawRegistryEvent (add_key / delete_key)
//   * Event ID 13           -> RawRegistryEvent (set_value)
//   * Event ID 14           -> RawRegistryEvent (rename_key)
//   * Event ID 5            -> RawProcessStopEvent           (Schema 0.5)
//   * Event ID 8            -> RawRemoteThreadEvent          (Schema 0.5)
//   * Event ID 10           -> RawProcessAccessEvent         (Schema 0.5)
//   * Event ID 22           -> RawDnsEvent                   (Schema 0.5)
//
// Event ID 1 (process create) is intentionally NOT handled here -- it stays with
// SysmonProcessDecoder so the live V1/V2 process path is untouched. This decoder
// carries observed facts only: no value contents, no file contents, no payload.
class SysmonTelemetryDecoder {
public:
    [[nodiscard]] static std::optional<telemetry::RawEvent> decode_xml(
        std::string_view xml,
        std::string& error_message);
};

// Parses an Event Log time -- Sysmon's "yyyy-MM-dd HH:mm:ss.fff" UtcTime or a
// System/TimeCreated SystemTime "yyyy-MM-ddTHH:mm:ss.fffffffZ" -- as UTC. Shared
// by the Windows Event Log decoders so they cannot disagree on time.
[[nodiscard]] std::optional<telemetry::UtcTimestamp> parse_event_log_time(
    std::string_view text,
    std::string& error_message);

}  // namespace panopticon::officer::collectors
