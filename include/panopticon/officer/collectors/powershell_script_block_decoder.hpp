#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::collectors {

// Decodes a rendered Microsoft-Windows-PowerShell/Operational EventID 4104
// (script block logging) event into a RawScriptBlockEvent (Schema 0.5).
//
// The event identifies the PowerShell host only by System/Execution@ProcessID
// and the user only by System/Security@UserID (a SID); it carries no image
// path. The collector backfills the image from its PID cache, exactly as it
// does for Sysmon events that report "<unknown process>". Time comes from
// System/TimeCreated. The script text is passed through whole; the wire cap is
// applied by the normalizer. Observed facts only.
class PowerShellScriptBlockDecoder {
public:
    static constexpr std::uint32_t kEventId = 4104;

    [[nodiscard]] static std::optional<telemetry::RawEvent> decode_xml(
        std::string_view xml,
        std::string& error_message);
};

}  // namespace panopticon::officer::collectors
