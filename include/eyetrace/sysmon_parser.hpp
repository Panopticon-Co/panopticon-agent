#pragma once

#include "eyetrace/telemetry_event.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace eyetrace {

class SysmonParser {
public:
    // Parses supported Sysmon XML (IDs 1, 3, 11, and 12-14). Missing optional
    // fields remain empty; malformed XML or numeric fields produce an error.
    [[nodiscard]] static std::optional<TelemetryEvent> parse_xml(
        std::string_view xml, std::string& error_message);
};

}  // namespace eyetrace
