#pragma once

#include "eyetrace/telemetry_event.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace eyetrace {

class SysmonParser {
public:
    // Parses one Sysmon Event ID 1 XML document. Missing optional fields remain
    // empty; malformed XML or numeric fields produce a descriptive error.
    [[nodiscard]] static std::optional<TelemetryEvent> parse_process_create_xml(
        std::string_view xml, std::string& error_message);
};

}  // namespace eyetrace
