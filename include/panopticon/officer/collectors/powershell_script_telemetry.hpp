#pragma once

#include <nlohmann/json.hpp>
#include <string_view>

namespace panopticon::officer::collectors {

// Read-only inspection of the two Windows PowerShell event channels and the
// documented PowerShell Group Policy values. This function never enables a
// channel, writes registry values, or changes PowerShell policy.
[[nodiscard]] nlohmann::json inspect_powershell_logging_coverage();

// Adds source-native PowerShell semantics while retaining the original XML,
// System fields, and every EventData element. Script block messages are
// represented as fragments; this decoder never joins fragments into a script.
[[nodiscard]] nlohmann::json decode_powershell_event_xml(
    std::string_view xml, std::string_view requested_channel);

}  // namespace panopticon::officer::collectors
