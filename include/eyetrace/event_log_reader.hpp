#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace eyetrace {

class EventLogReader {
public:
    // Returns at most limit newest recorded Sysmon records for event_id as raw XML.
    // On failure, returns std::nullopt and fills error_message.
    [[nodiscard]] static std::optional<std::vector<std::string>>
    read_newest_event_xmls(std::uint32_t event_id, std::size_t limit, std::string& error_message);
};

}  // namespace eyetrace
