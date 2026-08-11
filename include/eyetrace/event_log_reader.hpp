#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace eyetrace {

class EventLogReader {
public:
    // Returns at most limit newest recorded Sysmon Event ID 1 records as raw XML.
    // On failure, returns std::nullopt and fills error_message.
    [[nodiscard]] static std::optional<std::vector<std::string>>
    read_newest_process_creation_xmls(std::size_t limit, std::string& error_message);
};

}  // namespace eyetrace
