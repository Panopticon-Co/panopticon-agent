#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::collectors {

class SysmonProcessDecoder {
public:
    [[nodiscard]] static std::optional<telemetry::RawProcessEvent> decode_xml(
        std::string_view xml,
        std::string& error_message);
};

}  // namespace panopticon::officer::collectors
