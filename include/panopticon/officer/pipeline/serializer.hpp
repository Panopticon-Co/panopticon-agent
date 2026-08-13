#pragma once

#include "panopticon/officer/telemetry/panopticon_event.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::pipeline {

[[nodiscard]] nlohmann::json event_to_json(const telemetry::PanopticonEvent& event);
[[nodiscard]] std::string serialize_event(const telemetry::PanopticonEvent& event);
[[nodiscard]] std::optional<telemetry::PanopticonEvent> deserialize_event(
    std::string_view json_text,
    std::string& error_message);

}  // namespace panopticon::officer::pipeline
