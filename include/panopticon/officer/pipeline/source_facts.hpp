#pragma once
#include "panopticon/officer/telemetry/raw_process_event.hpp"
#include <nlohmann/json.hpp>
#include <string_view>

namespace panopticon::officer::pipeline {
[[nodiscard]] bool valid_utf8(std::string_view text);
// Invalid UTF-8 is preserved as hexadecimal bytes, never replaced or discarded.
[[nodiscard]] nlohmann::json lossless_text(std::string_view text);
[[nodiscard]] std::string observed_source_kind_name(telemetry::TelemetrySourceKind kind);
[[nodiscard]] nlohmann::json source_facts(const telemetry::RawEvent& raw);
[[nodiscard]] nlohmann::json enrichment_facts(const telemetry::RawEvent& raw);
[[nodiscard]] bool cached_context_applicable(const telemetry::SourceProvenance& source, const telemetry::RawProcessContext& process);
}
