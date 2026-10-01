#include "panopticon/officer/collectors/powershell_script_block_decoder.hpp"

#include "panopticon/officer/collectors/sysmon_telemetry_decoder.hpp"

#include <tinyxml2.h>

#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace panopticon::officer::collectors {
namespace {

std::optional<std::string> child_text(const tinyxml2::XMLElement* parent, const char* name) {
    if (parent == nullptr) {
        return std::nullopt;
    }
    const auto* child = parent->FirstChildElement(name);
    if (child == nullptr || child->GetText() == nullptr) {
        return std::nullopt;
    }
    return std::string{child->GetText()};
}

// Attribute of a System child element, e.g. Execution@ProcessID, Security@UserID.
std::optional<std::string> child_attribute(
    const tinyxml2::XMLElement* parent, const char* element, const char* attribute) {
    if (parent == nullptr) {
        return std::nullopt;
    }
    const auto* child = parent->FirstChildElement(element);
    if (child == nullptr) {
        return std::nullopt;
    }
    const char* value = child->Attribute(attribute);
    return value == nullptr ? std::nullopt : std::optional<std::string>{value};
}

std::optional<std::string> clean(const std::optional<std::string>& value) {
    if (!value || value->empty() || *value == "-") {
        return std::nullopt;
    }
    return value;
}

template <typename Integer>
std::optional<Integer> parse_integer(const std::optional<std::string>& value) {
    if (!value) {
        return std::nullopt;
    }
    Integer result{};
    const auto [end, status] = std::from_chars(value->data(), value->data() + value->size(), result);
    return status == std::errc{} && end == value->data() + value->size()
               ? std::optional<Integer>{result}
               : std::nullopt;
}

}  // namespace

std::optional<telemetry::RawEvent> PowerShellScriptBlockDecoder::decode_xml(
    std::string_view xml,
    std::string& error_message) {
    error_message.clear();
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS) {
        error_message = "Could not parse PowerShell event XML: " + std::string{document.ErrorStr()};
        return std::nullopt;
    }

    const auto* event = document.FirstChildElement("Event");
    const auto* system = event == nullptr ? nullptr : event->FirstChildElement("System");
    const auto* event_data = event == nullptr ? nullptr : event->FirstChildElement("EventData");
    if (event == nullptr || system == nullptr || event_data == nullptr) {
        error_message = "PowerShell XML is missing Event, System, or EventData.";
        return std::nullopt;
    }

    const auto event_id = parse_integer<std::uint32_t>(child_text(system, "EventID"));
    if (!event_id) {
        error_message = "PowerShell XML is missing a numeric System/EventID.";
        return std::nullopt;
    }
    if (*event_id != kEventId) {
        error_message = "PowerShell Event ID " + std::to_string(*event_id) +
                        " is not a script block (expected 4104).";
        return std::nullopt;
    }

    // EventData is a list of <Data Name="...">value</Data>.
    std::unordered_map<std::string, std::string> fields;
    for (const auto* data = event_data->FirstChildElement("Data"); data != nullptr;
         data = data->NextSiblingElement("Data")) {
        if (const char* name = data->Attribute("Name")) {
            fields.insert_or_assign(name, data->GetText() == nullptr ? "" : data->GetText());
        }
    }
    const auto field = [&](const char* name) -> std::optional<std::string> {
        const auto found = fields.find(name);
        return found == fields.end() ? std::nullopt : std::optional<std::string>{found->second};
    };

    std::optional<telemetry::UtcTimestamp> timestamp;
    if (const auto system_time = child_attribute(system, "TimeCreated", "SystemTime")) {
        std::string ignored;
        timestamp = parse_event_log_time(*system_time, ignored);
    }
    if (!timestamp) {
        error_message = "PowerShell 4104 event has no usable System/TimeCreated.";
        return std::nullopt;
    }

    const auto pid =
        parse_integer<std::uint32_t>(clean(child_attribute(system, "Execution", "ProcessID")));
    if (!pid) {
        error_message = "PowerShell 4104 event has no System/Execution ProcessID.";
        return std::nullopt;
    }

    telemetry::SourceProvenance source;
    source.kind = telemetry::TelemetrySourceKind::windows_event_log;
    source.provider = "Microsoft-Windows-PowerShell";
    if (const auto* provider = system->FirstChildElement("Provider")) {
        if (const char* name = provider->Attribute("Name")) {
            source.provider = name;
        }
    }
    source.channel = clean(child_text(system, "Channel"));
    source.record_id = parse_integer<std::uint64_t>(clean(child_text(system, "EventRecordID")));

    telemetry::RawScriptBlockEvent out;
    out.source = source;
    out.timestamp = *timestamp;
    out.process.pid = *pid;
    // 4104 carries no image path or ProcessGuid; the collector backfills the
    // image from its PID cache. The user is a SID only.
    out.process.user_sid = clean(child_attribute(system, "Security", "UserID"));
    out.script_block_id = clean(field("ScriptBlockId"));
    out.message_number = parse_integer<std::uint32_t>(clean(field("MessageNumber")));
    out.message_total = parse_integer<std::uint32_t>(clean(field("MessageTotal")));
    out.path = clean(field("Path"));
    out.text = field("ScriptBlockText");  // kept whole; the normalizer caps it
    return telemetry::RawEvent{std::move(out)};
}

}  // namespace panopticon::officer::collectors
