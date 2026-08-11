#include "eyetrace/sysmon_parser.hpp"

#include <tinyxml2.h>

#include <charconv>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace eyetrace {
namespace {

using FieldMap = std::unordered_map<std::string, std::string>;

std::optional<std::string> child_text(const tinyxml2::XMLElement* parent, const char* name) {
    if (parent == nullptr) {
        return std::nullopt;
    }

    const tinyxml2::XMLElement* child = parent->FirstChildElement(name);
    if (child == nullptr || child->GetText() == nullptr) {
        return std::nullopt;
    }
    return std::string(child->GetText());
}

std::optional<std::string> field_value(const FieldMap& fields, const char* name) {
    const auto field = fields.find(name);
    if (field == fields.end()) {
        return std::nullopt;
    }
    return field->second;
}

template <typename Integer>
std::optional<Integer> parse_integer(const std::optional<std::string>& value, const char* field_name,
                                     std::string& error_message) {
    if (!value.has_value()) {
        return std::nullopt;
    }

    Integer result = 0;
    const auto [end, error] = std::from_chars(value->data(), value->data() + value->size(), result);
    if (error != std::errc{} || end != value->data() + value->size()) {
        error_message = "Sysmon field '" + std::string(field_name) +
                        "' contains an invalid integer: '" + *value + "'.";
        return std::nullopt;
    }
    return result;
}

}  // namespace

std::optional<TelemetryEvent> SysmonParser::parse_process_create_xml(std::string_view xml,
                                                                       std::string& error_message) {
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS) {
        error_message = "Could not parse event XML: " + std::string(document.ErrorStr());
        return std::nullopt;
    }

    const tinyxml2::XMLElement* event = document.FirstChildElement("Event");
    const tinyxml2::XMLElement* system = event == nullptr ? nullptr : event->FirstChildElement("System");
    const tinyxml2::XMLElement* event_data =
        event == nullptr ? nullptr : event->FirstChildElement("EventData");
    if (event == nullptr || system == nullptr || event_data == nullptr) {
        error_message = "The XML does not contain the expected Event, System, and EventData sections.";
        return std::nullopt;
    }

    const tinyxml2::XMLElement* provider = system->FirstChildElement("Provider");
    const char* provider_name = provider == nullptr ? nullptr : provider->Attribute("Name");

    const std::optional<std::string> event_id_text = child_text(system, "EventID");
    const std::optional<std::uint32_t> event_id =
        parse_integer<std::uint32_t>(event_id_text, "System/EventID", error_message);
    if (!event_id.has_value()) {
        if (error_message.empty()) {
            error_message = "The XML is missing System/EventID.";
        }
        return std::nullopt;
    }
    if (*event_id != 1) {
        error_message = "This parser supports Sysmon Event ID 1, but the XML contains Event ID " +
                        std::to_string(*event_id) + ".";
        return std::nullopt;
    }

    const std::optional<std::string> record_id_text = child_text(system, "EventRecordID");
    const std::optional<std::uint64_t> record_id =
        parse_integer<std::uint64_t>(record_id_text, "System/EventRecordID", error_message);
    if (record_id_text.has_value() && !record_id.has_value()) {
        return std::nullopt;
    }

    FieldMap fields;
    for (const tinyxml2::XMLElement* data = event_data->FirstChildElement("Data"); data != nullptr;
         data = data->NextSiblingElement("Data")) {
        const char* name = data->Attribute("Name");
        if (name != nullptr) {
            fields.insert_or_assign(name, data->GetText() == nullptr ? "" : data->GetText());
        }
    }

    const std::optional<std::string> process_id_text = field_value(fields, "ProcessId");
    const std::optional<std::uint32_t> process_id =
        parse_integer<std::uint32_t>(process_id_text, "ProcessId", error_message);
    if (process_id_text.has_value() && !process_id.has_value()) {
        return std::nullopt;
    }

    const std::optional<std::string> parent_process_id_text = field_value(fields, "ParentProcessId");
    const std::optional<std::uint32_t> parent_process_id =
        parse_integer<std::uint32_t>(parent_process_id_text, "ParentProcessId", error_message);
    if (parent_process_id_text.has_value() && !parent_process_id.has_value()) {
        return std::nullopt;
    }

    TelemetryEvent telemetry_event;
    telemetry_event.source.provider = provider_name == nullptr ? std::nullopt
                                                                : std::optional<std::string>(provider_name);
    telemetry_event.source.channel = child_text(system, "Channel");
    telemetry_event.source.event_id = event_id;
    telemetry_event.source.record_id = record_id;
    telemetry_event.host_name = child_text(system, "Computer");
    telemetry_event.timestamp = field_value(fields, "UtcTime");
    telemetry_event.process.guid = field_value(fields, "ProcessGuid");
    telemetry_event.process.pid = process_id;
    telemetry_event.process.image = field_value(fields, "Image");
    telemetry_event.process.command_line = field_value(fields, "CommandLine");
    telemetry_event.process.current_directory = field_value(fields, "CurrentDirectory");
    telemetry_event.process.user = field_value(fields, "User");
    telemetry_event.process.integrity_level = field_value(fields, "IntegrityLevel");
    telemetry_event.process.hashes = field_value(fields, "Hashes");
    telemetry_event.parent.guid = field_value(fields, "ParentProcessGuid");
    telemetry_event.parent.pid = parent_process_id;
    telemetry_event.parent.image = field_value(fields, "ParentImage");
    telemetry_event.parent.command_line = field_value(fields, "ParentCommandLine");
    return telemetry_event;
}

}  // namespace eyetrace
