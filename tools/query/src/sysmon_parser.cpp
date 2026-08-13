#include "panopticon/officer/query/sysmon_parser.hpp"

#include <tinyxml2.h>

#include <charconv>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace panopticon::officer::query {
namespace {

using FieldMap = std::unordered_map<std::string, std::string>;

std::optional<std::string> child_text(const tinyxml2::XMLElement* parent, const char* name) {
    if (parent == nullptr) return std::nullopt;
    const auto* child = parent->FirstChildElement(name);
    return child == nullptr || child->GetText() == nullptr ? std::nullopt
                                                           : std::optional<std::string>(child->GetText());
}

std::optional<std::string> field(const FieldMap& fields, const char* name) {
    const auto found = fields.find(name);
    return found == fields.end() ? std::nullopt : std::optional<std::string>(found->second);
}

template <typename Integer>
std::optional<Integer> parse_integer(const std::optional<std::string>& value, const char* name,
                                     std::string& error) {
    if (!value) return std::nullopt;
    Integer parsed{};
    const auto [end, status] = std::from_chars(value->data(), value->data() + value->size(), parsed);
    if (status != std::errc{} || end != value->data() + value->size()) {
        error = "Sysmon field '" + std::string(name) + "' contains an invalid integer: '" + *value + "'.";
        return std::nullopt;
    }
    return parsed;
}

bool require_valid_number(const std::optional<std::string>& original, bool parsed) {
    return !original || parsed;
}

void set_process_context(TelemetryEvent& event, const FieldMap& fields, std::string& error) {
    event.timestamp = field(fields, "UtcTime");
    event.process.guid = field(fields, "ProcessGuid");
    event.process.image = field(fields, "Image");
    event.process.user = field(fields, "User");
    const auto pid_text = field(fields, "ProcessId");
    event.process.pid = parse_integer<std::uint32_t>(pid_text, "ProcessId", error);
}

bool process_context_is_valid(const FieldMap& fields, const TelemetryEvent& event) {
    return require_valid_number(field(fields, "ProcessId"), event.process.pid.has_value());
}

}  // namespace

std::optional<TelemetryEvent> SysmonParser::parse_xml(std::string_view xml, std::string& error_message) {
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS) {
        error_message = "Could not parse event XML: " + std::string(document.ErrorStr());
        return std::nullopt;
    }

    const auto* event_xml = document.FirstChildElement("Event");
    const auto* system = event_xml == nullptr ? nullptr : event_xml->FirstChildElement("System");
    const auto* event_data = event_xml == nullptr ? nullptr : event_xml->FirstChildElement("EventData");
    if (event_xml == nullptr || system == nullptr || event_data == nullptr) {
        error_message = "The XML does not contain the expected Event, System, and EventData sections.";
        return std::nullopt;
    }

    const auto event_id_text = child_text(system, "EventID");
    const auto event_id = parse_integer<std::uint32_t>(event_id_text, "System/EventID", error_message);
    if (!event_id) {
        if (error_message.empty()) error_message = "The XML is missing System/EventID.";
        return std::nullopt;
    }

    FieldMap fields;
    for (const auto* data = event_data->FirstChildElement("Data"); data != nullptr;
         data = data->NextSiblingElement("Data")) {
        if (const char* name = data->Attribute("Name")) {
            fields.insert_or_assign(name, data->GetText() == nullptr ? "" : data->GetText());
        }
    }

    TelemetryEvent result;
    result.source.event_id = event_id;
    if (const auto* provider = system->FirstChildElement("Provider")) {
        if (const char* name = provider->Attribute("Name")) result.source.provider = name;
    }
    result.source.channel = child_text(system, "Channel");
    result.host_name = child_text(system, "Computer");
    const auto record_id_text = child_text(system, "EventRecordID");
    result.source.record_id = parse_integer<std::uint64_t>(record_id_text, "System/EventRecordID", error_message);
    if (!require_valid_number(record_id_text, result.source.record_id.has_value())) return std::nullopt;

    set_process_context(result, fields, error_message);
    if (!process_context_is_valid(fields, result)) return std::nullopt;

    switch (*event_id) {
        case 1: {
            result.category = "process";
            result.type = "create";
            result.process.command_line = field(fields, "CommandLine");
            result.process.current_directory = field(fields, "CurrentDirectory");
            result.process.integrity_level = field(fields, "IntegrityLevel");
            result.process.hashes = field(fields, "Hashes");
            result.parent.guid = field(fields, "ParentProcessGuid");
            result.parent.image = field(fields, "ParentImage");
            result.parent.command_line = field(fields, "ParentCommandLine");
            const auto parent_pid_text = field(fields, "ParentProcessId");
            result.parent.pid = parse_integer<std::uint32_t>(parent_pid_text, "ParentProcessId", error_message);
            if (!require_valid_number(parent_pid_text, result.parent.pid.has_value())) return std::nullopt;
            break;
        }
        case 3: {
            result.category = "network";
            result.type = "connection";
            NetworkDetails network;
            network.protocol = field(fields, "Protocol");
            network.initiated = field(fields, "Initiated");
            network.source_ip = field(fields, "SourceIp");
            network.destination_ip = field(fields, "DestinationIp");
            network.destination_hostname = field(fields, "DestinationHostname");
            const auto source_port = field(fields, "SourcePort");
            const auto destination_port = field(fields, "DestinationPort");
            network.source_port = parse_integer<std::uint32_t>(source_port, "SourcePort", error_message);
            if (!require_valid_number(source_port, network.source_port.has_value())) return std::nullopt;
            network.destination_port = parse_integer<std::uint32_t>(destination_port, "DestinationPort", error_message);
            if (!require_valid_number(destination_port, network.destination_port.has_value())) return std::nullopt;
            result.network = std::move(network);
            break;
        }
        case 11: {
            result.category = "file";
            result.type = "create";
            result.file = FileDetails{field(fields, "TargetFilename"), field(fields, "CreationUtcTime")};
            break;
        }
        case 12:
        case 13:
        case 14: {
            result.category = "registry";
            result.type = *event_id == 12 ? "create_or_delete" : (*event_id == 13 ? "value_set" : "rename");
            result.registry = RegistryDetails{field(fields, "EventType"), field(fields, "TargetObject"),
                                              field(fields, "Details"), field(fields, "NewName")};
            break;
        }
        default:
            error_message = "Unsupported Sysmon Event ID " + std::to_string(*event_id) +
                            ". Supported IDs are 1, 3, 11, 12, 13, and 14.";
            return std::nullopt;
    }
    return result;
}

}  // namespace panopticon::officer::query
