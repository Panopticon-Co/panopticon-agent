#include "panopticon/officer/collectors/sysmon_process_decoder.hpp"

#include <tinyxml2.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace panopticon::officer::collectors {
namespace {

using FieldMap = std::unordered_map<std::string, std::string>;

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

std::optional<std::string> field(const FieldMap& fields, const char* name) {
    const auto found = fields.find(name);
    if (found == fields.end() || found->second.empty() || found->second == "-") {
        return std::nullopt;
    }
    return found->second;
}

template <typename Integer>
std::optional<Integer> parse_integer(
    const std::optional<std::string>& value,
    const char* name,
    std::string& error_message) {
    if (!value) {
        return std::nullopt;
    }
    Integer result{};
    const auto [end, status] = std::from_chars(
        value->data(), value->data() + value->size(), result);
    if (status != std::errc{} || end != value->data() + value->size()) {
        error_message = "Sysmon field '" + std::string{name} +
                        "' contains an invalid integer: '" + *value + "'.";
        return std::nullopt;
    }
    return result;
}

std::optional<unsigned int> decimal_component(
    std::string_view text,
    std::size_t offset,
    std::size_t length) {
    if (offset + length > text.size()) {
        return std::nullopt;
    }
    unsigned int value{};
    const char* begin = text.data() + offset;
    const char* end = begin + length;
    const auto [parsed_end, status] = std::from_chars(begin, end, value);
    return status == std::errc{} && parsed_end == end ? std::optional{value} : std::nullopt;
}

std::optional<telemetry::UtcTimestamp> parse_sysmon_utc(
    std::string_view text,
    std::string& error_message) {
    if (text.size() < 19 || text[4] != '-' || text[7] != '-' ||
        (text[10] != ' ' && text[10] != 'T') || text[13] != ':' || text[16] != ':') {
        error_message = "Sysmon UtcTime has an unsupported format: '" + std::string{text} + "'.";
        return std::nullopt;
    }

    const auto year = decimal_component(text, 0, 4);
    const auto month = decimal_component(text, 5, 2);
    const auto day = decimal_component(text, 8, 2);
    const auto hour = decimal_component(text, 11, 2);
    const auto minute = decimal_component(text, 14, 2);
    const auto second = decimal_component(text, 17, 2);
    if (!year || !month || !day || !hour || !minute || !second ||
        *hour > 23 || *minute > 59 || *second > 60) {
        error_message = "Sysmon UtcTime contains an invalid date or time: '" +
                        std::string{text} + "'.";
        return std::nullopt;
    }

    const std::chrono::year_month_day date{
        std::chrono::year{static_cast<int>(*year)},
        std::chrono::month{*month},
        std::chrono::day{*day}};
    if (!date.ok()) {
        error_message = "Sysmon UtcTime contains an invalid calendar date: '" +
                        std::string{text} + "'.";
        return std::nullopt;
    }

    std::chrono::nanoseconds fraction{};
    if (text.size() > 19) {
        if (text[19] != '.') {
            if (text[19] != 'Z' || text.size() != 20) {
                error_message = "Sysmon UtcTime has an invalid suffix: '" +
                                std::string{text} + "'.";
                return std::nullopt;
            }
        } else {
            std::size_t fraction_end = 20;
            while (fraction_end < text.size() && text[fraction_end] >= '0' &&
                   text[fraction_end] <= '9') {
                ++fraction_end;
            }
            const std::size_t digits = fraction_end - 20;
            if (digits == 0 || digits > 9 ||
                (fraction_end < text.size() &&
                 !(fraction_end + 1 == text.size() && text[fraction_end] == 'Z'))) {
                error_message = "Sysmon UtcTime has an invalid fractional value: '" +
                                std::string{text} + "'.";
                return std::nullopt;
            }
            const auto parsed_fraction = decimal_component(text, 20, digits);
            if (!parsed_fraction) {
                error_message = "Sysmon UtcTime has an invalid fractional value.";
                return std::nullopt;
            }
            std::uint64_t nanoseconds = *parsed_fraction;
            for (std::size_t index = digits; index < 9; ++index) {
                nanoseconds *= 10;
            }
            fraction = std::chrono::nanoseconds{nanoseconds};
        }
    }

    const auto base = std::chrono::sys_days{date} + std::chrono::hours{*hour} +
                      std::chrono::minutes{*minute} + std::chrono::seconds{*second};
    return telemetry::UtcTimestamp{
        std::chrono::duration_cast<std::chrono::nanoseconds>(base.time_since_epoch()) +
        fraction};
}

std::optional<std::string> extract_sha256(const std::optional<std::string>& hashes) {
    if (!hashes) {
        return std::nullopt;
    }
    constexpr std::string_view prefix = "SHA256=";
    std::size_t start = 0;
    while (start < hashes->size()) {
        const std::size_t end = hashes->find(',', start);
        const std::string_view entry{
            hashes->data() + start,
            (end == std::string::npos ? hashes->size() : end) - start};
        if (entry.size() >= prefix.size()) {
            bool matches = true;
            for (std::size_t index = 0; index < prefix.size(); ++index) {
                const char character = entry[index];
                const char expected = prefix[index];
                if (character != expected && character != expected + ('a' - 'A')) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                return std::string{entry.substr(prefix.size())};
            }
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
        while (start < hashes->size() && (*hashes)[start] == ' ') {
            ++start;
        }
    }
    return std::nullopt;
}

}  // namespace

std::optional<telemetry::RawProcessEvent> SysmonProcessDecoder::decode_xml(
    std::string_view xml,
    std::string& error_message) {
    error_message.clear();
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS) {
        error_message = "Could not parse Sysmon event XML: " +
                        std::string{document.ErrorStr()};
        return std::nullopt;
    }

    const auto* event = document.FirstChildElement("Event");
    const auto* system = event == nullptr ? nullptr : event->FirstChildElement("System");
    const auto* event_data = event == nullptr ? nullptr : event->FirstChildElement("EventData");
    if (event == nullptr || system == nullptr || event_data == nullptr) {
        error_message = "Sysmon XML is missing Event, System, or EventData.";
        return std::nullopt;
    }

    const auto event_id_text = child_text(system, "EventID");
    const auto event_id = parse_integer<std::uint32_t>(
        event_id_text, "System/EventID", error_message);
    if (!event_id) {
        if (error_message.empty()) {
            error_message = "Sysmon XML is missing System/EventID.";
        }
        return std::nullopt;
    }
    if (*event_id != 1) {
        error_message = "The live Sysmon process decoder accepts only Event ID 1.";
        return std::nullopt;
    }

    FieldMap fields;
    for (const auto* data = event_data->FirstChildElement("Data"); data != nullptr;
         data = data->NextSiblingElement("Data")) {
        if (const char* name = data->Attribute("Name")) {
            fields.insert_or_assign(name, data->GetText() == nullptr ? "" : data->GetText());
        }
    }

    const auto pid_text = field(fields, "ProcessId");
    const auto pid = parse_integer<std::uint32_t>(pid_text, "ProcessId", error_message);
    if (!pid) {
        if (error_message.empty()) {
            error_message = "Sysmon Event ID 1 is missing ProcessId.";
        }
        return std::nullopt;
    }
    const auto utc_text = field(fields, "UtcTime");
    if (!utc_text) {
        error_message = "Sysmon Event ID 1 is missing UtcTime.";
        return std::nullopt;
    }
    const auto timestamp = parse_sysmon_utc(*utc_text, error_message);
    if (!timestamp) {
        return std::nullopt;
    }

    const auto parent_pid_text = field(fields, "ParentProcessId");
    const auto parent_pid = parse_integer<std::uint32_t>(
        parent_pid_text, "ParentProcessId", error_message);
    if (parent_pid_text && !parent_pid) {
        return std::nullopt;
    }
    const auto record_id_text = child_text(system, "EventRecordID");
    const auto record_id = parse_integer<std::uint64_t>(
        record_id_text, "System/EventRecordID", error_message);
    if (record_id_text && !record_id) {
        return std::nullopt;
    }

    telemetry::RawProcessEvent result;
    result.source.kind = telemetry::TelemetrySourceKind::sysmon;
    result.source.provider = "Microsoft-Windows-Sysmon";
    if (const auto* provider = system->FirstChildElement("Provider")) {
        if (const char* provider_name = provider->Attribute("Name")) {
            result.source.provider = provider_name;
        }
    }
    result.source.channel = child_text(system, "Channel");
    result.source.record_id = record_id;
    result.process_start_time = *timestamp;
    result.pid = *pid;
    result.parent_pid = parent_pid;
    result.parent_executable = field(fields, "ParentImage");
    result.executable = field(fields, "Image");
    result.command_line = field(fields, "CommandLine");
    result.user_name = field(fields, "User");
    result.sha256 = extract_sha256(field(fields, "Hashes"));
    return result;
}

}  // namespace panopticon::officer::collectors
