#include "panopticon/officer/collectors/sysmon_telemetry_decoder.hpp"

#include <tinyxml2.h>

#include <charconv>
#include <algorithm>
#include <limits>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

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

std::optional<unsigned int> decimal_component(std::string_view text, std::size_t offset, std::size_t length) {
    if (offset + length > text.size()) {
        return std::nullopt;
    }
    unsigned int value{};
    const char* begin = text.data() + offset;
    const char* end = begin + length;
    const auto [parsed_end, status] = std::from_chars(begin, end, value);
    return status == std::errc{} && parsed_end == end ? std::optional{value} : std::nullopt;
}

// Sysmon UtcTime: "yyyy-MM-dd HH:mm:ss.fff" (millisecond fraction, no zone).
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
    if (!date.ok() || *year < 1678 || *year > 2261) {
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
        if (entry.size() > prefix.size()) {
            bool matches = true;
            for (std::size_t index = 0; index < prefix.size(); ++index) {
                const char c = entry[index];
                const char expected = prefix[index];
                if (c != expected && c != expected + ('a' - 'A')) {
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

std::optional<std::uint16_t> parse_port(
    const std::optional<std::string>& value, const char* name, std::string& error_message) {
    const auto parsed = parse_integer<std::uint32_t>(value, name, error_message);
    if (!parsed) {
        return std::nullopt;
    }
    if (*parsed > 65535) {
        error_message = "Sysmon field '" + std::string{name} + "' is not a valid port.";
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(*parsed);
}

std::optional<std::string> leaf_segment(const std::optional<std::string>& path) {
    if (!path || path->empty()) {
        return std::nullopt;
    }
    const std::size_t sep = path->find_last_of('\\');
    return sep == std::string::npos ? *path : path->substr(sep + 1);
}

// Maps a Sysmon EID 13 "Details" string to a REG_* type name WITHOUT retaining
// the value contents (metadata-only policy).
std::optional<std::string> registry_value_type(const std::optional<std::string>& details) {
    if (!details) {
        return std::nullopt;
    }
    const std::string& d = *details;
    if (d.rfind("DWORD", 0) == 0) return "REG_DWORD";
    if (d.rfind("QWORD", 0) == 0) return "REG_QWORD";
    if (d.rfind("Binary Data", 0) == 0) return "REG_BINARY";
    return "REG_SZ";
}

bool truthy(const std::optional<std::string>& value) {
    if (!value) {
        return false;
    }
    return *value == "true" || *value == "True" || *value == "TRUE" || *value == "1";
}

telemetry::RawProcessContext make_process_context(const FieldMap& fields) {
    telemetry::RawProcessContext ctx;
    std::string ignored;
    const auto pid = parse_integer<std::uint32_t>(field(fields, "ProcessId"), "ProcessId", ignored);
    ctx.pid = pid.value_or(0);
    ctx.executable = field(fields, "Image");
    ctx.process_guid = field(fields, "ProcessGuid");
    ctx.user_name = field(fields, "User");
    return ctx;
}

std::optional<telemetry::RawProcessContext> exact_source_context(
    const FieldMap& fields, const std::string& prefix, std::string& error) {
    const auto pid_name = prefix + "ProcessId";
    const auto pid = parse_integer<std::uint32_t>(field(fields, pid_name.c_str()), pid_name.c_str(), error);
    if (!pid) { if (error.empty()) error = "Sysmon event is missing " + pid_name; return std::nullopt; }
    telemetry::RawProcessContext result;
    result.pid = *pid;
    result.executable = field(fields, (prefix + "Image").c_str());
    result.user_name = field(fields, (prefix + "User").c_str());
    const auto lower = field(fields, (prefix + "ProcessGuid").c_str());
    const auto upper = field(fields, (prefix + "ProcessGUID").c_str());
    if (lower && upper && *lower != *upper) { error = "Conflicting Sysmon process GUID aliases"; return std::nullopt; }
    result.process_guid = lower ? lower : upper;
    return result;
}

std::optional<std::uint64_t> hex_value(const FieldMap& fields, const char* name, std::string& error) {
    const auto value = field(fields, name);
    if (!value) return std::nullopt;
    std::string_view digits = *value;
    if (digits.starts_with("0x") || digits.starts_with("0X")) digits.remove_prefix(2);
    std::uint64_t number{};
    const auto [end, status] = std::from_chars(digits.data(), digits.data() + digits.size(), number, 16);
    if (digits.empty() || status != std::errc{} || end != digits.data() + digits.size()) {
        error = "Invalid or overflowing Sysmon hexadecimal field: " + std::string{name}; return std::nullopt;
    }
    return number;
}

}  // namespace

std::optional<telemetry::RawEvent> SysmonTelemetryDecoder::decode_xml(
    std::string_view xml,
    std::string& error_message) {
    error_message.clear();
    if (xml.empty() || xml.size() > 256u * 1024 || xml.find('\0') != std::string_view::npos) {
        error_message = "Sysmon XML exceeds the 256 KiB decoded-event admission bound";
        return std::nullopt;
    }
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS) {
        error_message = "Could not parse Sysmon event XML: " + std::string{document.ErrorStr()};
        return std::nullopt;
    }

    const auto* event = document.FirstChildElement("Event");
    const auto* system = event == nullptr ? nullptr : event->FirstChildElement("System");
    const auto* event_data = event == nullptr ? nullptr : event->FirstChildElement("EventData");
    if (event == nullptr || system == nullptr || event_data == nullptr || event->NextSiblingElement() ||
        system->NextSiblingElement("System") || event_data->NextSiblingElement("EventData")) {
        error_message = "Sysmon XML is missing Event, System, or EventData.";
        return std::nullopt;
    }
    for (const auto* name : {"Provider", "Channel", "EventID", "EventRecordID", "TimeCreated"}) {
        const auto* first = system->FirstChildElement(name);
        if (first && first->NextSiblingElement(name)) {
            error_message = "Ambiguous duplicate Sysmon System field"; return std::nullopt;
        }
    }

    const auto event_id_text = child_text(system, "EventID");
    const auto event_id = parse_integer<std::uint32_t>(event_id_text, "System/EventID", error_message);
    if (!event_id) {
        if (error_message.empty()) {
            error_message = "Sysmon XML is missing System/EventID.";
        }
        return std::nullopt;
    }

    FieldMap fields;
    for (const auto* data = event_data->FirstChildElement("Data"); data != nullptr;
         data = data->NextSiblingElement("Data")) {
        if (const char* name = data->Attribute("Name")) {
            if (std::string_view{name}.empty() || std::string_view{name}.size() > 128 || fields.size() >= 64 ||
                !fields.emplace(name, data->GetText() == nullptr ? "" : data->GetText()).second) {
                error_message = "Sysmon named field is duplicate, invalid or beyond the field-count bound";
                return std::nullopt;
            }
        } else { error_message = "Sysmon Data field has no name"; return std::nullopt; }
    }

    // Prefer the Event Log's own System/TimeCreated over EventData/UtcTime.
    // Sysmon's UtcTime for EID 3 (NetworkConnect) is unreliable on some builds
    // -- it has been observed hours out from the real connection time, which
    // breaks cross-family time-window correlation -- whereas TimeCreated is
    // stamped by the Event Log service and is authoritative. UtcTime remains
    // the fallback (and is all the synthetic test fixtures carry).
    std::optional<telemetry::UtcTimestamp> timestamp;
    if (const auto* time_created = system->FirstChildElement("TimeCreated")) {
        if (const char* system_time = time_created->Attribute("SystemTime")) {
            std::string ignored;
            timestamp = parse_sysmon_utc(system_time, ignored);
        }
    }
    const auto utc_text = field(fields, "UtcTime");
    if (!timestamp) {
        if (!utc_text) {
            error_message =
                "Sysmon telemetry event " + std::to_string(*event_id) +
                " has neither System/TimeCreated nor EventData/UtcTime.";
            return std::nullopt;
        }
        timestamp = parse_sysmon_utc(*utc_text, error_message);
        if (!timestamp) {
            return std::nullopt;
        }
    }

    telemetry::SourceProvenance source;
    source.kind = telemetry::TelemetrySourceKind::sysmon;
    source.provider = "Microsoft-Windows-Sysmon";
    if (const auto* provider = system->FirstChildElement("Provider")) {
        if (const char* provider_name = provider->Attribute("Name")) {
            source.provider = provider_name;
        }
    }
    source.channel = child_text(system, "Channel");
    {
        std::string record_error;
        source.record_id = parse_integer<std::uint64_t>(
            child_text(system, "EventRecordID"), "System/EventRecordID", record_error);
        if (!record_error.empty()) { error_message = record_error; return std::nullopt; }
    }

    telemetry::RawProcessContext process = make_process_context(fields);

    switch (*event_id) {
        case 8:
        case 10:
        case 22: {
            const auto* native_provider = system->FirstChildElement("Provider");
            if (!native_provider || !native_provider->Attribute("Name") || source.provider != "Microsoft-Windows-Sysmon" ||
                source.channel != std::optional<std::string>{"Microsoft-Windows-Sysmon/Operational"}) {
                error_message = "Extended Sysmon event has the wrong provider/channel"; return std::nullopt;
            }
            telemetry::RawSysmonExtendedEvent out;
            out.source = source;
            out.event_id = static_cast<std::uint16_t>(*event_id);
            out.timestamp = *timestamp;
            out.event_time_field = "System/TimeCreated";
            // Match training adapter semantics: Sysmon's own event clock is primary.
            if (utc_text) {
                const auto source_time = parse_sysmon_utc(*utc_text, error_message);
                if (!source_time) return std::nullopt;
                out.timestamp = *source_time; out.event_time_field = "EventData/UtcTime";
            } else if (!system->FirstChildElement("TimeCreated")) {
                error_message = "Extended Sysmon event has no event clock"; return std::nullopt;
            }
            auto actor = exact_source_context(fields, *event_id == 22 ? "" : "Source", error_message);
            if (!actor) return std::nullopt;
            out.process = std::move(*actor);
            if (*event_id != 22) {
                out.target = exact_source_context(fields, "Target", error_message);
                if (!out.target) return std::nullopt;
            }
            if (*event_id == 10) {
                out.granted_access = hex_value(fields, "GrantedAccess", error_message);
                if (!error_message.empty()) return std::nullopt;
                if (out.granted_access && *out.granted_access > std::numeric_limits<std::uint32_t>::max()) {
                    error_message = "Sysmon access mask exceeds 32 bits"; return std::nullopt;
                }
                out.call_trace = field(fields, "CallTrace");
            } else if (*event_id == 8) {
                out.start_address = hex_value(fields, "StartAddress", error_message);
                if (!error_message.empty()) return std::nullopt;
                out.new_thread_id = parse_integer<std::uint32_t>(field(fields, "NewThreadId"), "NewThreadId", error_message);
                if (!error_message.empty()) return std::nullopt;
                out.start_module = field(fields, "StartModule");
                out.start_function = field(fields, "StartFunction");
            } else {
                out.query_name = field(fields, "QueryName");
                out.query_results = field(fields, "QueryResults");
                out.query_status = parse_integer<std::uint32_t>(field(fields, "QueryStatus"), "QueryStatus", error_message);
                if (!error_message.empty()) return std::nullopt;
            }
            out.source_fields.assign(fields.begin(), fields.end());
            std::sort(out.source_fields.begin(), out.source_fields.end());
            return telemetry::RawEvent{std::move(out)};
        }
        case 3: {
            telemetry::RawNetworkEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            out.direction = truthy(field(fields, "Initiated"))
                                ? telemetry::NetworkDirection::outbound
                                : telemetry::NetworkDirection::inbound;
            const auto protocol = field(fields, "Protocol");
            if (protocol && (*protocol == "tcp" || *protocol == "TCP")) {
                out.protocol = telemetry::NetworkProtocol::tcp;
            } else if (protocol && (*protocol == "udp" || *protocol == "UDP")) {
                out.protocol = telemetry::NetworkProtocol::udp;
            } else {
                out.protocol = telemetry::NetworkProtocol::other;
            }
            out.source_ip = field(fields, "SourceIp");
            out.destination_ip = field(fields, "DestinationIp");
            out.destination_hostname = field(fields, "DestinationHostname");
            std::string port_error;
            out.source_port = parse_port(field(fields, "SourcePort"), "SourcePort", port_error);
            if (!port_error.empty()) { error_message = port_error; return std::nullopt; }
            out.destination_port =
                parse_port(field(fields, "DestinationPort"), "DestinationPort", port_error);
            if (!port_error.empty()) { error_message = port_error; return std::nullopt; }
            return telemetry::RawEvent{std::move(out)};
        }
        case 7: {
            telemetry::RawImageLoadEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            out.path = field(fields, "ImageLoaded");
            const auto signed_field = field(fields, "Signed");
            if (signed_field) {
                out.is_signed = truthy(signed_field);
            }
            out.signature_status = field(fields, "SignatureStatus");
            out.sha256 = extract_sha256(field(fields, "Hashes"));
            return telemetry::RawEvent{std::move(out)};
        }
        case 11: {
            telemetry::RawFileEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            out.operation = telemetry::FileOperation::create;
            out.path = field(fields, "TargetFilename");
            out.sha256 = extract_sha256(field(fields, "Hashes"));
            return telemetry::RawEvent{std::move(out)};
        }
        case 23:
        case 26: {
            telemetry::RawFileEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            out.operation = telemetry::FileOperation::remove;
            out.path = field(fields, "TargetFilename");
            out.sha256 = extract_sha256(field(fields, "Hashes"));
            return telemetry::RawEvent{std::move(out)};
        }
        case 12: {
            telemetry::RawRegistryEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            const auto sysmon_op = field(fields, "EventType");
            out.operation = (sysmon_op && *sysmon_op == "DeleteKey")
                                ? telemetry::RegistryOperation::delete_key
                                : telemetry::RegistryOperation::add_key;
            out.key_path = field(fields, "TargetObject");
            return telemetry::RawEvent{std::move(out)};
        }
        case 13: {
            telemetry::RawRegistryEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            out.operation = telemetry::RegistryOperation::set_value;
            out.key_path = field(fields, "TargetObject");
            out.value_name = leaf_segment(out.key_path);
            out.value_type = registry_value_type(field(fields, "Details"));
            // value_data intentionally left unset (metadata-only policy).
            return telemetry::RawEvent{std::move(out)};
        }
        case 14: {
            telemetry::RawRegistryEvent out;
            out.source = source;
            out.timestamp = *timestamp;
            out.process = process;
            out.operation = telemetry::RegistryOperation::rename_key;
            out.key_path = field(fields, "TargetObject");
            return telemetry::RawEvent{std::move(out)};
        }
        default:
            error_message = "Sysmon Event ID " + std::to_string(*event_id) +
                            " is not a supported telemetry family (expected 3, 7, 8, 10, 11, 12, 13, 14, 22, 23, or 26).";
            return std::nullopt;
    }
}

}  // namespace panopticon::officer::collectors
