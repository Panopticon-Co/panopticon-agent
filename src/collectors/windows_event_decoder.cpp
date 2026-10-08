#include "panopticon/officer/collectors/windows_event_log.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tinyxml2.h>
#include <charconv>
#include <limits>
#include <string_view>
namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
const tinyxml2::XMLElement* child(const tinyxml2::XMLElement* parent, const char* name) {
    return parent ? parent->FirstChildElement(name) : nullptr;
}
Json text(const tinyxml2::XMLElement* node) { return node && node->GetText() ? Json(node->GetText()) : Json(nullptr); }
Json attribute(const tinyxml2::XMLElement* node, const char* name) {
    return node && node->Attribute(name) ? Json(node->Attribute(name)) : Json(nullptr);
}
std::optional<std::uint64_t> number(const Json& input, std::uint64_t maximum) {
    if (!input.is_string()) return std::nullopt;
    const auto& value = input.get_ref<const std::string&>(); std::uint64_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result > maximum) return std::nullopt;
    return result;
}
std::optional<telemetry::UtcTimestamp> timestamp(const Json& input) {
    if (!input.is_string()) return std::nullopt;
    const auto& value = input.get_ref<const std::string&>();
    if (value.size() < 20 || value.size() > 28 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
        value[13] != ':' || value[16] != ':' || value.back() != 'Z') return std::nullopt;
    auto digits = [&](std::size_t at, std::size_t count) -> std::optional<unsigned> {
        unsigned n = 0;
        for (std::size_t i = at; i < at + count; ++i) { if (value[i] < '0' || value[i] > '9') return std::nullopt; n = n * 10 + value[i] - '0'; }
        return n;
    };
    const auto year = digits(0,4), month = digits(5,2), day = digits(8,2), hour = digits(11,2), minute = digits(14,2), second = digits(17,2);
    if (!year || !month || !day || !hour || !minute || !second) return std::nullopt;
    unsigned fraction = 0;
    if (value.size() != 20) {
        if (value[19] != '.' || value.size() < 22) return std::nullopt;
        const auto length = value.size() - 21; const auto parsed = digits(20,length); if (!parsed) return std::nullopt;
        fraction = *parsed; for (std::size_t i = length; i < 7; ++i) fraction *= 10;
    }
    SYSTEMTIME system{}; system.wYear = static_cast<WORD>(*year); system.wMonth = static_cast<WORD>(*month);
    system.wDay = static_cast<WORD>(*day); system.wHour = static_cast<WORD>(*hour); system.wMinute = static_cast<WORD>(*minute); system.wSecond = static_cast<WORD>(*second);
    FILETIME native{}; SYSTEMTIME roundtrip{};
    if (!SystemTimeToFileTime(&system, &native) || !FileTimeToSystemTime(&native, &roundtrip) ||
        roundtrip.wYear != system.wYear || roundtrip.wMonth != system.wMonth || roundtrip.wDay != system.wDay ||
        roundtrip.wHour != system.wHour || roundtrip.wMinute != system.wMinute || roundtrip.wSecond != system.wSecond) return std::nullopt;
    const auto ticks = (static_cast<std::uint64_t>(native.dwHighDateTime) << 32) | native.dwLowDateTime;
    constexpr std::uint64_t epoch = 116444736000000000ull;
    constexpr auto bound = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() / 100);
    if (ticks >= epoch) {
        if (ticks - epoch > bound || fraction > bound - (ticks - epoch)) return std::nullopt;
        return telemetry::UtcTimestamp{std::chrono::nanoseconds{static_cast<std::int64_t>((ticks - epoch + fraction) * 100)}};
    }
    if (epoch - ticks > bound || epoch - ticks < fraction) return std::nullopt;
    return telemetry::UtcTimestamp{std::chrono::nanoseconds{-static_cast<std::int64_t>((epoch - ticks - fraction) * 100)}};
}
}
DecodedWindowsEvent decode_windows_event_xml(const std::string& xml, const std::string& requested) {
    DecodedWindowsEvent result;
    auto& data = result.data;
    data = {{"format", "windows_event_xml_v1"}, {"requested_channel", requested}, {"rendered_xml", xml},
        {"native_binary_bytes_retained", false}, {"process_reference", nullptr}, {"actor_verified", false},
        {"decode_state", "degraded"}, {"provider_name", nullptr}, {"event_record_id", nullptr},
        {"event_data", Json::array()}, {"semantic_family", "unclassified"}};
    tinyxml2::XMLDocument document;
    if (xml.size() > 196608 || xml.find('\0') != std::string::npos || document.Parse(xml.data(),xml.size()) != tinyxml2::XML_SUCCESS) {
        data["validation_error"] = "xml_uninterpreted"; return result;
    }
    const auto* root = document.RootElement();
    if (!root || std::string_view{root->Name()} != "Event" || root->NextSiblingElement()) {
        data["validation_error"] = "event_root_uninterpreted"; return result;
    }
    const auto* system = child(root,"System"); const auto* provider = child(system,"Provider");
    bool ambiguous = system && system->NextSiblingElement("System");
    for (const auto* field : {"Provider", "EventID", "EventRecordID", "TimeCreated", "Channel", "Execution", "Security", "Correlation"}) {
        const auto* first = child(system, field);
        if (first && first->NextSiblingElement(field)) ambiguous = true;
    }
    data["provider_name"] = attribute(provider,"Name"); data["provider_guid"] = attribute(provider,"Guid");
    data["native_channel"] = text(child(system,"Channel")); data["computer"] = text(child(system,"Computer"));
    for (const auto* field : {"EventID","Version","Level","Task","Opcode","Keywords","EventRecordID"}) data["system_fields"][field] = text(child(system,field));
    const auto id = number(data["system_fields"]["EventID"],65535), record = number(data["system_fields"]["EventRecordID"],std::numeric_limits<std::uint64_t>::max());
    if (record) data["event_record_id"] = std::to_string(*record);
    data["execution"] = {{"reported_writer_pid", attribute(child(system,"Execution"),"ProcessID")},
        {"reported_writer_tid", attribute(child(system,"Execution"),"ThreadID")}, {"subject_process_identity_verified", false}};
    data["security_user_id"] = attribute(child(system,"Security"),"UserID");
    data["correlation"] = {{"activity_id", attribute(child(system,"Correlation"),"ActivityID")},
        {"related_activity_id", attribute(child(system,"Correlation"),"RelatedActivityID")}};
    data["native_system_time"] = attribute(child(system,"TimeCreated"),"SystemTime"); result.event_time = timestamp(data["native_system_time"]);
    if (ambiguous) { result.event_time.reset(); data["event_record_id"] = nullptr; data["validation_error"] = "ambiguous_system_fields"; }
    if (const auto* values = child(root,"EventData")) {
        unsigned count = 0;
        for (auto* value = values->FirstChildElement(); value; value = value->NextSiblingElement()) {
            if (++count > 1024) { data["event_data_bound_exceeded"] = true; break; }
            tinyxml2::XMLPrinter printer(nullptr, true); value->Accept(&printer);
            data["event_data"].push_back({{"element", value->Name()}, {"name", attribute(value,"Name")},
                {"text", text(value)}, {"element_xml", printer.CStr()}});
        }
    }
    data["channel_matches_request"] = data["native_channel"] == requested;
    if (requested == "Security" && data["provider_name"] == "Microsoft-Windows-Security-Auditing") data["semantic_family"] = "security_audit";
    else if (requested.find("PowerShell") != std::string::npos) data["semantic_family"] = "powershell";
    else if (requested.find("TaskScheduler") != std::string::npos) data["semantic_family"] = "task_scheduler";
    else if (requested.find("WMI-Activity") != std::string::npos) data["semantic_family"] = "wmi_activity";
    else if (requested.find("Windows Defender") != std::string::npos) data["semantic_family"] = "defender";
    else if (requested.find("DNS-Client") != std::string::npos) data["semantic_family"] = "dns_client";
    else if (requested == "System") data["semantic_family"] = "system";
    // Source-native event classification only. These labels do not infer an
    // actor, authentication outcome beyond the provider event, or a detection.
    data["semantic_event"] = nullptr;
    if (!ambiguous && id && data["channel_matches_request"] == true) {
        if (data["semantic_family"] == "security_audit") {
            const char* label = nullptr;
            switch (*id) {
            case 1102: label = "security_log_cleared"; break;
            case 4616: label = "system_time_changed"; break;
            case 4624: label = "logon_success"; break;
            case 4625: label = "logon_failure"; break;
            case 4634: label = "logoff"; break;
            case 4647: label = "user_initiated_logoff"; break;
            case 4648: label = "explicit_credentials"; break;
            case 4672: label = "special_privileges_assigned"; break;
            case 4688: label = "audit_process_created"; break;
            case 4689: label = "audit_process_exited"; break;
            case 4697: label = "audit_service_installed"; break;
            case 4698: label = "audit_task_created"; break;
            case 4699: label = "audit_task_deleted"; break;
            case 4700: label = "audit_task_enabled"; break;
            case 4701: label = "audit_task_disabled"; break;
            case 4702: label = "audit_task_updated"; break;
            case 4719: label = "audit_policy_changed"; break;
            case 4720: label = "user_account_created"; break;
            case 4722: label = "user_account_enabled"; break;
            case 4723: label = "password_change_attempt"; break;
            case 4724: label = "password_reset_attempt"; break;
            case 4725: label = "user_account_disabled"; break;
            case 4726: label = "user_account_deleted"; break;
            case 4728: case 4732: case 4756: label = "security_group_member_added"; break;
            case 4729: case 4733: case 4757: label = "security_group_member_removed"; break;
            case 4740: label = "account_locked_out"; break;
            case 4768: label = "kerberos_tgt_requested"; break;
            case 4769: label = "kerberos_service_ticket_requested"; break;
            case 4771: label = "kerberos_preauthentication_failed"; break;
            case 4776: label = "credential_validation"; break;
            case 4778: label = "session_reconnected"; break;
            case 4779: label = "session_disconnected"; break;
            }
            if (label) data["semantic_event"] = label;
        } else if (requested == "Microsoft-Windows-PowerShell/Operational" && data["provider_name"] == "Microsoft-Windows-PowerShell") {
            if (*id == 4103) data["semantic_event"] = "powershell_module_logging";
            if (*id == 4104) { data["semantic_event"] = "powershell_script_block_fragment"; data["script_block_assembled"] = false; }
            if (*id == 4105) data["semantic_event"] = "powershell_script_block_invocation_started";
            if (*id == 4106) data["semantic_event"] = "powershell_script_block_invocation_finished";
        } else if (requested == "System" && data["provider_name"] == "Service Control Manager") {
            if (*id == 7045) data["semantic_event"] = "service_installed";
            if (*id == 7040) data["semantic_event"] = "service_start_type_changed";
            if (*id == 7036) data["semantic_event"] = "service_state_reported";
            if (*id == 7034) data["semantic_event"] = "service_terminated_unexpectedly";
        }
    }
    if (!ambiguous && system && provider && id && record && result.event_time && data["channel_matches_request"] == true && !data.contains("event_data_bound_exceeded")) data["decode_state"] = "healthy";
    return result;
}
}
