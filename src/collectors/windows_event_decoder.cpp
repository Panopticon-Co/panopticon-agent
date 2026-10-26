#include "panopticon/officer/collectors/windows_event_log.hpp"
#include "panopticon/officer/collectors/powershell_script_telemetry.hpp"
#include "panopticon/officer/collectors/security_audit_semantics.hpp"
#include "panopticon/officer/collectors/authentication_telemetry.hpp"
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
    const auto attach_security_semantics = [&]() {
        if (requested == "Security") {
            data["security_audit_semantics"] = SecurityAuditSemantics::enrich(data);
            if (const auto auth = decode_authentication(data)) data["authentication"] = *auth;
        }
    };
    tinyxml2::XMLDocument document;
    if (xml.size() > 196608 || xml.find('\0') != std::string::npos || document.Parse(xml.data(),xml.size()) != tinyxml2::XML_SUCCESS) {
        data["validation_error"] = "xml_uninterpreted"; attach_security_semantics(); return result;
    }
    const auto* root = document.RootElement();
    if (!root || std::string_view{root->Name()} != "Event" || root->NextSiblingElement()) {
        data["validation_error"] = "event_root_uninterpreted"; attach_security_semantics(); return result;
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
        if (values->NextSiblingElement("EventData")) data["event_data_ambiguous"] = true;
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
    else if (requested == "Microsoft-Windows-TaskScheduler/Operational" &&
        data["provider_name"] == "Microsoft-Windows-TaskScheduler") data["semantic_family"] = "task_scheduler";
    else if (requested == "Microsoft-Windows-WMI-Activity/Operational" &&
        data["provider_name"] == "Microsoft-Windows-WMI-Activity") data["semantic_family"] = "wmi_activity";
    else if (requested.find("Windows Defender") != std::string::npos) data["semantic_family"] = "defender";
    else if (requested == "Microsoft-Windows-DNS-Client/Operational" &&
        data["provider_name"] == "Microsoft-Windows-DNS-Client") data["semantic_family"] = "dns_client";
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
        } else if (requested == "Microsoft-Windows-TaskScheduler/Operational" &&
            data["provider_name"] == "Microsoft-Windows-TaskScheduler") {
            // Microsoft WEF identifies these exact Task Scheduler Operational
            // event IDs and labels. Its guidance does not define EventData
            // templates, so fields remain uninterpreted below.
            if (*id == 106) data["semantic_event"] = "task_registered";
            if (*id == 141) data["semantic_event"] = "task_registration_deleted";
            if (*id == 142) data["semantic_event"] = "task_deleted";
        } else if (data["semantic_family"] == "wmi_activity") {
            // Microsoft documents these Operational event examples: 5857 is
            // provider-start information; 5858 reports a WMI client operation.
            // Keep event fields raw because templates vary and are not decoded.
            if (*id == 5857) data["semantic_event"] = "wmi_provider_started";
            if (*id == 5858) data["semantic_event"] = "wmi_client_operation_reported";
        } else if (requested == "Microsoft-Windows-Windows Defender/Operational" &&
            data["provider_name"] == "Microsoft-Windows-Windows Defender") {
            // Microsoft documents these Defender Operational IDs. Only the
            // source event role is labeled; raw fields remain uninterpreted.
            switch (*id) {
            case 1116: data["semantic_event"] = "defender_threat_detected"; break;
            case 1117: data["semantic_event"] = "defender_remediation_action_reported"; break;
            case 1121: data["semantic_event"] = "defender_asr_block_reported"; break;
            case 1122: data["semantic_event"] = "defender_asr_audit_reported"; break;
            case 1129: data["semantic_event"] = "defender_asr_user_override_reported"; break;
            case 3002: data["semantic_event"] = "defender_realtime_protection_failure"; break;
            case 3007: data["semantic_event"] = "defender_realtime_protection_recovered"; break;
            case 5000: data["semantic_event"] = "defender_realtime_protection_enabled"; break;
            case 5001: data["semantic_event"] = "defender_realtime_protection_disabled"; break;
            case 5007: data["semantic_event"] = "defender_configuration_changed"; break;
            case 5008: data["semantic_event"] = "defender_engine_failure"; break;
            case 5013: data["semantic_event"] = "defender_tamper_protection_blocked_change"; break;
            }
        } else if (data["semantic_family"] == "dns_client" && *id == 3008) {
            // Microsoft WEF's sample query identifies Operational event 3008
            // as "Query Completed". Keep all EventData uninterpreted here.
            data["semantic_event"] = "dns_query_completed";
        }
    }
    if (requested == "Microsoft-Windows-WMI-Activity/Operational" &&
        data["provider_name"] == "Microsoft-Windows-WMI-Activity" && data["channel_matches_request"] == true) {
        data["wmi_activity_semantics"] = {
            {"event_role", data["semantic_family"] == "wmi_activity" ? data["semantic_event"] : Json(nullptr)},
            {"source_label_basis", "Microsoft Learn WMI troubleshooting guidance documents Operational events 5857 and 5858"},
            {"raw_event_data_preserved", true}, {"event_data_fields_interpreted", false},
            {"attribution", {{"state", "unverified"}, {"subject_process_id", nullptr},
                {"reported_security_user_id", data["security_user_id"]},
                {"reason", "WMI event User and ClientProcessId fields, when present, remain source-reported and are not independently verified or correlated to a process instance"}}}
        };
    }
    if (requested == "Microsoft-Windows-Windows Defender/Operational" &&
        data["provider_name"] == "Microsoft-Windows-Windows Defender" && data["channel_matches_request"] == true) {
        data["defender_operational_semantics"] = {
            {"event_role", data["semantic_family"] == "defender" ? data["semantic_event"] : Json(nullptr)},
            {"source_label_basis", "Microsoft Defender Antivirus event documentation and ASR event guidance"},
            {"raw_event_data_preserved", true}, {"event_data_fields_interpreted", false},
            {"process_and_action_attribution", {{"state", "unverified"}, {"subject_process_id", nullptr},
                {"reason", "raw event fields and reported writer metadata are not independently verified or correlated to a process instance"}}},
            {"privacy_scope", "retained raw XML/EventData may include threat names, file paths, usernames, and security configuration values"}
        };
    }
    if (requested == "Microsoft-Windows-TaskScheduler/Operational" &&
        data["provider_name"] == "Microsoft-Windows-TaskScheduler" && data["channel_matches_request"] == true) {
        data["task_scheduler_semantics"] = {
            {"event_role", data["semantic_family"] == "task_scheduler" ? data["semantic_event"] : Json(nullptr)},
            {"source_label_basis", "Microsoft Windows Event Forwarding intrusion detection guidance: Task Scheduler Operational events 106, 141, and 142"},
            {"raw_event_data_preserved", true}, {"event_data_fields_interpreted", false},
            {"actor_attribution", {{"state", "unverified"}, {"subject_process_id", nullptr},
                {"reported_event_writer_pid", data["execution"]["reported_writer_pid"]},
                {"reported_security_user_id", data["security_user_id"]},
                {"reason", "the cited source does not define EventData field templates; event writer metadata is not verified as the initiating actor or process"}}}
        };
    }
    if (requested == "Microsoft-Windows-DNS-Client/Operational" &&
        data["provider_name"] == "Microsoft-Windows-DNS-Client" && data["channel_matches_request"] == true) {
        data["dns_client_semantics"] = {
            {"event_role", data["semantic_event"] == "dns_query_completed" ? Json("dns_query_completed") : Json(nullptr)},
            {"source_label_basis", "Microsoft-Windows-DNS-Client Operational event 3008; query completion label only"},
            {"raw_event_data_preserved", true}, {"event_data_fields_interpreted", false},
            {"process_attribution", {{"state", "unverified"}, {"subject_process_id", nullptr},
                {"reported_event_writer_pid", data["execution"]["reported_writer_pid"]},
                {"reason", "event writer PID/TID are not verified as the DNS requester; no process instance or caller attribution is established"}}}
        };
    }
    if (requested == "Microsoft-Windows-PowerShell/Operational" || requested == "Windows PowerShell") {
        const auto source = decode_powershell_event_xml(xml, requested);
        data["powershell_source_semantics"] = {
            {"semantic_event", source.value("semantic_event", nlohmann::json(nullptr))},
            {"decode_state", source.value("decode_state", std::string("degraded"))},
            {"channel_matches_request", source.value("channel_matches_request", false)},
            {"process_attribution", source.value("process_attribution", nlohmann::json::object())},
            {"token_attribution", source.value("token_attribution", nlohmann::json::object())},
            {"script_block_assembled", false},
            {"script_block_fragment", source.value("script_block_fragment", nlohmann::json(nullptr))}
        };
    }
    if (!ambiguous && system && provider && id && record && result.event_time && data["channel_matches_request"] == true && !data.contains("event_data_bound_exceeded") && !data.contains("event_data_ambiguous")) data["decode_state"] = "healthy";
    attach_security_semantics();
    return result;
}
}
