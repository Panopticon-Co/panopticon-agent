#include "panopticon/officer/collectors/powershell_script_telemetry.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winevt.h>
#include <tinyxml2.h>

#include <string>
#include <vector>

namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;

std::wstring widen(std::string_view value) {
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!count) return {};
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count) != count) return {};
    return result;
}

struct EventHandle {
    EVT_HANDLE value{};
    ~EventHandle() { if (value) EvtClose(value); }
};

const tinyxml2::XMLElement* child(const tinyxml2::XMLElement* node, const char* name) {
    return node ? node->FirstChildElement(name) : nullptr;
}

Json node_text(const tinyxml2::XMLElement* node) {
    return node && node->GetText() ? Json(node->GetText()) : Json(nullptr);
}

Json attribute(const tinyxml2::XMLElement* node, const char* name) {
    return node && node->Attribute(name) ? Json(node->Attribute(name)) : Json(nullptr);
}

Json read_channel(std::string_view channel_name) {
    const auto channel = widen(channel_name);
    Json state{{"channel", std::string(channel_name)}, {"exists", false}, {"enabled", nullptr},
               {"read_query_opened", false}, {"inspection_error", nullptr}};
    if (channel.empty()) {
        state["inspection_error"] = "channel_name_invalid_utf8";
        return state;
    }
    EventHandle config{EvtOpenChannelConfig(nullptr, channel.c_str(), 0)};
    if (!config.value) {
        state["inspection_error"] = GetLastError();
        return state;
    }
    state["exists"] = true;
    EVT_VARIANT enabled{};
    DWORD used = 0;
    if (EvtGetChannelConfigProperty(config.value, EvtChannelConfigEnabled, 0, sizeof(enabled), &enabled, &used) && enabled.Type == EvtVarTypeBoolean)
        state["enabled"] = enabled.BooleanVal != FALSE;
    else
        state["enabled_query_error"] = GetLastError();
    EventHandle log{EvtOpenLog(nullptr, channel.c_str(), EvtOpenChannelPath)};
    state["read_query_opened"] = log.value != nullptr;
    if (!log.value) state["read_query_error"] = GetLastError();
    return state;
}

Json read_policy_dword(HKEY root, const wchar_t* path, const wchar_t* value_name) {
    HKEY key{};
    const auto opened = RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &key);
    if (opened != ERROR_SUCCESS) return {{"present", false}, {"registry_error", opened}};
    DWORD type = 0, value = 0, bytes = sizeof(value);
    const auto queried = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &bytes);
    RegCloseKey(key);
    if (queried == ERROR_FILE_NOT_FOUND) return {{"present", false}};
    if (queried != ERROR_SUCCESS) return {{"present", false}, {"registry_error", queried}};
    if (type != REG_DWORD || bytes != sizeof(value)) return {{"present", true}, {"value_type", type}, {"value", nullptr}};
    return {{"present", true}, {"value_type", "REG_DWORD"}, {"value", value}};
}

std::string narrow_ascii(const char* value) { return value ? std::string(value) : std::string{}; }

Json decode(std::string_view xml, std::string_view requested_channel) {
    Json out{{"format", "powershell_script_event_v1"}, {"requested_channel", std::string(requested_channel)},
             {"rendered_xml", std::string(xml)}, {"event_data", Json::array()}, {"system_fields", Json::object()},
             {"semantic_family", "powershell"}, {"semantic_event", nullptr},
             {"user_claims", Json::array()},
             {"process_attribution", {{"status", "uncertain"}, {"basis", "event System/Execution ProcessID is event-writer metadata and may not identify the script execution subject"}}},
             {"token_attribution", {{"status", "unverified"}, {"basis", "PowerShell EventData user fields are source claims; no token handle or logon-session join is verified here"}}},
             {"script_block_assembled", false}};
    if (xml.empty() || xml.size() > 196608 || xml.find('\0') != std::string_view::npos) {
        out["decode_state"] = "degraded"; out["validation_error"] = "xml_size_or_nul_bound"; return out;
    }
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS) {
        out["decode_state"] = "degraded"; out["validation_error"] = "xml_uninterpreted"; return out;
    }
    const auto* event = document.RootElement();
    if (!event || std::string_view(event->Name()) != "Event" || event->NextSiblingElement()) {
        out["decode_state"] = "degraded"; out["validation_error"] = "event_root_uninterpreted"; return out;
    }
    const auto* system = child(event, "System");
    bool system_ambiguous = !system || system->NextSiblingElement("System");
    for (const char* name : {"Provider", "EventID", "Version", "EventRecordID", "Channel", "Execution", "Security"}) {
        const auto* first = child(system, name);
        if (first && first->NextSiblingElement(name)) system_ambiguous = true;
    }
    out["system_fields_ambiguous"] = system_ambiguous;
    const auto* provider = child(system, "Provider");
    out["provider_name"] = attribute(provider, "Name");
    out["provider_guid"] = attribute(provider, "Guid");
    out["native_channel"] = node_text(child(system, "Channel"));
    out["channel_matches_request"] = out["native_channel"] == std::string(requested_channel);
    for (const char* name : {"EventID", "Version", "Level", "Task", "Opcode", "Keywords", "EventRecordID"})
        out["system_fields"][name] = node_text(child(system, name));
    out["event_writer"] = {{"pid", attribute(child(system, "Execution"), "ProcessID")},
                           {"tid", attribute(child(system, "Execution"), "ThreadID")},
                           {"user_sid", attribute(child(system, "Security"), "UserID")}};
    const auto* event_data = child(event, "EventData");
    std::string script_block_id;
    std::string message_number, message_total;
    std::string event_id_text;
    if (out["system_fields"]["EventID"].is_string()) event_id_text = out["system_fields"]["EventID"].get<std::string>();
    unsigned count = 0;
    for (auto* item = event_data ? event_data->FirstChildElement() : nullptr; item; item = item->NextSiblingElement()) {
        if (++count > 1024) { out["event_data_bound_exceeded"] = true; break; }
        const char* field_name = item->Attribute("Name");
        const std::string field = narrow_ascii(field_name);
        const std::string value = item->GetText() ? item->GetText() : "";
        tinyxml2::XMLPrinter printer(nullptr, true); item->Accept(&printer);
        out["event_data"].push_back({{"element", item->Name()}, {"name", attribute(item, "Name")},
                                     {"text", node_text(item)}, {"element_xml", printer.CStr()}});
        if (field == "ScriptBlockId") script_block_id = value;
        else if (field == "MessageNumber") message_number = value;
        else if (field == "MessageTotal") message_total = value;
        else if (field == "ScriptBlockText" || field == "Message") out["script_block_text_fragment"] = value;
        else if (field == "ContextInfo") out["module_context_info"] = value;
        else if (field == "Payload") out["module_payload"] = value;
        else if (field == "Path" || field == "ScriptName" || field == "CommandPath") out["script_path_claim"] = value;
        else if (field == "CommandName") out["command_name_claim"] = value;
        else if (field == "CommandType") out["command_type_claim"] = value;
        else if (field == "RunspaceId") out["runspace_id_claim"] = value;
        else if (field == "PipelineId") out["pipeline_id_claim"] = value;
        else if (field == "User" || field == "UserId" || field == "ConnectedUser") out["user_claims"].push_back({{"field", field}, {"value", value}});
    }
    const std::string provider_name = out["provider_name"].is_string() ? out["provider_name"].get<std::string>() : "";
    const bool trusted_source_shape = !system_ambiguous && provider_name == "Microsoft-Windows-PowerShell" && out["channel_matches_request"] == true &&
        (requested_channel == "Microsoft-Windows-PowerShell/Operational" || requested_channel == "Windows PowerShell");
    const bool operational_channel = requested_channel == "Microsoft-Windows-PowerShell/Operational";
    if (!trusted_source_shape) out["semantic_event"] = "powershell_event_unclassified_source_mismatch";
    else if (operational_channel && event_id_text == "4103") out["semantic_event"] = "powershell_module_logging";
    else if (operational_channel && event_id_text == "4104") out["semantic_event"] = "powershell_script_block_fragment";
    else if (operational_channel && event_id_text == "4105") out["semantic_event"] = "powershell_script_block_invocation_started";
    else if (operational_channel && event_id_text == "4106") out["semantic_event"] = "powershell_script_block_invocation_finished";
    else if (event_id_text == "400") out["semantic_event"] = "powershell_engine_started";
    else if (event_id_text == "403") out["semantic_event"] = "powershell_engine_stopped";
    else out["semantic_event"] = "powershell_event_unclassified";
    if (trusted_source_shape && operational_channel && event_id_text == "4104") {
        out["script_block_fragment"] = {{"script_block_id", script_block_id.empty() ? Json(nullptr) : Json(script_block_id)},
            {"message_number", message_number.empty() ? Json(nullptr) : Json(message_number)},
            {"message_total", message_total.empty() ? Json(nullptr) : Json(message_total)},
            {"assembled", false}, {"assembly_performed", false}, {"text_is_fragment_only", true}};
    }
    out["decode_state"] = out["channel_matches_request"] == true && !system_ambiguous &&
        !out.contains("event_data_bound_exceeded") ? "healthy" : "degraded";
    return out;
}
}  // namespace

nlohmann::json inspect_powershell_logging_coverage() {
    constexpr wchar_t policy[] = L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\";
    Json machine{{"script_block_logging", read_policy_dword(HKEY_LOCAL_MACHINE, (std::wstring(policy) + L"ScriptBlockLogging").c_str(), L"EnableScriptBlockLogging")},
                 {"script_block_invocation_logging", read_policy_dword(HKEY_LOCAL_MACHINE, (std::wstring(policy) + L"ScriptBlockLogging").c_str(), L"EnableScriptBlockInvocationLogging")},
                 {"module_logging", read_policy_dword(HKEY_LOCAL_MACHINE, (std::wstring(policy) + L"ModuleLogging").c_str(), L"EnableModuleLogging")},
                 {"transcription", read_policy_dword(HKEY_LOCAL_MACHINE, (std::wstring(policy) + L"Transcription").c_str(), L"EnableTranscripting")}};
    Json user{{"script_block_logging", read_policy_dword(HKEY_CURRENT_USER, (std::wstring(policy) + L"ScriptBlockLogging").c_str(), L"EnableScriptBlockLogging")},
              {"script_block_invocation_logging", read_policy_dword(HKEY_CURRENT_USER, (std::wstring(policy) + L"ScriptBlockLogging").c_str(), L"EnableScriptBlockInvocationLogging")},
              {"module_logging", read_policy_dword(HKEY_CURRENT_USER, (std::wstring(policy) + L"ModuleLogging").c_str(), L"EnableModuleLogging")},
              {"transcription", read_policy_dword(HKEY_CURRENT_USER, (std::wstring(policy) + L"Transcription").c_str(), L"EnableTranscripting")}};
    return {{"capability", "windows_powershell_script_telemetry"}, {"inspection_mode", "read_only"},
            {"channels", Json::array({read_channel("Microsoft-Windows-PowerShell/Operational"), read_channel("Windows PowerShell")})},
            {"group_policy_registry_observations", {{"HKLM", machine}, {"HKCU", user}}},
            {"coverage_state", "partial_configuration_observed_policy_effective_state_unverified"},
            {"coverage_limitations", Json::array({"channel_enabled does not prove audit policy or provider event generation", "policy registry values are local observations and do not prove resultant policy", "module names and transcript destination are not inspected", "classic channel EventID and fields vary by provider and Windows version", "writer PID and user fields do not prove script subject process or token", "4104 script-block records remain separate fragments and are never assembled"})}};
}

nlohmann::json decode_powershell_event_xml(std::string_view xml, std::string_view requested_channel) {
    return decode(xml, requested_channel);
}

}  // namespace panopticon::officer::collectors
