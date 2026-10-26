#include "panopticon/officer/collectors/security_audit_semantics.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ntsecapi.h>
#endif

namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
constexpr std::size_t kMaxFields = 1024;
constexpr std::size_t kMaxFieldNameBytes = 4096;
constexpr std::size_t kMaxFieldValueBytes = 65536;
constexpr std::size_t kMaxDerivedBytes = 196608;
constexpr ULONG kMaxAuditSubcategories = 256;

std::string lower_ascii(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char ch : value) result.push_back(static_cast<char>(std::tolower(ch)));
    return result;
}

std::optional<std::uint32_t> event_id(const Json& event) {
    if (!event.is_object() || !event.contains("system_fields") || !event["system_fields"].is_object()) return std::nullopt;
    const auto& value = event["system_fields"].value("EventID", Json(nullptr));
    if (!value.is_string()) return std::nullopt;
    const auto& raw = value.get_ref<const std::string&>();
    if (raw.empty()) return std::nullopt;
    std::uint32_t parsed = 0;
    for (const auto ch : raw) {
        if (ch < '0' || ch > '9' || parsed > (65535u - static_cast<unsigned>(ch - '0')) / 10u) return std::nullopt;
        parsed = parsed * 10u + static_cast<unsigned>(ch - '0');
    }
    return parsed;
}

const char* event_family(std::uint32_t id) {
    if ((id >= 4624 && id <= 4648) || id == 4672 || id == 4778 || id == 4779 || id == 4964) return "authentication_and_logon";
    if ((id >= 4720 && id <= 4740) || (id >= 4741 && id <= 4767) || (id >= 4781 && id <= 4782)) return "account_and_group_management";
    if (id == 4719 || (id >= 4902 && id <= 4907) || (id >= 4912 && id <= 4913)) return "audit_policy";
    if (id == 4688 || id == 4689) return "process_audit";
    if (id == 4697) return "service_audit";
    if (id >= 4698 && id <= 4702) return "scheduled_task_audit";
    if (id == 5152 || id == 5156 || id == 5157) return "wfp_connection_and_packet_audit";
    if ((id >= 4768 && id <= 4773) || (id >= 4771 && id <= 4776)) return "kerberos_and_credential_validation";
    return "security_audit_unclassified";
}

const char* semantic_event(std::uint32_t id) {
    switch (id) {
    case 4624: return "logon_succeeded_source_event";
    case 4625: return "logon_failed_source_event";
    case 4634: return "logon_session_ended_source_event";
    case 4647: return "user_initiated_logoff_source_event";
    case 4648: return "explicit_credentials_used_source_event";
    case 4672: return "special_privileges_assigned_source_event";
    case 4688: return "process_created_source_event";
    case 4689: return "process_exited_source_event";
    case 4697: return "service_installed_source_event";
    case 4698: return "scheduled_task_created_source_event";
    case 4699: return "scheduled_task_deleted_source_event";
    case 4700: return "scheduled_task_enabled_source_event";
    case 4701: return "scheduled_task_disabled_source_event";
    case 4702: return "scheduled_task_updated_source_event";
    case 4719: return "system_audit_policy_changed_source_event";
    case 4720: return "user_account_created_source_event";
    case 4722: return "user_account_enabled_source_event";
    case 4723: return "password_change_attempt_source_event";
    case 4724: return "password_reset_attempt_source_event";
    case 4725: return "user_account_disabled_source_event";
    case 4726: return "user_account_deleted_source_event";
    case 4727: return "security_group_created_source_event";
    case 4728: case 4732: case 4756: return "security_group_member_added_source_event";
    case 4729: case 4733: case 4757: return "security_group_member_removed_source_event";
    case 4731: case 4754: case 4759: return "security_group_created_source_event";
    case 4734: case 4758: case 4761: return "security_group_deleted_source_event";
    case 4735: case 4737: case 4755: case 4760: return "security_group_changed_source_event";
    case 4738: return "user_account_changed_source_event";
    case 4740: return "account_locked_source_event";
    case 4741: return "computer_account_created_source_event";
    case 4742: return "computer_account_changed_source_event";
    case 4743: return "computer_account_deleted_source_event";
    case 4762: return "security_group_member_removed_source_event";
    case 4768: return "kerberos_tgt_requested_source_event";
    case 4769: return "kerberos_service_ticket_requested_source_event";
    case 4770: return "kerberos_service_ticket_renewed_source_event";
    case 4771: return "kerberos_preauthentication_failed_source_event";
    case 4776: return "credential_validation_source_event";
    case 4781: return "account_name_changed_source_event";
    case 4782: return "password_hash_changed_source_event";
    case 4902: return "per_user_audit_policy_table_created_source_event";
    case 4904: return "security_audit_event_source_registered_source_event";
    case 4905: return "security_audit_event_source_unregistered_source_event";
    case 4906: return "crash_on_audit_fail_setting_changed_source_event";
    case 4907: return "auditable_object_sacl_changed_source_event";
    case 4912: return "per_user_audit_policy_changed_source_event";
    case 4778: return "session_reconnected_source_event";
    case 4779: return "session_disconnected_source_event";
    case 4964: return "special_groups_logon_source_event";
    case 5152: return "wfp_packet_blocked_source_event";
    case 5156: return "wfp_connection_permitted_source_event";
    case 5157: return "wfp_connection_blocked_source_event";
    default: return nullptr;
    }
}

const char* claim_role(std::string_view raw_name) {
    const auto name = lower_ascii(raw_name);
    if (name == "subjectusersid" || name == "subjectusername" || name == "subjectdomainname" || name == "subjectlogonid" ||
        name == "subjectaccountname" || name == "subjectaccountdomain" || name == "subjectsid") return "subject_claim";
    if (name == "targetusersid" || name == "targetusername" || name == "targetdomainname" || name == "targetlogonid" ||
        name == "targetaccountname" || name == "targetaccountdomain" || name == "targetsid" || name == "membername" ||
        name == "membersid" || name == "groupname" || name == "groupsid" || name == "servicename" || name == "taskname" ||
        name == "newaccountname" || name == "newaccountdomain" || name == "objectname" || name == "objecttype") return "target_claim";
    if (name == "ipaddress" || name == "ipport" || name == "sourceaddress" || name == "sourceport" || name == "clientaddress" ||
        name == "clientport" || name == "workstationname" || name == "workstation" || name == "networkaddress" ||
        name == "callercomputername") return "source_claim";
    if (name == "processid" || name == "newprocessid" || name == "processname" || name == "newprocessname" || name == "commandline" ||
        name == "parentprocessname" || name == "creatorprocessid" || name == "callerprocessid" || name == "logonprocessname" ||
        name == "authenticationpackagename" || name == "logontype" || name == "status" || name == "substatus" ||
        name == "failurecode" || name == "taskcontent" || name == "servicefilename" || name == "servicefilepath" ||
        name == "subjectusersid" || name == "targetusersid") return "contextual_claim";
    return "unknown_claim";
}

Json unavailable_policy(const char* reason, unsigned long error = 0) {
    Json result{{"format", "windows_system_audit_policy_v1"}, {"state", "unavailable"},
        {"query", "AuditEnumerateSubCategories+AuditQuerySystemPolicy"}, {"read_only", true},
        {"policy_scope", "system_policy_only"}, {"error", error}, {"reason", reason},
        {"subcategories", Json::array()}, {"per_user_or_effective_token_policy_queried", false},
        {"audit_policy_changed_by_collector", false}};
    return result;
}

#ifdef _WIN32
struct AuditBuffer {
    void* value{};
    ~AuditBuffer() { if (value) AuditFree(value); }
    AuditBuffer(const AuditBuffer&) = delete;
    AuditBuffer& operator=(const AuditBuffer&) = delete;
    AuditBuffer() = default;
};

std::string utf8_bounded(const wchar_t* value, std::size_t max_chars = 1024) {
    if (!value) return {};
    std::size_t length = 0;
    while (length < max_chars && value[length] != L'\0') ++length;
    if (length == max_chars && value[length] != L'\0') return {};
    if (!length) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0 || bytes > static_cast<int>(kMaxFieldValueBytes)) return {};
    std::string result(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length), result.data(), bytes, nullptr, nullptr) != bytes) return {};
    return result;
}

std::string guid_text(const GUID& guid) {
    char buffer[39]{};
    const int size = std::snprintf(buffer, sizeof(buffer), "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        static_cast<unsigned long>(guid.Data1), static_cast<unsigned>(guid.Data2), static_cast<unsigned>(guid.Data3),
        static_cast<unsigned>(guid.Data4[0]), static_cast<unsigned>(guid.Data4[1]),
        static_cast<unsigned>(guid.Data4[2]), static_cast<unsigned>(guid.Data4[3]), static_cast<unsigned>(guid.Data4[4]),
        static_cast<unsigned>(guid.Data4[5]), static_cast<unsigned>(guid.Data4[6]), static_cast<unsigned>(guid.Data4[7]));
    return size > 0 && static_cast<std::size_t>(size) < sizeof(buffer) ? std::string(buffer, static_cast<std::size_t>(size)) : std::string{};
}
#endif
}  // namespace

Json SecurityAuditSemantics::enrich(const Json& event) {
    Json result{{"format", "windows_security_audit_semantics_v1"}, {"state", "unavailable"},
        {"event_family", "unclassified"}, {"semantic_event", nullptr}, {"raw_event_id", nullptr},
        {"raw_event_version", nullptr}, {"raw_fields", Json::array()}, {"fields_truncated", false},
        {"actor_verification", "not_performed"}, {"process_attribution", "not_performed"},
        {"claims_are_source_reported_only", true}, {"source_identity_guard", false}};
    if (!event.is_object()) { result["reason"] = "decoded_event_not_object"; return result; }
    const auto requested = event.value("requested_channel", Json(nullptr));
    const auto channel = event.value("native_channel", Json(nullptr));
    const auto provider = event.value("provider_name", Json(nullptr));
    const bool ambiguous_system = event.value("validation_error", Json(nullptr)) == "ambiguous_system_fields";
    const bool guarded = requested == "Security" && channel == "Security" && provider == "Microsoft-Windows-Security-Auditing" && !ambiguous_system;
    result["source_identity_guard"] = guarded;
    result["raw_event_id"] = event.contains("system_fields") && event["system_fields"].is_object()
        ? event["system_fields"].value("EventID", Json(nullptr)) : Json(nullptr);
    result["raw_event_version"] = event.contains("system_fields") && event["system_fields"].is_object()
        ? event["system_fields"].value("Version", Json(nullptr)) : Json(nullptr);
    if (!guarded) {
        result["reason"] = ambiguous_system ? "ambiguous_system_metadata" : "requires_exact_security_channel_and_security_auditing_provider";
        return result;
    }

    const auto id = event_id(event);
    if (id) {
        result["event_family"] = event_family(*id);
        if (const auto* label = semantic_event(*id)) result["semantic_event"] = label;
        result["event_id_classification_basis"] = "provider_channel_and_event_id_only";
        if (*id == 5152 || *id == 5156 || *id == 5157) {
            result["wfp_event_semantics"] = {
                {"event_role", semantic_event(*id)}, {"raw_event_data_preserved", true},
                {"event_fields_interpreted", false},
                {"actor_process_endpoint_attribution", "not_performed"},
                {"reported_process_and_network_fields", "unverified_source_claims"},
                {"source_scope", "Security channel and Microsoft-Windows-Security-Auditing provider; event ID only"}
            };
        }
    } else {
        result["event_family"] = "security_audit_unclassified";
        result["reason"] = "event_id_missing_or_malformed";
    }
    result["version_interpreted"] = false;
    result["unknown_event_or_version_preserved"] = true;

    const auto fields = event.value("event_data", Json::array());
    if (!fields.is_array()) { result["state"] = "partial"; result["reason"] = "event_data_not_array"; return result; }
    std::size_t bytes = 0;
    const auto count = std::min(fields.size(), kMaxFields);
    for (std::size_t i = 0; i < count; ++i) {
        const auto& field = fields[i];
        Json name = field.is_object() ? field.value("name", Json(nullptr)) : Json(nullptr);
        Json text = field.is_object() ? field.value("text", Json(nullptr)) : Json(nullptr);
        Json element_name = field.is_object() ? field.value("element", Json(nullptr)) : Json(nullptr);
        const auto element_bytes = element_name.is_string() ? element_name.get_ref<const std::string&>().size() : 0;
        const auto name_bytes = name.is_string() ? name.get_ref<const std::string&>().size() : 0;
        const auto value_bytes = text.is_string() ? text.get_ref<const std::string&>().size() : 0;
        const bool bounded = element_bytes <= kMaxFieldNameBytes && name_bytes <= kMaxFieldNameBytes && value_bytes <= kMaxFieldValueBytes &&
            element_bytes <= kMaxDerivedBytes - bytes && name_bytes <= kMaxDerivedBytes - bytes - element_bytes &&
            value_bytes <= kMaxDerivedBytes - bytes - element_bytes - name_bytes;
        if (!bounded) {
            result["fields_truncated"] = true;
            result["truncation_reason"] = "derived_field_budget_exceeded_source_xml_remains_authoritative";
            break;
        }
        bytes += element_bytes + name_bytes + value_bytes;
        const std::string_view name_view = name.is_string() ? std::string_view{name.get_ref<const std::string&>()} : std::string_view{};
        result["raw_fields"].push_back({{"index", i}, {"raw_element_name", std::move(element_name)},
            {"raw_name", std::move(name)}, {"raw_value", std::move(text)}, {"claim_role", claim_role(name_view)},
            {"claim_verification", "unverified_source_claim"}});
    }
    if (fields.size() > count) { result["fields_truncated"] = true; result["truncation_reason"] = "field_count_limit_source_xml_remains_authoritative"; }
    if (result["fields_truncated"] == true) result["state"] = "partial";
    else result["state"] = "healthy";
    if (event.value("event_data_bound_exceeded", false)) {
        result["state"] = "partial";
        result["fields_truncated"] = true;
        result["truncation_reason"] = "source_event_data_bound_exceeded_source_xml_remains_authoritative";
    }
    return result;
}

Json SecurityAuditSemantics::query_system_policy() {
#ifdef _WIN32
    GUID* subcategories = nullptr;
    ULONG count = 0;
    if (!AuditEnumerateSubCategories(nullptr, TRUE, &subcategories, &count))
        return unavailable_policy("AuditEnumerateSubCategories_failed", GetLastError());
    AuditBuffer subcategory_buffer; subcategory_buffer.value = subcategories;
    if (!subcategories || count == 0) return unavailable_policy("no_system_audit_subcategories_returned");
    if (count > kMaxAuditSubcategories) return unavailable_policy("system_audit_subcategory_count_exceeds_bound");

    PAUDIT_POLICY_INFORMATION policy = nullptr;
    if (!AuditQuerySystemPolicy(subcategories, count, &policy))
        return unavailable_policy("AuditQuerySystemPolicy_failed", GetLastError());
    AuditBuffer policy_buffer; policy_buffer.value = policy;
    if (!policy) return unavailable_policy("AuditQuerySystemPolicy_returned_no_buffer");

    Json records = Json::array();
    bool partial = false;
    for (ULONG i = 0; i < count; ++i) {
        const auto* item = &policy[i];
        PWSTR display_name = nullptr;
        const bool has_name = AuditLookupSubCategoryNameW(&item->AuditSubCategoryGuid, &display_name) != FALSE;
        AuditBuffer name_buffer; name_buffer.value = display_name;
        const auto mask = static_cast<std::uint32_t>(item->AuditingInformation);
        const auto display = has_name ? utf8_bounded(display_name) : std::string{};
        if (display.empty()) partial = true;
        records.push_back({{"subcategory_guid", guid_text(item->AuditSubCategoryGuid)},
            {"display_name", display.empty() ? Json(nullptr) : Json(display)},
            {"display_name_localized", true}, {"auditing_information_raw", mask},
            {"success_audit_enabled", (mask & POLICY_AUDIT_EVENT_SUCCESS) != 0},
            {"failure_audit_enabled", (mask & POLICY_AUDIT_EVENT_FAILURE) != 0},
            {"unknown_auditing_information_bits", mask & ~(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE)},
            {"policy_scope", "system"}});
    }
    return {{"format", "windows_system_audit_policy_v1"}, {"state", partial ? "partial" : "healthy"},
        {"query", "AuditEnumerateSubCategories+AuditQuerySystemPolicy"}, {"read_only", true},
        {"policy_scope", "system_policy_only"}, {"subcategory_count", records.size()},
        {"enumeration_bound", kMaxAuditSubcategories}, {"subcategories", std::move(records)},
        {"coverage", "enumerated_system_subcategory_inventory_including_authentication_account_group_policy_process_service_and_task_related_categories"},
        {"per_user_or_effective_token_policy_queried", false}, {"effective_policy_computed", false},
        {"policy_event_generation_or_delivery_verified", false}, {"audit_policy_changed_by_collector", false}};
#else
    return unavailable_policy("windows_native_audit_policy_api_unavailable_on_this_platform");
#endif
}

}  // namespace panopticon::officer::collectors
