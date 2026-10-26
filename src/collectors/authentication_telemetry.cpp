#include "panopticon/officer/collectors/authentication_telemetry.hpp"
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
std::optional<std::uint64_t> integer(std::string_view text, int radix, std::uint64_t maximum) {
    if (radix == 16 && (text.starts_with("0x") || text.starts_with("0X"))) text.remove_prefix(2);
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, radix);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size() || value > maximum) return std::nullopt;
    return value;
}
}
std::optional<Json> decode_authentication(const Json& event) {
    if (!event.is_object()) return std::nullopt;
    if (event.value("requested_channel", Json(nullptr)) != "Security" || event.value("native_channel", Json(nullptr)) != "Security" ||
        event.value("provider_name", Json(nullptr)) != "Microsoft-Windows-Security-Auditing" ||
        event.value("validation_error", Json(nullptr)) == "ambiguous_system_fields" || !event.contains("system_fields")) return std::nullopt;
    const auto& system = event.at("system_fields");
    if (!system.is_object()) return std::nullopt;
    const auto raw_id = system.value("EventID", Json(nullptr)), raw_version = system.value("Version", Json(nullptr));
    if (!raw_id.is_string()) return std::nullopt;
    const auto id = integer(raw_id.get_ref<const std::string&>(), 10, 65535);
    if (!id || (*id != 4624 && *id != 4625 && *id != 4634 && *id != 4648 && *id != 4672 && *id != 4768 && *id != 4769 && *id != 4776)) return std::nullopt;
    Json out{{"format", "windows_authentication_v1"}, {"event_id", *id}, {"event_version", raw_version},
        {"state", "degraded"}, {"confidence", "reported"}, {"process_instance", nullptr}, {"logon_session_entity", nullptr},
        {"event_boot_id", nullptr}, {"raw_fields_retained", true}, {"unavailable", Json::array()}};
    const auto unavailable = [&](const std::string& field, const char* reason) { out["unavailable"].push_back({{"field", field}, {"reason", reason}}); };
    unavailable("process_instance", "source_does_not_supply_native_creation_token");
    unavailable("logon_session_entity", "native_event_boot_unverified");
    if (event.value("event_data_ambiguous", false)) { unavailable("typed_fields", "ambiguous_source_fields"); return out; }
    const auto version = raw_version.is_string() ? integer(raw_version.get_ref<const std::string&>(), 10, 65535) : std::nullopt;
    const bool known_version = version && (*id == 4624 ? *version <= 2 : (*id == 4768 || *id == 4769) ? (*version == 0 || *version == 2) : *version == 0);
    if (!known_version) {
        unavailable("typed_fields", "unsupported_or_missing_event_version"); return out;
    }
    const auto fields = event.value("event_data", Json::array());
    if (!fields.is_array() || fields.size() > 1024 || event.value("event_data_bound_exceeded", false)) {
        unavailable("typed_fields", "source_field_bound_exceeded"); return out;
    }
    std::map<std::string, Json> values; std::set<std::string> duplicate;
    std::size_t bytes = 0;
    for (const auto& field : fields) {
        if (!field.is_object() || field.value("element", Json(nullptr)) != "Data" || !field.value("name", Json(nullptr)).is_string()) continue;
        const auto name = field.at("name").get<std::string>(); const auto value = field.value("text", Json(nullptr));
        const auto size = value.is_string() ? value.get_ref<const std::string&>().size() : 0;
        if (name.size() > 128 || size > 65536 || name.size() + size > 196608 - bytes) {
            unavailable("typed_fields", "source_field_bound_exceeded"); return out;
        }
        bytes += name.size() + size;
        if (!values.emplace(name, value).second) duplicate.insert(name);
    }
    bool invalid_field = false;
    const auto text = [&](const char* name) -> Json {
        const auto found = values.find(name);
        if (duplicate.contains(name)) { invalid_field = true; unavailable(name, "ambiguous_source_field"); return nullptr; }
        if (found == values.end() || !found->second.is_string() || found->second == "" || found->second == "-") {
            unavailable(name, "source_not_reported"); return nullptr;
        }
        return found->second;
    };
    const auto number = [&](const char* name, int radix, std::uint64_t maximum) -> Json {
        const auto raw = text(name); if (!raw.is_string()) return nullptr;
        const auto parsed = integer(raw.get_ref<const std::string&>(), radix, maximum);
        if (!parsed) { invalid_field = true; unavailable(name, "invalid_source_number"); return nullptr; }
        return std::to_string(*parsed);
    };
    const auto account = [&](const char* sid, const char* name, const char* domain, const char* luid) -> Json {
        return {{"sid", text(sid)}, {"name", text(name)}, {"domain", text(domain)}, {"logon_id", number(luid, 16, UINT64_MAX)}};
    };
    out["subject"] = account("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId");
    out["target"] = account(*id == 4768 ? "TargetSid" : "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId");
    const auto type = number("LogonType", 10, UINT32_MAX);
    out["logon_type"] = type.is_string() ? Json(static_cast<std::uint32_t>(*integer(type.get_ref<const std::string&>(), 10, UINT32_MAX))) : Json(nullptr);
    out["source"] = {{"ip", text("IpAddress")}, {"port", number("IpPort", 10, 65535)},
        {"workstation", text(*id == 4776 ? "Workstation" : "WorkstationName")}};
    out["authentication_package"] = text(*id == 4776 ? "PackageName" : "AuthenticationPackageName");
    out["status"] = number("Status", 16, UINT32_MAX); out["substatus"] = number("SubStatus", 16, UINT32_MAX);
    out["process"] = {{"observed_pid", number("ProcessId", 16, UINT32_MAX)}, {"executable", text("ProcessName")}, {"instance", nullptr}};
    out["logon_guid"] = text("LogonGuid");
    const auto elevated = text("ElevatedToken");
    out["elevated_token"] = elevated == "%%1842" ? Json(true) : elevated == "%%1843" ? Json(false) : Json(nullptr);
    if (!elevated.is_null() && out["elevated_token"].is_null()) { invalid_field = true; unavailable("ElevatedToken", "unsupported_source_value"); }
    const auto* luid_field = (*id == 4624 || *id == 4634) ? "TargetLogonId" : (*id == 4625 || *id == 4648 || *id == 4672) ? "SubjectLogonId" : nullptr;
    out["session_id_field"] = luid_field ? Json(luid_field) : Json(nullptr);
    out["session_observed_logon_id"] = luid_field ? (std::string_view{luid_field} == "TargetLogonId" ? out["target"]["logon_id"] : out["subject"]["logon_id"]) : Json(nullptr);
    // A failed target account or ticket request is not a newly established local session.
    out["session_role"] = *id == 4624 ? "new_logon" : *id == 4634 ? "ended_logon" : luid_field ? "subject_logon" : "not_reported";
    out["operation"] = *id == 4624 ? "logon" : *id == 4625 ? "logon_failed" : *id == 4634 ? "logoff" : *id == 4648 ? "explicit_credentials" :
        *id == 4672 ? "privileges_assigned" : *id == 4768 ? "kerberos_tgt_request" : *id == 4769 ? "kerberos_service_ticket_request" : "credential_validation";
    out["outcome"] = *id == 4624 ? "success" : *id == 4625 ? "failure" : (*id == 4768 || *id == 4769 || *id == 4776) && !out["status"].is_null() ?
        (out["status"] == "0" ? "success" : "failure") : "not_reported";
    out["outcome_scope"] = "native_event_only_no_local_session_or_process_inference";
    out["state"] = invalid_field || !duplicate.empty() ? "partial" : "decoded";
    return out;
}
}
