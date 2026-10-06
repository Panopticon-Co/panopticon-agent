#include "panopticon/officer/state/service_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>
#include <optional>
#include <algorithm>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
struct ScCloser { void operator()(void* value) const noexcept { if (value) CloseServiceHandle(static_cast<SC_HANDLE>(value)); } };
using ScHandle = std::unique_ptr<void, ScCloser>;
Json failed(const char* source, DWORD code) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "Win32"}, {"error_code", std::to_string(code)}};
}
Json invalid(const char* source, const char* code) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "validation"}, {"error_code", code}};
}
Json observed(Json value, const char* source) {
    return {{"state", "healthy"}, {"value", std::move(value)}, {"source", source}, {"error_code", nullptr}};
}
std::optional<std::size_t> offset(std::span<const std::byte> buffer, const void* pointer) {
    const auto base = reinterpret_cast<std::uintptr_t>(buffer.data()), address = reinterpret_cast<std::uintptr_t>(pointer);
    if (!pointer || address < base || address - base >= buffer.size() || address % alignof(wchar_t)
        || buffer.size() - (address - base) < sizeof(wchar_t)) return std::nullopt;
    return static_cast<std::size_t>(address - base);
}
wchar_t character(std::span<const std::byte> buffer, std::size_t position) {
    wchar_t value = 0; std::memcpy(&value, buffer.data() + position, sizeof(value)); return value;
}
Json utf16(const std::wstring& value) {
    if (value.empty()) return "";
    const auto needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed > 0) {
        std::string encoded(static_cast<std::size_t>(needed), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), encoded.data(), needed, nullptr, nullptr)) return encoded;
    }
    constexpr char digits[] = "0123456789abcdef"; std::string hex;
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    for (std::size_t index = 0; index < value.size() * sizeof(wchar_t); ++index) { hex += digits[bytes[index] >> 4]; hex += digits[bytes[index] & 15]; }
    return {{"encoding", "utf16le_hex"}, {"bytes", std::move(hex)}, {"byte_length", std::to_string(value.size() * sizeof(wchar_t))}};
}
Json basic_configuration(SC_HANDLE service, std::uint64_t& failures) {
    std::vector<std::byte> bytes(8192); DWORD needed = 0;
    if (!QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data()),
        static_cast<DWORD>(bytes.size()), &needed)) {
        const auto code = GetLastError(); ++failures;
        auto fact = failed("QueryServiceConfigW/held service handle", code);
        fact["required_bytes"] = std::to_string(needed); fact["byte_limit"] = bytes.size(); fact["bound_exceeded"] = needed > bytes.size();
        return fact;
    }
    QUERY_SERVICE_CONFIGW value{}; std::memcpy(&value, bytes.data(), sizeof(value));
    Json fields = Json::object();
    const auto retain = [&](const char* key, Json fact) {
        if (fact["state"] == "unavailable") ++failures;
        fields[key] = std::move(fact);
    };
    retain("binary_path_and_arguments", detail::service_text(bytes, value.lpBinaryPathName));
    retain("load_order_group", value.lpLoadOrderGroup ? detail::service_text(bytes, value.lpLoadOrderGroup) : observed(nullptr, "QueryServiceConfigW/null load-order group"));
    retain("configured_account_or_driver_object", value.lpServiceStartName ? detail::service_text(bytes, value.lpServiceStartName) : observed(nullptr, "QueryServiceConfigW/null service start name"));
    retain("display_name", detail::service_text(bytes, value.lpDisplayName, 256));
    retain("dependencies", detail::service_dependencies(bytes, value.lpDependencies));
    return {{"state", "degraded"}, {"source", "QueryServiceConfigW/one held service handle"},
        {"reported_service_type", std::to_string(value.dwServiceType)}, {"reported_start_type", std::to_string(value.dwStartType)},
        {"reported_error_control", std::to_string(value.dwErrorControl)}, {"reported_tag_id", std::to_string(value.dwTagId)},
        {"fields", std::move(fields)}, {"consistency", "same_service_object_configuration; relation to earlier descriptor unverified"},
        {"scope", "registry configuration for next start can differ from currently executing service; image identity/account/dependency instances unresolved"}};
}
struct OptionalLevel { const char* name; DWORD level; };
constexpr OptionalLevel optional_levels[]{
    {"description", SERVICE_CONFIG_DESCRIPTION}, {"failure_actions", SERVICE_CONFIG_FAILURE_ACTIONS},
    {"delayed_auto_start", SERVICE_CONFIG_DELAYED_AUTO_START_INFO},
    {"failure_actions_on_non_crash", SERVICE_CONFIG_FAILURE_ACTIONS_FLAG},
    {"service_sid_type", SERVICE_CONFIG_SERVICE_SID_INFO},
    {"required_privileges", SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO},
    {"preshutdown_timeout", SERVICE_CONFIG_PRESHUTDOWN_INFO},
    {"launch_protection", SERVICE_CONFIG_LAUNCH_PROTECTED}, {"triggers", SERVICE_CONFIG_TRIGGER_INFO}};
Json configuration(SC_HANDLE manager, const wchar_t* name, std::uint64_t& failures, std::uint64_t& not_attempted, Json& summary) {
    ScHandle service{OpenServiceW(manager, name, SERVICE_QUERY_CONFIG)};
    if (!service) { const auto code = GetLastError(); ++failures; ++not_attempted; return failed("OpenServiceW/SERVICE_QUERY_CONFIG", code); }
    const auto handle = static_cast<SC_HANDLE>(service.get());
    auto result = basic_configuration(handle, failures); Json optional = Json::object();
    for (const auto& info : optional_levels) {
        std::vector<std::byte> bytes(8192); DWORD needed = 0; Json fact;
        const auto started = GetTickCount64();
        if (!QueryServiceConfig2W(handle, info.level, reinterpret_cast<BYTE*>(bytes.data()),
            static_cast<DWORD>(bytes.size()), &needed)) {
            const auto code = GetLastError();
            fact = failed("QueryServiceConfig2W/held service handle", code);
            fact["native_query_succeeded"] = false;
            if (code == ERROR_INSUFFICIENT_BUFFER) {
                fact["required_bytes"] = std::to_string(needed); fact["bound_exceeded"] = needed > bytes.size();
            }
            ++failures;
            auto count = std::stoull(summary[info.name]["failed_native_queries"].get<std::string>());
            summary[info.name]["failed_native_queries"] = std::to_string(count + 1);
        } else {
            fact = detail::service_optional_configuration(bytes, info.level);
            fact["native_query_succeeded"] = true;
            auto count = std::stoull(summary[info.name]["successful_native_queries"].get<std::string>());
            summary[info.name]["successful_native_queries"] = std::to_string(count + 1);
            if (fact["state"] != "healthy") {
                count = std::stoull(summary[info.name]["uninterpreted_or_invalid_results"].get<std::string>());
                summary[info.name]["uninterpreted_or_invalid_results"] = std::to_string(count + 1);
            }
            if (fact["state"] == "unavailable") ++failures;
            if (fact.contains("validation_failure_count")) failures += std::stoull(fact["validation_failure_count"].get<std::string>());
        }
        fact["information_level"] = std::to_string(info.level); fact["buffer_byte_limit"] = "8192";
        fact["query_started_uptime_ms"] = std::to_string(started);
        fact["query_completed_uptime_ms"] = std::to_string(GetTickCount64());
        optional[info.name] = std::move(fact);
    }
    result["optional_configuration_queries"] = std::move(optional);
    result["optional_configuration_consistency"] = "same opened service object; separate queries are non-atomic and not proof of running instance configuration";
    return result;
}
}
Json detail::service_text(std::span<const std::byte> buffer, const void* pointer, std::size_t limit) {
    const auto start = offset(buffer, pointer);
    if (!start) return invalid("SCM returned string/bounds", "pointer_outside_buffer_or_unaligned");
    std::wstring text;
    for (std::size_t index = 0, position = *start; position + sizeof(wchar_t) <= buffer.size(); ++index, position += sizeof(wchar_t)) {
        const auto value = character(buffer, position);
        if (!value) return observed(utf16(text), "SCM returned UTF-16 string");
        if (index >= limit) return invalid("SCM returned string/bounds", "character_limit_exceeded");
        text += value;
    }
    return invalid("SCM returned string/bounds", "missing_terminator");
}
Json detail::service_dependencies(std::span<const std::byte> buffer, const void* pointer) {
    if (!pointer) return observed(Json::array(), "QueryServiceConfigW/null dependencies");
    const auto start = offset(buffer, pointer);
    if (!start) return invalid("SCM dependencies/bounds", "pointer_outside_buffer_or_unaligned");
    Json entries = Json::array(); std::wstring text;
    for (std::size_t position = *start; position + sizeof(wchar_t) <= buffer.size(); position += sizeof(wchar_t)) {
        const auto value = character(buffer, position);
        if (value) { text += value; continue; }
        if (text.empty()) return observed(std::move(entries), "QueryServiceConfigW/MULTISZ unresolved service/group names");
        entries.push_back(utf16(text)); text.clear();
    }
    return invalid("SCM dependencies/bounds", "missing_final_terminator");
}
Json detail::service_optional_configuration(std::span<const std::byte> buffer, std::uint32_t level) {
    constexpr const char* source = "QueryServiceConfig2W/bounded native buffer";
    if (buffer.size() > 8192) return invalid(source, "buffer_limit_exceeded");
    if (level == SERVICE_CONFIG_TRIGGER_INFO) return detail::service_triggers(buffer);
    const auto scalar = [&](const char* raw_key, const char* bool_key) {
        if (buffer.size() < sizeof(DWORD)) return invalid(source, "truncated_fixed_structure");
        DWORD raw = 0; std::memcpy(&raw, buffer.data(), sizeof(raw));
        Json value{{raw_key, std::to_string(raw)}};
        if (bool_key) value[bool_key] = raw != 0;
        return observed(std::move(value), source);
    };
    if (level == SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
        return scalar("reported_delayed_auto_start", "delayed_auto_start");
    if (level == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
        return scalar("reported_failure_actions_on_non_crash", "failure_actions_on_non_crash");
    if (level == SERVICE_CONFIG_PRESHUTDOWN_INFO)
        return scalar("reported_preshutdown_timeout_ms", nullptr);
    if (level == SERVICE_CONFIG_SERVICE_SID_INFO || level == SERVICE_CONFIG_LAUNCH_PROTECTED) {
        auto result = scalar(level == SERVICE_CONFIG_SERVICE_SID_INFO ? "reported_service_sid_type" : "reported_launch_protection", nullptr);
        if (result["state"] == "unavailable") return result;
        DWORD raw = 0; std::memcpy(&raw, buffer.data(), sizeof(raw)); const char* symbol = nullptr;
        if (level == SERVICE_CONFIG_SERVICE_SID_INFO) {
            if (raw == SERVICE_SID_TYPE_NONE) symbol = "SERVICE_SID_TYPE_NONE";
            else if (raw == SERVICE_SID_TYPE_UNRESTRICTED) symbol = "SERVICE_SID_TYPE_UNRESTRICTED";
            else if (raw == SERVICE_SID_TYPE_RESTRICTED) symbol = "SERVICE_SID_TYPE_RESTRICTED";
        } else {
            if (raw == SERVICE_LAUNCH_PROTECTED_NONE) symbol = "SERVICE_LAUNCH_PROTECTED_NONE";
            else if (raw == SERVICE_LAUNCH_PROTECTED_WINDOWS) symbol = "SERVICE_LAUNCH_PROTECTED_WINDOWS";
            else if (raw == SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT) symbol = "SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT";
            else if (raw == SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT) symbol = "SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT";
        }
        result["value"]["sdk_symbol"] = symbol ? Json(symbol) : Json(nullptr);
        if (!symbol) result["state"] = "degraded";
        result["scope"] = "configured service setting; running token/protection and agent PPL/ELAM readiness are not established";
        return result;
    }
    if (level == SERVICE_CONFIG_DESCRIPTION || level == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO) {
        if (buffer.size() < sizeof(void*)) return invalid(source, "truncated_fixed_structure");
        void* pointer = nullptr; std::memcpy(&pointer, buffer.data(), sizeof(pointer));
        Json result;
        if (!pointer) result = observed(nullptr, source);
        else if (level == SERVICE_CONFIG_DESCRIPTION) result = detail::service_text(buffer, pointer);
        else result = detail::service_dependencies(buffer, pointer);
        result["source"] = source;
        result["scope"] = level == SERVICE_CONFIG_DESCRIPTION
            ? "raw configured description; indirect resource text not loaded or expanded"
            : "configured privilege names; not effective token privileges; next-start and shared-process union semantics apply";
        return result;
    }
    if (level == SERVICE_CONFIG_FAILURE_ACTIONS) {
        if (buffer.size() < sizeof(SERVICE_FAILURE_ACTIONSW)) return invalid(source, "truncated_fixed_structure");
        SERVICE_FAILURE_ACTIONSW config{}; std::memcpy(&config, buffer.data(), sizeof(config));
        Json value{{"reported_reset_period_seconds", std::to_string(config.dwResetPeriod)},
            {"reported_action_count", std::to_string(config.cActions)}};
        std::uint64_t validation_failures = 0; bool unknown = false;
        for (const auto& field : {std::pair{"reboot_message", config.lpRebootMsg}, std::pair{"command", config.lpCommand}}) {
            auto fact = field.second ? detail::service_text(buffer, field.second) : observed(nullptr, source);
            if (fact["state"] == "unavailable") ++validation_failures;
            value[field.first] = std::move(fact);
        }
        Json actions;
        if (!config.lpsaActions) {
            actions = observed(nullptr, source);
            actions["scope"] = "native null actions pointer; count/reset members are not interpreted as an active action array";
        } else {
            const auto base = reinterpret_cast<std::uintptr_t>(buffer.data());
            const auto address = reinterpret_cast<std::uintptr_t>(config.lpsaActions);
            if (address < base || address - base >= buffer.size() || address % alignof(SC_ACTION)
                || config.cActions > (buffer.size() - (address - base)) / sizeof(SC_ACTION)) {
                actions = invalid(source, "action_array_outside_buffer_or_unaligned"); ++validation_failures;
            } else {
                Json list = Json::array();
                for (DWORD index = 0; index < config.cActions; ++index) {
                    const auto position = address - base + index * sizeof(SC_ACTION);
                    DWORD type = 0, delay = 0;
                    static_assert(sizeof(SC_ACTION_TYPE) == sizeof(DWORD));
                    std::memcpy(&type, buffer.data() + position + offsetof(SC_ACTION, Type), sizeof(type));
                    std::memcpy(&delay, buffer.data() + position + offsetof(SC_ACTION, Delay), sizeof(delay));
                    const char* symbol = nullptr;
                    if (type == SC_ACTION_NONE) symbol = "SC_ACTION_NONE";
                    else if (type == SC_ACTION_RESTART) symbol = "SC_ACTION_RESTART";
                    else if (type == SC_ACTION_REBOOT) symbol = "SC_ACTION_REBOOT";
                    else if (type == SC_ACTION_RUN_COMMAND) symbol = "SC_ACTION_RUN_COMMAND";
                    else unknown = true;
                    list.push_back({{"reported_type", std::to_string(type)}, {"reported_delay_ms", std::to_string(delay)},
                        {"sdk_symbol", symbol ? Json(symbol) : Json(nullptr)}});
                }
                actions = observed(std::move(list), source);
                if (unknown) actions["state"] = "degraded";
            }
        }
        value["actions"] = std::move(actions); auto result = observed(std::move(value), source);
        result["validation_failure_count"] = std::to_string(validation_failures);
        if (validation_failures || unknown) result["state"] = "degraded";
        result["scope"] = "configured failure policy; raw commands/resources are never executed or loaded; no observed failure/action history";
        return result;
    }
    return invalid(source, "information_level_not_implemented");
}
Json collect_service_inventory_pages(const std::function<bool(Json)>& consumer, ServiceInventoryLimits limits) {
    if (!consumer || !limits.page_entries || limits.page_entries > 4096 || limits.encoded_bytes < 2 || limits.encoded_bytes > 512 * 1024
        || !limits.total_entries || limits.total_entries > 65536 || !limits.pages || limits.pages > 4096
        || limits.enumeration_bytes < 4096 || limits.enumeration_bytes > 256 * 1024) throw std::invalid_argument("invalid service inventory limits");
    const auto started = GetTickCount64();
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)};
    if (!manager) return failed("OpenSCManagerW/local/CONNECT|ENUMERATE_SERVICE", GetLastError());
    constexpr DWORD types = SERVICE_WIN32 | SERVICE_DRIVER;
    std::vector<std::byte> native(limits.enumeration_bytes); DWORD resume = 0;
    Json rows = Json::array(), enumeration_failure = nullptr, optional_summary = Json::object();
    for (const auto& info : optional_levels) optional_summary[info.name] = {
        {"successful_native_queries", "0"}, {"failed_native_queries", "0"}, {"uninterpreted_or_invalid_results", "0"}};
    std::size_t encoded = 2, pages = 0, delivered = 0;
    std::uint64_t failures = 0, native_calls = 0, optional_not_attempted = 0;
    std::uint64_t security_success = 0, security_failed = 0, security_opens_failed = 0, security_not_attempted = 0, security_invalid = 0;
    std::uint64_t security_bounded = 0;
    bool complete = false, bounded = false, refused = false, stopped = false;
    const auto flush = [&]() {
        if (pages >= limits.pages) { bounded = true; stopped = true; return false; }
        const auto count = rows.size();
        Json page{{"state", "degraded"}, {"service_state_version", "1.3"}, {"page_index", std::to_string(pages)},
            {"entries", std::move(rows)}, {"inventory_complete", false}, {"consistency", "non_atomic"},
            {"collection_started_uptime_ms", std::to_string(started)}};
        ++pages;
        if (!consumer(std::move(page))) { refused = true; stopped = true; return false; }
        delivered += count; rows = Json::array(); encoded = 2; return true;
    };
    while (!stopped) {
        DWORD needed = 0, returned = 0; const auto previous_resume = resume;
        std::fill(native.begin(), native.end(), std::byte{0});
        const BOOL result = EnumServicesStatusExW(static_cast<SC_HANDLE>(manager.get()), SC_ENUM_PROCESS_INFO, types, SERVICE_STATE_ALL,
            reinterpret_cast<BYTE*>(native.data()), static_cast<DWORD>(native.size()), &needed, &returned, &resume, nullptr);
        const DWORD code = result ? ERROR_SUCCESS : GetLastError(); ++native_calls;
        if (!result && code != ERROR_MORE_DATA) { enumeration_failure = failed("EnumServicesStatusExW", code); break; }
        if (returned > native.size() / sizeof(ENUM_SERVICE_STATUS_PROCESSW)) {
            enumeration_failure = invalid("EnumServicesStatusExW/array", "returned_count_outside_buffer"); break;
        }
        for (DWORD index = 0; index < returned; ++index) {
            if (delivered + rows.size() >= limits.total_entries) { bounded = true; stopped = true; break; }
            if (rows.size() >= limits.page_entries && !flush()) break;
            ENUM_SERVICE_STATUS_PROCESSW entry{};
            std::memcpy(&entry, native.data() + index * sizeof(entry), sizeof(entry));
            auto name = detail::service_text(native, entry.lpServiceName, 256);
            auto display = detail::service_text(native, entry.lpDisplayName, 256);
            const auto query_start = GetTickCount64(); Json config, security;
            if (name["state"] != "healthy" || name["value"] == "") {
                ++failures; ++optional_not_attempted; config = invalid("OpenServiceW/input", "enumerated_name_invalid");
                ++security_not_attempted; security = invalid("OpenServiceW/READ_CONTROL/input", "enumerated_name_invalid");
            } else {
                config = configuration(static_cast<SC_HANDLE>(manager.get()), entry.lpServiceName, failures, optional_not_attempted, optional_summary);
                security = query_service_security(manager.get(), entry.lpServiceName);
                if (!security.contains("native_query_succeeded")) ++security_opens_failed;
                else if (security["native_query_succeeded"] == true) ++security_success;
                else ++security_failed;
                if (security.contains("validation_failure_count")) security_invalid += std::stoull(security["validation_failure_count"].get<std::string>());
                if (security.value("bound_exceeded", false)) ++security_bounded;
            }
            const auto& status = entry.ServiceStatusProcess;
            Json row{{"snapshot_descriptor", {{"name", std::move(name)}, {"display_name", std::move(display)},
                {"reported_service_type", std::to_string(status.dwServiceType)}, {"reported_state", std::to_string(status.dwCurrentState)},
                {"reported_controls_accepted", std::to_string(status.dwControlsAccepted)}, {"reported_win32_exit_code", std::to_string(status.dwWin32ExitCode)},
                {"reported_service_exit_code", std::to_string(status.dwServiceSpecificExitCode)}, {"reported_checkpoint", std::to_string(status.dwCheckPoint)},
                {"reported_wait_hint", std::to_string(status.dwWaitHint)}, {"reported_process_id", std::to_string(status.dwProcessId)},
                {"reported_flags", std::to_string(status.dwServiceFlags)}, {"source", "ENUM_SERVICE_STATUS_PROCESSW"}}},
                {"later_configuration_query", std::move(config)}, {"later_security_query", std::move(security)},
                {"process_reference", nullptr}, {"service_instance_reference", nullptr},
                {"descriptor_configuration_relation", "unverified; service name may have been deleted/reused before OpenServiceW"},
                {"query_started_uptime_ms", std::to_string(query_start)}, {"query_completed_uptime_ms", std::to_string(GetTickCount64())}};
            auto size = row.dump().size() + (rows.empty() ? 0 : 1);
            if (size > limits.encoded_bytes - encoded) {
                if (rows.empty()) { bounded = true; stopped = true; break; }
                if (!flush()) break;
                size = row.dump().size();
                if (size > limits.encoded_bytes - encoded) { bounded = true; stopped = true; break; }
            }
            encoded += size; rows.push_back(std::move(row));
        }
        if (stopped) break;
        if (result) { complete = true; break; }
        if (!returned || !resume || resume == previous_resume) {
            enumeration_failure = invalid("EnumServicesStatusExW/resume", "resume_not_advancing");
            enumeration_failure["native_error_code"] = std::to_string(code); break;
        }
    }
    if (!refused && !rows.empty()) (void)flush();
    for (auto& query : optional_summary) {
        query["queries_not_attempted"] = std::to_string(optional_not_attempted);
        query["state"] = query["successful_native_queries"] == "0" ? "unavailable"
            : (query["failed_native_queries"] != "0" || query["uninterpreted_or_invalid_results"] != "0"
                || optional_not_attempted || !complete || bounded || refused) ? "degraded" : "healthy";
    }
    return {{"state", "degraded"}, {"service_state_version", "1.3"}, {"format", "paged_service_inventory_v1"},
        {"inventory_complete", false}, {"consistency", "non_atomic"}, {"enumeration_complete", complete && !bounded && !refused},
        {"bound_exceeded", bounded}, {"consumer_refused", refused}, {"pages_produced", std::to_string(pages)},
        {"entries_delivered", std::to_string(delivered)}, {"query_failure_count", std::to_string(failures)},
        {"optional_configuration_query_summary", std::move(optional_summary)},
        {"security_query_summary", {{"state", security_success ? "degraded" : "unavailable"},
            {"successful_native_queries", std::to_string(security_success)}, {"failed_native_queries", std::to_string(security_failed)},
            {"failed_security_opens", std::to_string(security_opens_failed)}, {"queries_not_attempted", std::to_string(security_not_attempted)},
            {"validation_failures", std::to_string(security_invalid)},
            {"bounded_results", std::to_string(security_bounded)},
            {"scope", "later separate READ_CONTROL object queries including undelivered rows; selected owner/group/DACL; not effective access, full security or instance association"}}},
        {"optional_configuration_summary_scope", "queried later service objects including undelivered rows; absent queries after OpenService/name refusal are not counted as native API failures; not full host coverage"},
        {"enumeration_failure", std::move(enumeration_failure)}, {"native_enumeration_calls", std::to_string(native_calls)},
        {"service_type_filter", std::to_string(types)}, {"service_state_filter", std::to_string(SERVICE_STATE_ALL)},
        {"page_entry_limit", limits.page_entries}, {"encoded_page_byte_limit", limits.encoded_bytes},
        {"total_entry_limit", limits.total_entries}, {"page_limit", limits.pages}, {"native_enumeration_byte_limit", limits.enumeration_bytes},
        {"query_failure_scope", "later configuration opens/queries/field and name-input refusals including undelivered rows; not lost events"},
        {"collection_started_uptime_ms", std::to_string(started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"scope", "caller-visible SCM win32/driver records; API can silently omit services without SERVICE_QUERY_STATUS; omitted set/count unknown"},
        {"lifecycle_continuity", "unverified"}, {"process_instances_verified", false}, {"service_instances_verified", false}};
}
}
