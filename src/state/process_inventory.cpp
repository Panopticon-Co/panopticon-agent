#include "panopticon/officer/state/process_inventory.hpp"
#include "panopticon/officer/state/process_token.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <array>
#include <memory>
#include <stdexcept>

namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
struct HandleCloser { void operator()(void* value) const noexcept { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
using Handle = std::unique_ptr<void, HandleCloser>;
Json unavailable(const char* source, DWORD error) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "Win32"}, {"error_code", std::to_string(error)}};
}
Json observed(Json value, const char* source) {
    return {{"state", "healthy"}, {"value", std::move(value)}, {"source", source}, {"error_code", nullptr}};
}
std::uint64_t ticks(FILETIME value) { return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
const char* machine_name(std::uint16_t value) {
    switch (value) {
        case IMAGE_FILE_MACHINE_UNKNOWN: return "IMAGE_FILE_MACHINE_UNKNOWN";
        case IMAGE_FILE_MACHINE_I386: return "IMAGE_FILE_MACHINE_I386";
        case IMAGE_FILE_MACHINE_AMD64: return "IMAGE_FILE_MACHINE_AMD64";
        case IMAGE_FILE_MACHINE_ARM: return "IMAGE_FILE_MACHINE_ARM";
        case IMAGE_FILE_MACHINE_THUMB: return "IMAGE_FILE_MACHINE_THUMB";
        case IMAGE_FILE_MACHINE_ARMNT: return "IMAGE_FILE_MACHINE_ARMNT";
        case IMAGE_FILE_MACHINE_ARM64: return "IMAGE_FILE_MACHINE_ARM64";
        case IMAGE_FILE_MACHINE_IA64: return "IMAGE_FILE_MACHINE_IA64";
#ifdef IMAGE_FILE_MACHINE_ARM64EC
        case IMAGE_FILE_MACHINE_ARM64EC: return "IMAGE_FILE_MACHINE_ARM64EC";
#endif
#ifdef IMAGE_FILE_MACHINE_ARM64X
        case IMAGE_FILE_MACHINE_ARM64X: return "IMAGE_FILE_MACHINE_ARM64X";
#endif
        default: return nullptr;
    }
}
using MachineQuery = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
struct ArchitectureApi { MachineQuery query; DWORD error; bool unsupported; const char* source; };
ArchitectureApi resolve_architecture_api() {
        const auto module = GetModuleHandleW(L"kernel32.dll");
        if (!module) return {nullptr, GetLastError(), false, "GetModuleHandleW/kernel32.dll/IsWow64Process2"};
        const auto address = GetProcAddress(module, "IsWow64Process2");
        if (!address) {
            const auto error = GetLastError();
            return {nullptr, error, error == ERROR_PROC_NOT_FOUND, "GetProcAddress/IsWow64Process2"};
        }
        return {reinterpret_cast<MachineQuery>(address), ERROR_SUCCESS, false, "IsWow64Process2/held handle"};
}
Json architecture_query(HANDLE process, const ArchitectureApi& api) {
    if (!api.query) {
        auto fact = unavailable(api.source, api.error);
        if (api.unsupported) { fact["state"] = "unsupported"; fact["reason"] = "native API entrypoint absent; machine codes not guessed"; }
        return fact;
    }
    USHORT process_machine = 0, native_machine = 0;
    if (!api.query(process, &process_machine, &native_machine)) return unavailable(api.source, GetLastError());
    return detail::process_machine_result(process_machine, native_machine);
}
Json text(const wchar_t* value, std::size_t size) {
    const auto needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(size), nullptr, 0, nullptr, nullptr);
    if (size == 0) return "";
    if (needed > 0) {
        std::string encoded(static_cast<std::size_t>(needed), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(size), encoded.data(), needed, nullptr, nullptr)) return encoded;
    }
    const auto* raw = reinterpret_cast<const unsigned char*>(value); std::string hex;
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t index = 0; index < size * sizeof(wchar_t); ++index) { hex += digits[raw[index] >> 4]; hex += digits[raw[index] & 15]; }
    return {{"encoding", "utf16le_hex"}, {"bytes", std::move(hex)}, {"byte_length", std::to_string(size * sizeof(wchar_t))}};
}
struct SecurityCounts {
    std::uint64_t critical_success = 0, critical_failure = 0;
    std::uint64_t protection_success = 0, protection_failure = 0, protection_uninterpreted = 0;
    std::uint64_t not_attempted = 0;
    std::uint64_t tokens_opened = 0, token_open_failures = 0;
    std::uint64_t token_fields_success = 0, token_fields_failed = 0, token_fields_uninterpreted = 0;
    std::uint64_t architecture_success = 0, architecture_failure = 0, architecture_unsupported = 0, architecture_uninterpreted = 0;
    Json json() const {
        const auto status = [&](std::uint64_t success, std::uint64_t failure, std::uint64_t unknown) {
            return !success ? "unavailable" : failure || unknown || not_attempted ? "degraded" : "healthy";
        };
        return {{"scope", "held-handle child queries including undelivered rows; not-attempted counts OpenProcess/GetProcessId refusal; not full host coverage"},
            {"process_queries_not_attempted", std::to_string(not_attempted)},
            {"critical_process", {{"state", status(critical_success, critical_failure, 0)},
                {"successful_queries", std::to_string(critical_success)}, {"failed_queries", std::to_string(critical_failure)}}},
            {"protection_level", {{"state", status(protection_success, protection_failure, protection_uninterpreted)},
                {"successful_queries", std::to_string(protection_success)}, {"failed_queries", std::to_string(protection_failure)},
                {"uninterpreted_results", std::to_string(protection_uninterpreted)}}},
            {"architecture", {{"state", architecture_success ? status(architecture_success, architecture_failure + architecture_unsupported, architecture_uninterpreted)
                    : architecture_unsupported && !architecture_failure ? "unsupported" : "unavailable"},
                {"successful_queries", std::to_string(architecture_success)}, {"failed_queries", std::to_string(architecture_failure)},
                {"unsupported_queries", std::to_string(architecture_unsupported)}, {"uninterpreted_results", std::to_string(architecture_uninterpreted)}}},
            {"primary_token", {{"state", token_fields_success ? "degraded" : "unavailable"},
                {"opened_tokens", std::to_string(tokens_opened)}, {"failed_token_opens", std::to_string(token_open_failures)},
                {"successful_field_queries", std::to_string(token_fields_success)}, {"failed_field_queries", std::to_string(token_fields_failed)},
                {"uninterpreted_fields", std::to_string(token_fields_uninterpreted)},
                {"scope", "selected primary token attributes; process not-attempted count also applies; not full token/effective access coverage"}}}};
    }
};
Json handle_query(DWORD pid, core::ProcessInstanceStore& identities, std::uint64_t& failures, SecurityCounts& security,
    const ArchitectureApi& machine_api) {
    Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process) { const auto error = GetLastError(); ++failures; ++security.not_attempted; return unavailable("OpenProcess/PROCESS_QUERY_LIMITED_INFORMATION", error); }
    const auto actual_pid = GetProcessId(process.get());
    if (!actual_pid || actual_pid != pid) { const auto error = actual_pid ? ERROR_INVALID_DATA : GetLastError(); ++failures; ++security.not_attempted; return unavailable("GetProcessId/held handle", error); }
    Json creation, image, critical, protection;
    FILETIME born{}, exited{}, kernel{}, user{};
    std::optional<std::uint64_t> native_creation;
    if (GetProcessTimes(process.get(), &born, &exited, &kernel, &user)) {
        const auto value = ticks(born);
        if (value) native_creation = value;
        creation = observed({{"creation_ticks", std::to_string(value)}, {"kernel_cpu_ticks", std::to_string(ticks(kernel))},
            {"user_cpu_ticks", std::to_string(ticks(user))}, {"exit_ticks", nullptr},
            {"exit_scope", "exit time not interpreted without independently verified termination"}}, "GetProcessTimes/held handle");
    } else { const auto error = GetLastError(); ++failures; creation = unavailable("GetProcessTimes/held handle", error); }
    std::array<wchar_t, 32768> path{}; DWORD length = static_cast<DWORD>(path.size());
    if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &length)) {
        if (length >= path.size()) { ++failures; image = unavailable("QueryFullProcessImageNameW/held handle", ERROR_INVALID_DATA); }
        else image = observed(text(path.data(), length), "QueryFullProcessImageNameW/held handle/Win32 path");
    } else { const auto error = GetLastError(); ++failures; image = unavailable("QueryFullProcessImageNameW/held handle", error); }
    BOOL is_critical = FALSE;
    if (IsProcessCritical(process.get(), &is_critical)) {
        ++security.critical_success;
        critical = observed(is_critical != FALSE, "IsProcessCritical/held handle");
    } else {
        const auto error = GetLastError(); ++failures; ++security.critical_failure;
        critical = unavailable("IsProcessCritical/held handle", error);
    }
    PROCESS_PROTECTION_LEVEL_INFORMATION level{};
    if (GetProcessInformation(process.get(), ProcessProtectionLevelInfo, &level, sizeof(level))) {
        ++security.protection_success;
        protection = detail::process_protection_result(level.ProtectionLevel);
        if (protection["state"] != "healthy") ++security.protection_uninterpreted;
    } else {
        const auto error = GetLastError(); ++failures; ++security.protection_failure;
        protection = unavailable("GetProcessInformation/ProcessProtectionLevelInfo/held handle", error);
    }
    auto primary_token = query_primary_process_token(process.get());
    if (primary_token.opened) {
        ++security.tokens_opened; security.token_fields_success += primary_token.successful_fields;
        security.token_fields_failed += primary_token.failed_fields;
        security.token_fields_uninterpreted += primary_token.uninterpreted_fields;
        failures += primary_token.failed_fields;
    } else { ++security.token_open_failures; ++failures; }
    auto architecture = architecture_query(process.get(), machine_api);
    if (architecture["state"] == "unsupported") { ++security.architecture_unsupported; }
    else if (!architecture["error_code"].is_null()) { ++failures; ++security.architecture_failure; }
    else { ++security.architecture_success; if (architecture["state"] != "healthy") ++security.architecture_uninterpreted; }
    return {{"state", "degraded"},
        {"source", "one held process handle; no reopen between identity, image and security queries"},
        {"reference", identities.observe(actual_pid, native_creation, std::nullopt, "Win32:held-process-query").json()},
        {"times", std::move(creation)}, {"image", std::move(image)}, {"liveness", "unverified"},
        {"critical_process", std::move(critical)}, {"protection_level", std::move(protection)},
        {"primary_token", std::move(primary_token.fact)},
        {"architecture", std::move(architecture)},
        {"consistency", "same_object_non_atomic_fields"}, {"error_code", nullptr}};
}
}
Json detail::process_machine_result(std::uint16_t process_machine, std::uint16_t native_machine) {
    const auto process_name = machine_name(process_machine), native_name = machine_name(native_machine);
    auto fact = observed({{"process_machine", std::to_string(process_machine)},
        {"native_machine", std::to_string(native_machine)},
        {"process_machine_symbol", process_name ? Json(process_name) : Json(nullptr)},
        {"native_machine_symbol", native_name ? Json(native_name) : Json(nullptr)},
        {"is_wow64", process_machine != IMAGE_FILE_MACHINE_UNKNOWN},
        {"scope", "API-reported WOW process and native host machine codes; image ABI/modules/ARM64EC hybrid semantics unverified"}},
        "IsWow64Process2/held handle");
    if (!process_name || !native_name || native_machine == IMAGE_FILE_MACHINE_UNKNOWN) fact["state"] = "degraded";
    return fact;
}
Json detail::process_protection_result(std::uint32_t level) {
    const char* symbol = nullptr; bool not_implemented = false;
    switch (level) {
        case PROTECTION_LEVEL_WINTCB_LIGHT: symbol = "PROTECTION_LEVEL_WINTCB_LIGHT"; break;
        case PROTECTION_LEVEL_WINDOWS: symbol = "PROTECTION_LEVEL_WINDOWS"; break;
        case PROTECTION_LEVEL_WINDOWS_LIGHT: symbol = "PROTECTION_LEVEL_WINDOWS_LIGHT"; break;
        case PROTECTION_LEVEL_ANTIMALWARE_LIGHT: symbol = "PROTECTION_LEVEL_ANTIMALWARE_LIGHT"; break;
        case PROTECTION_LEVEL_LSA_LIGHT: symbol = "PROTECTION_LEVEL_LSA_LIGHT"; break;
        case PROTECTION_LEVEL_PPL_APP: symbol = "PROTECTION_LEVEL_PPL_APP"; break;
        case PROTECTION_LEVEL_NONE: symbol = "PROTECTION_LEVEL_NONE"; break;
        case PROTECTION_LEVEL_WINTCB: symbol = "PROTECTION_LEVEL_WINTCB"; not_implemented = true; break;
        case PROTECTION_LEVEL_CODEGEN_LIGHT: symbol = "PROTECTION_LEVEL_CODEGEN_LIGHT"; not_implemented = true; break;
        case PROTECTION_LEVEL_AUTHENTICODE: symbol = "PROTECTION_LEVEL_AUTHENTICODE"; not_implemented = true; break;
    }
    auto result = observed({{"raw_protection_level", std::to_string(level)},
        {"documented_symbol", symbol ? Json(symbol) : Json(nullptr)},
        {"classification", !symbol ? "unknown_level" : not_implemented ? "documented_not_implemented"
            : level == PROTECTION_LEVEL_NONE ? "not_protected" : "documented_level"},
        {"interpretation_scope", "raw documented API level; internal signer/type bits and agent PPL readiness not inferred"}},
        "GetProcessInformation/ProcessProtectionLevelInfo/held handle");
    if (!symbol || not_implemented) result["state"] = "degraded";
    return result;
}
static Json collect(const std::string& host_id, const std::optional<std::string>& boot_id, ProcessInventoryLimits limits,
    const std::function<bool(Json)>& consumer, std::size_t total_limit, std::size_t page_limit) {
    if (!limits.entries || limits.entries > 8192 || limits.encoded_bytes < 2 || limits.encoded_bytes > 512 * 1024)
        throw std::invalid_argument("invalid process snapshot bounds");
    core::ProcessInstanceStore identities{host_id, boot_id, limits.entries};
    // Resolve once per capture; transient lookup failures are retried next capture.
    const auto machine_api = resolve_architecture_api();
    const auto started = GetTickCount64();
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snapshot.get() == INVALID_HANDLE_VALUE) return unavailable("CreateToolhelp32Snapshot/TH32CS_SNAPPROCESS", GetLastError());
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    Json rows = Json::array(); std::size_t bytes = 2; std::uint64_t failures = 0, exact = 0; SecurityCounts security;
    bool complete = true, bounded = false; DWORD enumeration_error = ERROR_SUCCESS;
    std::size_t pages = 0, delivered = 0; bool refused = false;
    const auto flush = [&]() {
        if (pages >= page_limit) { bounded = true; complete = false; return false; }
        const auto count = rows.size();
        Json page{{"state", "degraded"}, {"process_state_version", "1.4"}, {"page_index", std::to_string(pages)},
            {"entries", std::move(rows)}, {"inventory_complete", false}, {"consistency", "non_atomic"},
            {"collection_started_uptime_ms", std::to_string(started)}};
        ++pages;
        if (!consumer(std::move(page))) { refused = true; complete = false; return false; }
        delivered += count; rows = Json::array(); bytes = 2; return true;
    };
    BOOL available = Process32FirstW(snapshot.get(), &entry);
    if (!available && GetLastError() != ERROR_NO_MORE_FILES) return unavailable("Process32FirstW", GetLastError());
    while (available) {
        if (consumer && delivered + rows.size() >= total_limit) { complete = false; bounded = true; break; }
        if (rows.size() >= limits.entries) {
            if (!consumer) { complete = false; bounded = true; break; }
            if (!flush()) break;
        }
        const auto query_start = GetTickCount64();
        auto query = handle_query(entry.th32ProcessID, identities, failures, security, machine_api);
        const auto query_end = GetTickCount64();
        std::size_t name_length = 0; while (name_length < MAX_PATH && entry.szExeFile[name_length] != L'\0') ++name_length;
        Json row{{"snapshot_descriptor", {{"pid", entry.th32ProcessID}, {"reported_parent_pid", entry.th32ParentProcessID},
            {"reported_thread_count", entry.cntThreads}, {"reported_base_priority", entry.pcPriClassBase},
            {"reported_image_basename", text(entry.szExeFile, name_length)}, {"source", "PROCESSENTRY32W"}}},
            {"later_pid_query", std::move(query)}, {"descriptor_instance_relation", "unverified; PID may have been reused before OpenProcess"},
            {"parent_reference", nullptr}, {"query_started_uptime_ms", std::to_string(query_start)}, {"query_completed_uptime_ms", std::to_string(query_end)}};
        const auto size = row.dump().size() + (rows.empty() ? 0 : 1);
        if (size > limits.encoded_bytes - bytes) {
            if (!consumer || rows.empty()) { complete = false; bounded = true; break; }
            if (!flush()) break;
            if (row.dump().size() > limits.encoded_bytes - bytes) { complete = false; bounded = true; break; }
        }
        bytes += row.dump().size() + (rows.empty() ? 0 : 1);
        if (row["later_pid_query"].contains("reference") && row["later_pid_query"]["reference"]["resolution"] == "native_exact") ++exact;
        rows.push_back(std::move(row));
        entry.dwSize = sizeof(entry); available = Process32NextW(snapshot.get(), &entry);
        if (!available) { const auto error = GetLastError(); if (error != ERROR_NO_MORE_FILES) { complete = false; enumeration_error = error; } }
    }
    if (consumer && !refused && !rows.empty()) (void)flush();
    if (consumer) return {{"state", "degraded"}, {"process_state_version", "1.4"}, {"format", "paged_process_inventory_v1"},
        {"inventory_complete", false}, {"consistency", "non_atomic"}, {"enumeration_complete", complete},
        {"bound_exceeded", bounded}, {"consumer_refused", refused}, {"pages_produced", std::to_string(pages)},
        {"entries_delivered", std::to_string(delivered)}, {"total_entry_limit", total_limit}, {"page_limit", page_limit},
        {"query_failure_count", std::to_string(failures)}, {"native_exact_query_references", std::to_string(exact)},
        {"security_query_summary", security.json()},
        {"enumeration_error_code", enumeration_error ? Json(std::to_string(enumeration_error)) : Json(nullptr)},
        {"collection_started_uptime_ms", std::to_string(started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"parent_instances_verified", false}, {"lifecycle_continuity", "unverified"}};
    return {{"state", "degraded"}, {"process_state_version", "1.3"}, {"inventory_complete", false}, {"consistency", "non_atomic"},
        {"snapshot_type", "toolhelp_descriptors_and_later_held_handle_queries"}, {"entries", std::move(rows)},
        {"enumeration_complete", complete}, {"bound_exceeded", bounded}, {"entry_limit", limits.entries}, {"encoded_entry_byte_limit", limits.encoded_bytes},
        {"query_failure_count", std::to_string(failures)}, {"query_failure_scope", "child query failures, including queried row omitted by byte bound; not lost events"},
        {"native_exact_query_references", std::to_string(exact)}, {"enumeration_error_code", enumeration_error ? Json(std::to_string(enumeration_error)) : Json(nullptr)},
        {"security_query_summary", security.json()},
        {"collection_started_uptime_ms", std::to_string(started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"lifecycle_continuity", "unverified"}, {"parent_instances_verified", false}, {"token_modules_handles_threads_complete", false}};
}
Json collect_process_inventory(const std::string& host_id, const std::optional<std::string>& boot_id, ProcessInventoryLimits limits) {
    return collect(host_id, boot_id, limits, {}, limits.entries, 1);
}
Json collect_process_inventory_pages(const std::string& host_id, const std::optional<std::string>& boot_id,
    const std::function<bool(Json)>& consumer, ProcessInventoryLimits limits, std::size_t total_limit, std::size_t page_limit) {
    if (!consumer || !total_limit || total_limit > 65536 || !page_limit || page_limit > 4096)
        throw std::invalid_argument("invalid paged process snapshot limits");
    return collect(host_id, boot_id, limits, consumer, total_limit, page_limit);
}
}
