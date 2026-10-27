#include "panopticon/officer/state/remote_access_inventory.hpp"
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include "persistence_native.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <lm.h>

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>
#include <algorithm>

namespace panopticon::officer::state {
using namespace native_persistence;

namespace {
struct NetBuffer {
    LPBYTE value = nullptr;
    ~NetBuffer() { if (value) NetApiBufferFree(value); }
    NetBuffer(const NetBuffer&) = delete;
    NetBuffer& operator=(const NetBuffer&) = delete;
    NetBuffer() = default;
};

bool within(const std::byte* base, std::size_t bytes, const void* pointer, std::size_t need) {
    if (!pointer || !base || need > bytes) return false;
    const auto p = reinterpret_cast<std::uintptr_t>(pointer);
    const auto b = reinterpret_cast<std::uintptr_t>(base);
    return p >= b && p - b <= bytes - need;
}

Json bounded_text(Pager& pager, const std::byte* base, std::size_t bytes, const wchar_t* value) {
    if (!value) return nullptr;
    if (!within(base, bytes, value, sizeof(wchar_t))) {
        pager.field({{"state", "unavailable"}, {"source", "NetAPI buffer validation"}, {"reason", "string_pointer_outside_buffer"}});
        return {{"state", "unavailable"}, {"value", nullptr}, {"reason", "string_pointer_outside_buffer"}};
    }
    const auto offset = reinterpret_cast<const std::byte*>(value) - base;
    const auto remaining_units = (bytes - static_cast<std::size_t>(offset)) / sizeof(wchar_t);
    const auto max_units = std::min(remaining_units, pager.limits.field_bytes / sizeof(wchar_t));
    std::size_t units = 0;
    while (units < max_units && value[units] != L'\0') ++units;
    if (units == max_units) {
        pager.field({{"state", "degraded"}, {"source", "NetAPI buffer validation"}, {"bound_exceeded", true}});
        return {{"state", "degraded"}, {"value", nullptr}, {"bound_exceeded", true}, {"reason", "unterminated_or_oversized_string"}};
    }
    return text(value, units);
}

bool append_sessions(Pager& pager, bool& complete) {
    DWORD resume = 0;
    for (;;) {
        if (!pager.active()) { complete = false; return false; }
        NetBuffer buffer;
        DWORD read = 0, total = 0;
        const NET_API_STATUS status = NetSessionEnum(nullptr, nullptr, nullptr, 10,
            &buffer.value, 64 * 1024, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            auto query = failure("NetSessionEnum", status, "NetAPI"); pager.field(query);
            pager.add({{"entry_kind", "smb_session_query"}, {"query", std::move(query)}, {"scope", "local_server"}});
            pager.partitions.push_back({{"partition", "smb_sessions"}, {"enumeration_complete", false}, {"reported_total", std::to_string(total)}});
            complete = false; return false;
        }
        DWORD native_bytes = 0;
        if (buffer.value) {
            if (NetApiBufferSize(buffer.value, &native_bytes) != NERR_Success ||
                static_cast<std::size_t>(native_bytes) > pager.limits.encoded_bytes * 4) {
                pager.field({{"state", "degraded"}, {"source", "NetSessionEnum buffer"}, {"bound_exceeded", true}});
                pager.add({{"entry_kind", "smb_session_query"}, {"state", "degraded"}, {"reason", "native_buffer_size_unavailable_or_excessive"}});
                complete = false; return false;
            }
        }
        const auto bytes = static_cast<std::size_t>(native_bytes);
        auto* rows = reinterpret_cast<SESSION_INFO_10*>(buffer.value);
        if (static_cast<std::uint64_t>(read) * sizeof(SESSION_INFO_10) > bytes) {
            pager.field({{"state", "unavailable"}, {"source", "NetSessionEnum buffer"}});
            pager.add({{"entry_kind", "smb_session_query"}, {"state", "unavailable"}, {"reason", "row_array_outside_buffer"}});
            complete = false; return false;
        }
        for (DWORD i = 0; i < read && pager.active(); ++i) {
            const auto* base = reinterpret_cast<const std::byte*>(buffer.value);
            Json row{{"entry_kind", "smb_server_session"}, {"scope", "local_server"},
                {"client_name", bounded_text(pager, base, bytes, rows[i].sesi10_cname)},
                {"username", bounded_text(pager, base, bytes, rows[i].sesi10_username)},
                {"session_seconds", std::to_string(rows[i].sesi10_time)},
                {"idle_seconds", std::to_string(rows[i].sesi10_idle_time)},
                {"process_entity_id", nullptr}, {"actor_identity_verified", false}};
            if (!pager.add(std::move(row))) { complete = false; return false; }
        }
        if (status == NERR_Success) break;
        if (read == 0) { complete = false; pager.partitions.push_back({{"partition", "smb_sessions"}, {"enumeration_complete", false}, {"reason", "no_progress"}}); return false; }
    }
    pager.partitions.push_back({{"partition", "smb_sessions"}, {"enumeration_complete", true}});
    return true;
}

bool append_open_files(Pager& pager, bool& complete) {
    DWORD_PTR resume = 0;
    for (;;) {
        if (!pager.active()) { complete = false; return false; }
        NetBuffer buffer;
        DWORD read = 0, total = 0;
        const NET_API_STATUS status = NetFileEnum(nullptr, nullptr, nullptr, 3,
            &buffer.value, 64 * 1024, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            auto query = failure("NetFileEnum", status, "NetAPI"); pager.field(query);
            pager.add({{"entry_kind", "smb_open_file_query"}, {"query", std::move(query)}, {"scope", "local_server"}});
            pager.partitions.push_back({{"partition", "smb_open_files"}, {"enumeration_complete", false}, {"reported_total", std::to_string(total)}});
            complete = false; return false;
        }
        DWORD native_bytes = 0;
        if (buffer.value && (NetApiBufferSize(buffer.value, &native_bytes) != NERR_Success ||
            static_cast<std::size_t>(native_bytes) > pager.limits.encoded_bytes * 4)) {
            pager.field({{"state", "degraded"}, {"source", "NetFileEnum buffer"}, {"bound_exceeded", true}});
            pager.add({{"entry_kind", "smb_open_file_query"}, {"state", "degraded"}, {"reason", "native_buffer_size_unavailable_or_excessive"}});
            complete = false; return false;
        }
        const auto bytes = static_cast<std::size_t>(native_bytes);
        auto* rows = reinterpret_cast<FILE_INFO_3*>(buffer.value);
        if (static_cast<std::uint64_t>(read) * sizeof(FILE_INFO_3) > bytes) {
            pager.field({{"state", "unavailable"}, {"source", "NetFileEnum buffer"}});
            pager.add({{"entry_kind", "smb_open_file_query"}, {"state", "unavailable"}, {"reason", "row_array_outside_buffer"}});
            complete = false; return false;
        }
        for (DWORD i = 0; i < read && pager.active(); ++i) {
            const auto* base = reinterpret_cast<const std::byte*>(buffer.value);
            Json row{{"entry_kind", "smb_server_open_file"}, {"scope", "local_server"},
                {"file_id", std::to_string(rows[i].fi3_id)},
                {"permissions_mask", std::to_string(rows[i].fi3_permissions)},
                {"lock_count", std::to_string(rows[i].fi3_num_locks)},
                {"path", bounded_text(pager, base, bytes, rows[i].fi3_pathname)},
                {"username", bounded_text(pager, base, bytes, rows[i].fi3_username)},
                {"process_entity_id", nullptr}, {"file_identity_verified", false}};
            if (!pager.add(std::move(row))) { complete = false; return false; }
        }
        if (status == NERR_Success) break;
        if (read == 0) { complete = false; pager.partitions.push_back({{"partition", "smb_open_files"}, {"enumeration_complete", false}, {"reason", "no_progress"}}); return false; }
    }
    pager.partitions.push_back({{"partition", "smb_open_files"}, {"enumeration_complete", true}});
    return true;
}

// Live SCM state of the remote-access services. Running is not proof that a
// listener accepts connections (firewall, configuration and NLA still apply).
bool append_remote_services(Pager& pager, bool& complete) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        auto query = failure("OpenSCManagerW", GetLastError(), "Win32"); pager.field(query);
        pager.add({{"entry_kind", "remote_access_service_query"}, {"query", std::move(query)}});
        pager.partitions.push_back({{"partition", "remote_access_services"}, {"enumeration_complete", false}});
        complete = false; return false;
    }
    bool all = true;
    for (const auto* name : {L"TermService", L"WinRM"}) {
        if (!pager.active()) { all = false; break; }
        Json row{{"entry_kind", "remote_access_service"}, {"service_name", text(name, wcslen(name))},
            {"source", "QueryServiceStatusEx"}, {"listener_accepting_verified", false}};
        SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (!service) {
            const auto error = GetLastError();
            row["query"] = failure("OpenServiceW", error, "Win32");
            row["state"] = error == ERROR_SERVICE_DOES_NOT_EXIST ? "not_present" : "unavailable";
            if (error != ERROR_SERVICE_DOES_NOT_EXIST) { pager.field(row["query"]); all = false; }
        } else {
            SERVICE_STATUS_PROCESS status{}; DWORD needed = 0;
            if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
                    sizeof(status), &needed)) {
                row["state"] = "healthy";
                row["current_state_value"] = std::to_string(status.dwCurrentState);
                row["running"] = status.dwCurrentState == SERVICE_RUNNING;
                row["process_id"] = status.dwProcessId ? Json(std::to_string(status.dwProcessId)) : Json(nullptr);
            } else {
                row["query"] = failure("QueryServiceStatusEx", GetLastError(), "Win32");
                row["state"] = "unavailable"; pager.field(row["query"]); all = false;
            }
            DWORD config_bytes = 0;
            QueryServiceConfigW(service, nullptr, 0, &config_bytes);
            if (config_bytes && config_bytes <= 8192) {
                std::vector<std::byte> buffer(config_bytes);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
                if (QueryServiceConfigW(service, config, config_bytes, &config_bytes))
                    row["start_type_value"] = std::to_string(config->dwStartType);
            }
            CloseServiceHandle(service);
        }
        if (!pager.add(std::move(row))) { all = false; break; }
    }
    CloseServiceHandle(manager);
    pager.partitions.push_back({{"partition", "remote_access_services"}, {"enumeration_complete", all}});
    complete = complete && all;
    return all;
}

// Configured RDP settings, including the Group Policy override key. Values are
// raw registry data: no effective-policy merge or listener verification.
bool append_rdp_configuration(Pager& pager, bool& complete) {
    static constexpr const wchar_t* server_fields[]{L"fDenyTSConnections", L"fSingleSessionPerUser"};
    static constexpr const wchar_t* listener_fields[]{L"PortNumber", L"UserAuthentication", L"SecurityLayer",
        L"MinEncryptionLevel", L"fEnableWinStation"};
    static constexpr const wchar_t* policy_fields[]{L"fDenyTSConnections", L"UserAuthentication", L"SecurityLayer",
        L"MinEncryptionLevel", L"fDisableCdm", L"fDisableClip"};
    bool ok = registry_values(pager, HKEY_LOCAL_MACHINE, "HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        KEY_WOW64_64KEY, server_fields, "rdp_configuration");
    ok = registry_values(pager, HKEY_LOCAL_MACHINE, "HKLM",
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", KEY_WOW64_64KEY,
        listener_fields, "rdp_configuration") && ok;
    ok = registry_values(pager, HKEY_LOCAL_MACHINE, "HKLM",
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", KEY_WOW64_64KEY, policy_fields,
        "rdp_policy") && ok;
    pager.partitions.push_back({{"partition", "rdp_configuration"}, {"enumeration_complete", ok},
        {"scope", "configured registry values; policy key may be absent; not effective policy or listener state"}});
    complete = complete && ok;
    return ok;
}

// Configured WinRM service settings and listeners (WSMan registry store).
// The plan's local WSMan API enumeration remains a stronger, future source.
bool append_winrm_configuration(Pager& pager, bool& complete) {
    static constexpr const wchar_t* service_fields[]{L"allow_unencrypted", L"auth_basic", L"auth_kerberos",
        L"auth_negotiate", L"auth_certificate", L"auth_credssp"};
    static constexpr const wchar_t* listener_fields[]{L"Port", L"hostname", L"enabled", L"certThumbprint",
        L"uriprefix", L"Transport"};
    const std::wstring root = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN";
    bool ok = registry_values(pager, HKEY_LOCAL_MACHINE, "HKLM", root + L"\\Service", KEY_WOW64_64KEY,
        service_fields, "winrm_configuration");
    HKEY listeners = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, (root + L"\\Listener").c_str(), 0,
        KEY_READ | KEY_WOW64_64KEY, &listeners);
    std::size_t count = 0;
    if (opened == ERROR_SUCCESS) {
        for (DWORD index = 0; index < 64 && pager.active(); ++index) {
            wchar_t name[256]{}; DWORD length = 256;
            const auto status = RegEnumKeyExW(listeners, index, name, &length, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) {
                auto query = failure("RegEnumKeyExW", status, "Win32"); pager.field(query); ok = false; break;
            }
            ++count;
            ok = registry_values(pager, HKEY_LOCAL_MACHINE, "HKLM", root + L"\\Listener\\" + name, KEY_WOW64_64KEY,
                listener_fields, "winrm_listener") && ok;
        }
        RegCloseKey(listeners);
    } else if (opened != ERROR_FILE_NOT_FOUND) {
        auto query = failure("RegOpenKeyExW", opened, "Win32"); pager.field(query); ok = false;
    }
    pager.partitions.push_back({{"partition", "winrm_configuration"}, {"enumeration_complete", ok},
        {"configured_listener_count", std::to_string(count)},
        {"scope", "WSMan registry store; not runtime listener verification or effective GPO merge"}});
    complete = complete && ok;
    return ok;
}
}

nlohmann::json collect_remote_access_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer, NativeInventoryLimits limits,
    const std::function<bool()>& cancelled) {
    Pager pager(limits, "remote_access_inventory", consumer, cancelled, "remote_access_state_version");
    bool complete = true;
    append_sessions(pager, complete);
    if (pager.active()) append_open_files(pager, complete);
    // Each partition runs independently: one refused query must not hide the others.
    if (pager.active()) append_remote_services(pager, complete);
    if (pager.active()) append_rdp_configuration(pager, complete);
    if (pager.active()) append_winrm_configuration(pager, complete);
    return pager.finish("local SMB server sessions/open files, TermService/WinRM service state, configured RDP "
        "settings and WSMan listeners visible to this caller; no outbound client, effective policy, live listener "
        "verification, actor process attribution or atomic cross-query snapshot", complete);
}
}
