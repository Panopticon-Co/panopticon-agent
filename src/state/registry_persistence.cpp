#include "persistence_native.hpp"
#include <sddl.h>
#include <array>
#include <stdexcept>

namespace panopticon::officer::state::native_persistence {
namespace {
struct Key {
    HKEY value = nullptr;
    ~Key() { if (value) RegCloseKey(value); }
};
using Visit = std::function<bool(const std::wstring&)>;
bool children(Pager& pager, HKEY hive, const char* hive_name, const std::wstring& path,
    REGSAM view, const char* mechanism, const Visit& visit, DWORD maximum = 256) {
    Json row{{"entry_kind", "registry_branch_scan"}, {"mechanism", mechanism},
        {"registry_hive", hive_name}, {"key_path", text(path.data(), path.size())},
        {"registry_view", view == KEY_WOW64_32KEY ? "32" : "64"},
        {"consistency", "non_atomic_indexed_registry_queries"}, {"index_limit", std::to_string(maximum)}};
    Key key;
    const auto opened = RegOpenKeyExW(hive, path.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | view, &key.value);
    if (opened != ERROR_SUCCESS) {
        const bool absent = opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND;
        row["query"] = absent ? Json{{"state", "healthy"}, {"key_exists", false}, {"error_code", std::to_string(opened)}}
            : failure("RegOpenKeyExW/enumerate persistence subkeys", opened, "Win32");
        row["enumeration_complete"] = absent;
        pager.field(row["query"]);
        return pager.add(std::move(row)) && absent;
    }
    std::array<wchar_t, 256> name{};
    DWORD index = 0;
    bool complete = false, descendants_complete = true;
    for (; index < maximum && pager.active(); ++index) {
        DWORD units = static_cast<DWORD>(name.size()); FILETIME written{};
        const auto status = RegEnumKeyExW(key.value, index, name.data(), &units, nullptr, nullptr, nullptr, &written);
        if (status == ERROR_NO_MORE_ITEMS) { complete = true; break; }
        if (status != ERROR_SUCCESS || units >= name.size()) {
            ++pager.failures;
            row["query"] = failure("RegEnumKeyExW/persistence branch", status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status, "Win32");
            break;
        }
        // Registry component names cannot contain a backslash; validate instead
        // of allowing malformed native/test output to change the selected scope.
        const std::wstring component(name.data(), units);
        if (component.empty() || component.find(L'\\') != std::wstring::npos) {
            ++pager.failures; row["query"] = failure("invalid registry subkey component", ERROR_INVALID_DATA, "Win32"); break;
        }
        descendants_complete = visit(path + L"\\" + component) && descendants_complete;
    }
    row["key_exists"] = true;
    row["examined_indices"] = std::to_string(index);
    row["subkey_index_limit_exceeded"] = index == maximum;
    row["enumeration_complete"] = complete && descendants_complete && pager.active();
    const bool result = row["enumeration_complete"] == true;
    return pager.add(std::move(row)) && result;
}
}

bool registry_mechanism_scope(Pager& pager, PersistenceSource source, HKEY hive,
    const char* hive_name, const std::wstring& prefix) {
    const char* mechanism = persistence_source_name(source);
    bool complete = true;
    const auto path = [&](const wchar_t* relative) { return prefix.empty() ? std::wstring(relative) : prefix + L"\\" + relative; };
    for (const auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        const auto values = [&](const std::wstring& key, std::span<const wchar_t* const> selected) {
            return pager.active() && registry_values(pager, hive, hive_name, key, view, selected, mechanism);
        };
        switch (source) {
        case PersistenceSource::active_setup: {
            constexpr const wchar_t* selected[]{L"", L"StubPath", L"Version", L"Locale", L"IsInstalled", L"ComponentID"};
            complete = children(pager, hive, hive_name, path(L"Software\\Microsoft\\Active Setup\\Installed Components"), view, mechanism,
                [&](const std::wstring& child) { return values(child, selected); }) && complete;
            break;
        }
        case PersistenceSource::image_execution: {
            constexpr const wchar_t* selected[]{L"Debugger", L"GlobalFlag", L"VerifierDlls", L"VerifierFlags", L"UseFilter", L"FilterFullPath", L"MitigationOptions"};
            complete = children(pager, hive, hive_name, path(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), view, mechanism,
                [&](const std::wstring& child) {
                    const bool parent = values(child, selected);
                    const bool filters = children(pager, hive, hive_name, child, view, mechanism,
                        [&](const std::wstring& filter) { return values(filter, selected); }, 32);
                    return parent && filters;
                }) && complete;
            constexpr const wchar_t* exit_fields[]{L"MonitorProcess", L"ReportingMode", L"IgnoreSelfExits", L"LocalDumpFolder", L"DumpType", L"MaxNumberOfDumpFiles"};
            const auto exit_path = path(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit");
            complete = values(exit_path, exit_fields) && complete;
            complete = children(pager, hive, hive_name, exit_path, view, mechanism,
                [&](const std::wstring& child) { return values(child, exit_fields); }) && complete;
            constexpr const wchar_t* boot_fields[]{L"BootExecute", L"SetupExecute", L"Execute"};
            complete = values(path(L"System\\CurrentControlSet\\Control\\Session Manager"), boot_fields) && complete;
            if (pager.active()) complete = registry_values(pager, hive, hive_name,
                path(L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"), view, {}, mechanism) && complete;
            break;
        }
        case PersistenceSource::com_activation: {
            constexpr const wchar_t* clsid_fields[]{L"AppID", L"LocalService"};
            constexpr const wchar_t* inproc_fields[]{L"", L"ThreadingModel"};
            constexpr const wchar_t* local_fields[]{L"", L"ServerExecutable"};
            constexpr const wchar_t* default_field[]{L""};
            complete = children(pager, hive, hive_name, path(L"Software\\Classes\\CLSID"), view, mechanism,
                [&](const std::wstring& child) {
                    bool ok = values(child, clsid_fields);
                    ok = values(child + L"\\InprocServer32", inproc_fields) && ok;
                    ok = values(child + L"\\InprocHandler32", inproc_fields) && ok;
                    ok = values(child + L"\\LocalServer32", local_fields) && ok;
                    ok = values(child + L"\\TreatAs", default_field) && ok;
                    ok = values(child + L"\\AutoTreatAs", default_field) && ok;
                    return ok;
                }) && complete;
            constexpr const wchar_t* appid_fields[]{L"LocalService", L"ServiceParameters", L"DllSurrogate", L"DllSurrogateExecutable", L"RunAs", L"LaunchPermission", L"AccessPermission"};
            complete = children(pager, hive, hive_name, path(L"Software\\Classes\\AppID"), view, mechanism,
                [&](const std::wstring& child) { return values(child, appid_fields); }) && complete;
            break;
        }
        case PersistenceSource::startup_approval:
            for (const auto* leaf : {L"Run", L"Run32", L"StartupFolder"}) {
                if (!pager.active()) { complete = false; break; }
                complete = registry_values(pager, hive, hive_name,
                    path(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved") + L"\\" + leaf,
                    view, {}, mechanism) && complete;
            }
            break;
        default: throw std::invalid_argument("not an extended registry persistence source");
        }
    }
    return complete && pager.active();
}

Json registry_mechanism(Pager& pager, PersistenceSource source) {
    bool complete = true;
    // User scopes first for per-user overrides, without merging HKCR or claiming
    // that the collector's HKCU is the interactive user's hive under a service.
    if (source != PersistenceSource::image_execution) {
        complete = registry_mechanism_scope(pager, source, HKEY_CURRENT_USER, "HKCU/caller") && complete;
        std::array<wchar_t, 256> name{};
        DWORD index = 0; bool user_enumeration_complete = false;
        for (; index < 128 && pager.active(); ++index) {
            DWORD units = static_cast<DWORD>(name.size());
            const auto status = RegEnumKeyExW(HKEY_USERS, index, name.data(), &units, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS) { user_enumeration_complete = true; break; }
            if (status != ERROR_SUCCESS || units >= name.size()) {
                ++pager.failures; complete = false;
                if (!pager.add({{"entry_kind", "loaded_user_hive_error"}, {"query", failure("HKU/RegEnumKeyExW", status, "Win32")}})) break;
                break;
            }
            const std::wstring user(name.data(), units);
            PSID sid = nullptr;
            if (!ConvertStringSidToSidW(user.c_str(), &sid)) continue;
            LocalFree(sid);
            complete = registry_mechanism_scope(pager, source, HKEY_USERS, "HKU/loaded SID hive", user) && complete;
        }
        pager.partitions.push_back({{"source", "loaded_HKU"}, {"index_limit", "128"},
            {"examined_indices", std::to_string(index)}, {"enumeration_complete", user_enumeration_complete},
            {"unloaded_hives_observed", false}});
        complete = complete && user_enumeration_complete;
    }
    if (pager.active()) complete = registry_mechanism_scope(pager, source, HKEY_LOCAL_MACHINE, "HKLM") && complete;
    else complete = false;
    auto result = pager.finish("selected raw native registry persistence configuration; explicit views and query failures; no execution/actor/effective activation assertion", complete);
    result["mechanism"] = persistence_source_name(source);
    result["subkey_index_limit"] = "256";
    result["filter_subkey_index_limit"] = "32";
    result["state_deltas_verified"] = false;
    result["effective_persistence_verified"] = false;
    result["unloaded_user_hives_observed"] = false;
    result["registry_view_scope"] = "requested 32/64 views; native OS redirection/sharing rules apply; no claim of distinct physical keys";
    result["resource_scope"] = "bounded application copies/pages/subkey indices; native calls lack hard deadline/allocation bounds; bounded prefix scans may omit later keys";
    return result;
}
}
