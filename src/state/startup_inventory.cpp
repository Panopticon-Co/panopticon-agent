#include "persistence_native.hpp"
#include <shlobj.h>
#include <sddl.h>
#include <array>

namespace panopticon::officer::state::native_persistence {
namespace {
struct Key { HKEY value = nullptr; ~Key() { if (value) RegCloseKey(value); } };
struct FindCloser { void operator()(void* value) const noexcept { if (value && value != INVALID_HANDLE_VALUE) FindClose(value); } };
using Find = std::unique_ptr<void, FindCloser>;
const wchar_t* autorun_keys[]{L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"};
bool registry(Pager& pager, HKEY hive, const char* hive_name, const std::wstring& path, REGSAM view,
    std::span<const wchar_t* const> selected = {}) {
    Json base{{"registry_hive", hive_name}, {"key_path", text(path.data(), path.size())},
        {"registry_view", view == KEY_WOW64_32KEY ? "32" : "64"}, {"consistency", "non_atomic_indexed_registry_queries"}};
    Key key; const auto opened = RegOpenKeyExW(hive, path.c_str(), 0, KEY_QUERY_VALUE | view, &key.value);
    if (opened != ERROR_SUCCESS) {
        auto row = base; row["entry_kind"] = "registry_key_scan";
        row["query"] = opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND ?
            Json{{"state", "healthy"}, {"key_exists", false}, {"error_code", std::to_string(opened)}} : failure("RegOpenKeyExW", opened, "Win32");
        pager.field(row["query"]); pager.add(std::move(row));
        return opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND;
    }
    std::vector<wchar_t> name(16384); std::vector<std::byte> bytes(pager.limits.field_bytes);
    bool complete = true; DWORD index = 0;
    for (; pager.active(); ++index) {
        DWORD name_units = static_cast<DWORD>(name.size()), data_bytes = static_cast<DWORD>(bytes.size()), type = 0;
        LSTATUS status;
        if (selected.empty()) status = RegEnumValueW(key.value, index, name.data(), &name_units, nullptr, &type, reinterpret_cast<BYTE*>(bytes.data()), &data_bytes);
        else {
            if (index >= selected.size()) break;
            const auto units = std::wcslen(selected[index]);
            std::copy_n(selected[index], units, name.data()); name_units = static_cast<DWORD>(units);
            status = RegQueryValueExW(key.value, selected[index], nullptr, &type, reinterpret_cast<BYTE*>(bytes.data()), &data_bytes);
            if (status == ERROR_FILE_NOT_FOUND) {
                auto row = base; row["entry_kind"] = "startup_registry_value"; row["value_name"] = text(name.data(), name_units);
                row["query"] = {{"state", "healthy"}, {"value_exists", false}, {"error_code", std::to_string(status)}};
                if (!pager.add(std::move(row))) return false;
                continue;
            }
        }
        if (status == ERROR_NO_MORE_ITEMS) break;
        auto row = base; row["entry_kind"] = "startup_registry_value";
        // ERROR_MORE_DATA leaves value name/data undefined. Never decode either.
        if (status != ERROR_SUCCESS || name_units >= name.size() || data_bytes > bytes.size()) {
            row["query"] = failure(selected.empty() ? "RegEnumValueW" : "RegQueryValueExW", status, "Win32");
            row["query"]["bound_exceeded"] = status == ERROR_MORE_DATA || data_bytes > bytes.size() || name_units >= name.size();
            row["query"]["reported_required_bytes"] = std::to_string(data_bytes); complete = false;
            pager.field(row["query"]);
            if (!pager.add(std::move(row))) return false;
            // Retry by index risks silent omission when concurrent edits reorder
            // values. Continue only oversized entries; all other errors stop key.
            if (status != ERROR_MORE_DATA) break;
            continue;
        }
        row["value_name"] = text(name.data(), name_units);
        row["query"] = detail::persistence_registry_data(type, {bytes.data(), data_bytes}); pager.field(row["query"]);
        row["environment_expanded"] = false; row["process_entity_id"] = nullptr; row["effective_startup_execution"] = "unverified";
        if (!pager.add(std::move(row))) return false;
    }
    auto summary = base; summary["entry_kind"] = "registry_key_scan"; summary["key_exists"] = true;
    summary["enumeration_complete"] = complete && pager.active(); summary["examined_indices"] = std::to_string(index);
    pager.add(std::move(summary)); return complete && pager.active();
}
bool startup_folder(Pager& pager, REFKNOWNFOLDERID folder_id, const char* scope) {
    PWSTR folder = nullptr; const auto status = SHGetKnownFolderPath(folder_id, KF_FLAG_DONT_VERIFY, nullptr, &folder);
    std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> owned(folder, CoTaskMemFree);
    if (FAILED(status) || !folder) {
        ++pager.failures; pager.add({{"entry_kind", "startup_folder_scan"}, {"folder_scope", scope},
            {"query", failure("SHGetKnownFolderPath", static_cast<std::uint32_t>(status))}}); return false;
    }
    const std::wstring directory(folder); auto pattern = directory + L"\\*";
    WIN32_FIND_DATAW found{}; Find handle{FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &found, FindExSearchNameMatch, nullptr, 0)};
    if (handle.get() == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        pager.add({{"entry_kind", "startup_folder_scan"}, {"folder_scope", scope}, {"path", text(directory.data(), directory.size())},
            {"query", error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ?
                Json{{"state", "healthy"}, {"empty_or_absent", true}, {"error_code", std::to_string(error)}} : failure("FindFirstFileExW", error, "Win32")}});
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) ++pager.failures;
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    bool complete = false;
    while (pager.active()) {
        if (std::wstring_view{found.cFileName} != L"." && std::wstring_view{found.cFileName} != L"..") {
            const auto file_name = directory + L"\\" + found.cFileName;
            const auto filetime = [](FILETIME value) { return std::to_string((static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime); };
            Json row{{"entry_kind", "startup_folder_entry"}, {"state", "degraded"}, {"folder_scope", scope},
                {"configured_path", text(file_name.data(), file_name.size())}, {"reported_file_attributes", std::to_string(found.dwFileAttributes)},
                {"reported_size_bytes", std::to_string((static_cast<std::uint64_t>(found.nFileSizeHigh) << 32) | found.nFileSizeLow)},
                {"reported_creation_filetime", filetime(found.ftCreationTime)}, {"reported_last_write_filetime", filetime(found.ftLastWriteTime)},
                {"reported_reparse_tag", (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? Json(std::to_string(found.dwReserved0)) : Json(nullptr)},
                {"file_entity_id", nullptr}, {"resolved_shortcut_target", nullptr}, {"scope", "directory entry metadata; no recursive traversal, shortcut resolution or execution"}};
            if (!pager.add(std::move(row))) return false;
        }
        if (!FindNextFileW(handle.get(), &found)) {
            const auto error = GetLastError(); complete = error == ERROR_NO_MORE_FILES;
            if (!complete) { ++pager.failures; pager.add({{"entry_kind", "startup_folder_error"}, {"query", failure("FindNextFileW", error, "Win32")}}); }
            break;
        }
    }
    pager.add({{"entry_kind", "startup_folder_scan"}, {"folder_scope", scope}, {"path", text(directory.data(), directory.size())}, {"enumeration_complete", complete}});
    return complete;
}
}
Json startup(Pager& pager) {
    constexpr const char* scope = "Run/RunOnce/Policies Explorer Run in HKLM/current caller and loaded HKU SID hives, explicit 32/64 views; selected HKLM Winlogon/AppInit values; current-caller/common startup directory metadata; unloaded users, Active Setup/COM/IFEO/other mechanisms unobserved; no expansion/resolution/execution";
    bool complete = true;
    for (const auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        for (const auto* path : autorun_keys) {
            if (!pager.active()) { complete = false; break; }
            complete = registry(pager, HKEY_LOCAL_MACHINE, "HKLM", path, view) && complete;
            if (pager.active()) complete = registry(pager, HKEY_CURRENT_USER, "HKCU/caller", path, view) && complete;
        }
        constexpr const wchar_t* winlogon[]{L"Shell", L"Userinit", L"AppSetup", L"TaskMan"};
        constexpr const wchar_t* appinit[]{L"AppInit_DLLs", L"LoadAppInit_DLLs", L"RequireSignedAppInit_DLLs"};
        if (pager.active()) complete = registry(pager, HKEY_LOCAL_MACHINE, "HKLM", L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", view, winlogon) && complete;
        if (pager.active()) complete = registry(pager, HKEY_LOCAL_MACHINE, "HKLM", L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", view, appinit) && complete;
    }
    std::array<wchar_t, 256> name{}; DWORD index = 0;
    for (; index < 1024 && pager.active(); ++index) {
        DWORD units = static_cast<DWORD>(name.size());
        const auto status = RegEnumKeyExW(HKEY_USERS, index, name.data(), &units, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS || units >= name.size()) {
            ++pager.failures; complete = false; pager.add({{"entry_kind", "loaded_user_hive_error"}, {"query", failure("HKU/RegEnumKeyExW", status, "Win32")}}); break;
        }
        PSID sid = nullptr;
        if (!ConvertStringSidToSidW(name.data(), &sid)) continue;
        LocalFree(sid);
        const std::wstring hive_path(name.data(), units);
        for (const auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) for (const auto* path : autorun_keys) {
            if (!pager.active()) { complete = false; break; }
            complete = registry(pager, HKEY_USERS, "HKU/loaded SID hive", hive_path + L"\\" + path, view) && complete;
        }
    }
    if (index == 1024) complete = false;
    pager.partitions.push_back({{"source", "loaded_HKU"}, {"enumerated_indices", std::to_string(index)}, {"index_limit", "1024"}});
    if (pager.active()) complete = startup_folder(pager, FOLDERID_Startup, "current_caller") && complete;
    if (pager.active()) complete = startup_folder(pager, FOLDERID_CommonStartup, "common") && complete;
    return pager.finish(scope, complete);
}
}
