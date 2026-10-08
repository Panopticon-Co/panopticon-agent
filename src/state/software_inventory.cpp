#include "panopticon/officer/state/software_inventory.hpp"
#include "persistence_native.hpp"
#include <msi.h>
#include <sddl.h>
#include <array>
#include <stdexcept>

namespace panopticon::officer::state {
using namespace native_persistence;
namespace {
struct Key { HKEY value = nullptr; ~Key() { if (value) RegCloseKey(value); } };
constexpr const wchar_t* uninstall = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
Json msi_property(Pager& pager, const wchar_t* code, const wchar_t* sid,
    MSIINSTALLCONTEXT context, const wchar_t* property) {
    std::vector<wchar_t> buffer(pager.limits.field_bytes / sizeof(wchar_t) + 1);
    DWORD units = static_cast<DWORD>(buffer.size());
    const auto status = MsiGetProductInfoExW(code, context == MSIINSTALLCONTEXT_MACHINE ? nullptr : sid,
        context, property, buffer.data(), &units);
    if (status != ERROR_SUCCESS || units >= buffer.size() || buffer[units] != L'\0') {
        auto result = failure("MsiGetProductInfoExW", status, "Win32");
        result["bound_exceeded"] = status == ERROR_MORE_DATA || (status == ERROR_SUCCESS && units >= buffer.size());
        result["reported_units"] = status == ERROR_MORE_DATA || status == ERROR_SUCCESS ? Json(std::to_string(units)) : Json(nullptr);
        result["reason"] = status == ERROR_SUCCESS ? "invalid_success_output" : "native_query_failed"; return result;
    }
    auto value = text(buffer.data(), units);
    return {{"state", value.is_string() ? "healthy" : "degraded"}, {"value", std::move(value)},
        {"source", "MsiGetProductInfoExW"}};
}
Json msi(Pager& pager) {
    bool complete = true;
    // Independent contexts preserve machine inventory if another-user queries
    // are denied. Enumeration and its continuation stay on this worker thread.
    for (const auto context : {MSIINSTALLCONTEXT_MACHINE, MSIINSTALLCONTEXT_USERMANAGED, MSIINSTALLCONTEXT_USERUNMANAGED}) {
        bool ended = false; DWORD index = 0;
        while (pager.active()) {
            std::array<wchar_t, 39> code{}; std::array<wchar_t, 256> sid{};
            DWORD units = static_cast<DWORD>(sid.size()); MSIINSTALLCONTEXT actual = MSIINSTALLCONTEXT_NONE;
            const auto status = MsiEnumProductsExW(nullptr, context == MSIINSTALLCONTEXT_MACHINE ? nullptr : L"S-1-1-0",
                context, index, code.data(), &actual, sid.data(), &units);
            if (status == ERROR_NO_MORE_ITEMS) { ended = true; break; }
            if (status != ERROR_SUCCESS || units >= sid.size() || sid[units] != L'\0' || code.back() != L'\0' || actual != context) {
                auto query = failure("MsiEnumProductsExW", status, "Win32");
                query["bound_exceeded"] = status == ERROR_MORE_DATA || (status == ERROR_SUCCESS && units >= sid.size());
                query["output_validated"] = false; pager.field(query);
                pager.add({{"entry_kind", "msi_enumeration_error"}, {"requested_context", std::to_string(context)}, {"query", query}});
                break; // Never advance an index on ERROR_MORE_DATA or any failure.
            }
            Json row{{"entry_kind", "msi_product_registration"}, {"reported_product_code", text(code.data(), std::wcslen(code.data()))},
                {"reported_user_sid", text(sid.data(), units)}, {"reported_install_context", std::to_string(actual)},
                {"software_entity_id", nullptr}, {"file_entity_id", nullptr}, {"process_entity_id", nullptr},
                {"association", "later property queries; registration lifetime and installed files unverified"}, {"fields", Json::object()}};
            for (const auto* property : {L"InstalledProductName", L"VersionString", L"Publisher", L"InstallLocation", L"InstallDate", L"State", L"AssignmentType", L"Language"}) {
                if (!pager.active()) break;
                auto field = msi_property(pager, code.data(), sid.data(), actual, property); pager.field(field);
                row["fields"][text(property, std::wcslen(property)).get<std::string>()] = std::move(field);
            }
            if (!pager.add(std::move(row))) break;
            ++index;
        }
        pager.partitions.push_back({{"context", std::to_string(context)}, {"enumeration_complete", ended}, {"successful_indices", std::to_string(index)}});
        complete = complete && ended;
    }
    return pager.finish("MSI registered/advertised products: machine plus all-user managed/unmanaged contexts; permission refusals explicit; advertised-only unmanaged other-user products omitted by API; no repair, install or execution", complete);
}
bool registry_partition(Pager& pager, HKEY hive, const char* hive_name, const std::wstring& path, REGSAM view) {
    Json base{{"registry_hive", hive_name}, {"key_path", text(path.data(), path.size())},
        {"registry_view", view == KEY_WOW64_32KEY ? "32" : "64"}};
    Key root; const auto status = RegOpenKeyExW(hive, path.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | view, &root.value);
    if (status != ERROR_SUCCESS) {
        const bool absent = status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
        auto query = absent ? Json{{"state", "healthy"}, {"key_exists", false}} : failure("RegOpenKeyExW/uninstall", status, "Win32");
        pager.field(query); base["entry_kind"] = "uninstall_partition_scan"; base["query"] = query;
        pager.add(std::move(base)); return absent;
    }
    bool complete = false; DWORD index = 0;
    for (; pager.active(); ++index) {
        std::array<wchar_t, 256> name{}; DWORD units = static_cast<DWORD>(name.size()); FILETIME last_write{};
        const auto enumerated = RegEnumKeyExW(root.value, index, name.data(), &units, nullptr, nullptr, nullptr, &last_write);
        if (enumerated == ERROR_NO_MORE_ITEMS) { complete = true; break; }
        if (enumerated != ERROR_SUCCESS || units >= name.size()) {
            auto query = failure("RegEnumKeyExW/uninstall", enumerated, "Win32"); pager.field(query);
            auto row = base; row["entry_kind"] = "uninstall_enumeration_error"; row["query"] = query; pager.add(std::move(row)); break;
        }
        auto row = base; row["entry_kind"] = "uninstall_registration"; row["subkey_name"] = text(name.data(), units);
        row["reported_key_last_write_filetime"] = std::to_string((static_cast<std::uint64_t>(last_write.dwHighDateTime)<<32)|last_write.dwLowDateTime);
        row["software_entity_id"] = nullptr; row["file_entity_id"] = nullptr; row["process_entity_id"] = nullptr;
        row["installed_or_executable_verified"] = false; row["fields"] = Json::object();
        Key product; const auto opened = RegOpenKeyExW(root.value, name.data(), 0, KEY_QUERY_VALUE | view, &product.value);
        if (opened != ERROR_SUCCESS) { row["query"] = failure("RegOpenKeyExW/product", opened, "Win32"); pager.field(row["query"]); }
        else for (const auto* property : {L"DisplayName", L"DisplayVersion", L"Publisher", L"InstallLocation", L"InstallDate", L"EstimatedSize", L"WindowsInstaller", L"SystemComponent", L"ReleaseType", L"ParentKeyName"}) {
            if (!pager.active()) break;
            std::vector<std::byte> bytes(pager.limits.field_bytes); DWORD size = static_cast<DWORD>(bytes.size()), type = 0;
            const auto queried = RegQueryValueExW(product.value, property, nullptr, &type, reinterpret_cast<BYTE*>(bytes.data()), &size);
            Json field;
            if (queried == ERROR_FILE_NOT_FOUND) field = {{"state", "healthy"}, {"value_exists", false}};
            else if (queried != ERROR_SUCCESS || size > bytes.size()) {
                field = failure("RegQueryValueExW/uninstall", queried, "Win32"); field["bound_exceeded"] = queried == ERROR_MORE_DATA || (queried == ERROR_SUCCESS && size > bytes.size());
                field["reported_required_bytes"] = queried == ERROR_MORE_DATA || queried == ERROR_SUCCESS ? Json(std::to_string(size)) : Json(nullptr);
            } else field = detail::persistence_registry_data(type, {bytes.data(), size});
            pager.field(field); row["fields"][text(property, std::wcslen(property)).get<std::string>()] = std::move(field);
        }
        if (!pager.add(std::move(row))) break;
    }
    base["enumeration_complete"] = complete; base["examined_indices"] = std::to_string(index); pager.partitions.push_back(base);
    return complete;
}
Json registry(Pager& pager) {
    bool complete = true;
    for (auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        if (pager.active()) complete = registry_partition(pager, HKEY_LOCAL_MACHINE, "HKLM", uninstall, view) && complete;
        if (pager.active()) complete = registry_partition(pager, HKEY_CURRENT_USER, "HKCU/caller", uninstall, view) && complete;
    }
    // Loaded SID hives only. Never mount another user's profile or scan secrets.
    bool ended = false;
    for (DWORD index = 0; index < 1024 && pager.active(); ++index) {
        std::array<wchar_t, 256> name{}; DWORD units = static_cast<DWORD>(name.size());
        const auto status = RegEnumKeyExW(HKEY_USERS, index, name.data(), &units, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) { ended = true; break; }
        if (status != ERROR_SUCCESS || units >= name.size()) { ++pager.failures; pager.add({{"entry_kind", "loaded_hive_error"}, {"query", failure("RegEnumKeyExW/HKU", status, "Win32")}}); break; }
        PSID sid = nullptr; if (!ConvertStringSidToSidW(name.data(), &sid)) continue; LocalFree(sid);
        const auto path = std::wstring(name.data(), units) + L"\\" + uninstall;
        for (auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY})
            if (pager.active()) complete = registry_partition(pager, HKEY_USERS, "HKU/loaded_sid", path, view) && complete;
    }
    complete = complete && ended;
    return pager.finish("selected uninstall registration values in explicit HKLM/current-caller/loaded-HKU 32/64 views; duplicates retained; unloaded users, MSIX/AppX, portable apps, signers and actual installed files unobserved; non-atomic, no environment expansion or uninstall execution", complete);
}
}
const char* software_source_name(SoftwareSource source) {
    switch (source) { case SoftwareSource::msi: return "msi_product_inventory"; case SoftwareSource::uninstall_registry: return "uninstall_registry_inventory"; }
    throw std::invalid_argument("unknown software source");
}
Json collect_software_inventory_pages(SoftwareSource source, const std::function<bool(Json)>& consumer,
    NativeInventoryLimits limits, const std::function<bool()>& cancelled) {
    if (!consumer || !limits.page_entries || limits.page_entries > 4096 || limits.encoded_bytes < 4096 || limits.encoded_bytes > 512*1024 ||
        !limits.total_entries || limits.total_entries > 65536 || !limits.pages || limits.pages > 1024 || limits.field_bytes < 2 || limits.field_bytes > 128*1024 ||
        !limits.soft_budget_ms || limits.soft_budget_ms > 300000) throw std::invalid_argument("invalid software limits");
    Pager pager{limits, software_source_name(source), consumer, cancelled, "software_state_version"};
    return source == SoftwareSource::msi ? msi(pager) : registry(pager);
}
}
