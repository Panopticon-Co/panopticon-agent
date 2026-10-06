#include "panopticon/officer/state/host_inventory.hpp"
#include "panopticon/officer/pipeline/source_facts.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <lmjoin.h>
#include <tbs.h>
#include <ntsecapi.h>
#include <cstdio>
#include <cstring>
#include <array>
#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <optional>
#include <memory>
#include <string>
#include <vector>

namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
class SystemModule {
public:
    explicit SystemModule(const wchar_t* name) : module_(LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {}
    ~SystemModule() { if (module_) FreeLibrary(module_); }
    SystemModule(const SystemModule&) = delete;
    SystemModule& operator=(const SystemModule&) = delete;
    HMODULE get() const noexcept { return module_; }
private:
    HMODULE module_;
};
Json observed(Json value, std::string source) {
    return {{"state", "healthy"}, {"value", std::move(value)}, {"source", std::move(source)},
        {"reason", "query succeeded for this field; not complete inventory or attestation"}, {"error_code", nullptr}};
}
Json failed(std::string source, DWORD error, std::string reason = "query failed; value unknown") {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", std::move(source)},
        {"reason", std::move(reason)}, {"error_code", std::to_string(error)}};
}
Json missing(std::string reason) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", nullptr}, {"reason", std::move(reason)}, {"error_code", nullptr}};
}
std::string audit_guid(const GUID& guid) {
    std::array<char, 39> value{};
    std::snprintf(value.data(), value.size(), "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        static_cast<unsigned long>(guid.Data1), static_cast<unsigned>(guid.Data2), static_cast<unsigned>(guid.Data3),
        static_cast<unsigned>(guid.Data4[0]), static_cast<unsigned>(guid.Data4[1]), static_cast<unsigned>(guid.Data4[2]),
        static_cast<unsigned>(guid.Data4[3]), static_cast<unsigned>(guid.Data4[4]), static_cast<unsigned>(guid.Data4[5]),
        static_cast<unsigned>(guid.Data4[6]), static_cast<unsigned>(guid.Data4[7]));
    return value.data();
}
struct AuditCloser { void operator()(void* value) const noexcept { if (value) AuditFree(value); } };
Json audit_policy() {
    constexpr ULONG limit = 256;
    GUID* raw_categories = nullptr; ULONG count = 0;
    const auto enumerated = AuditEnumerateSubCategories(nullptr, TRUE, &raw_categories, &count);
    const auto enumeration_error = enumerated ? ERROR_SUCCESS : GetLastError();
    std::unique_ptr<void, AuditCloser> categories{raw_categories};
    const auto fail = [&](const char* source, DWORD error, const char* reason) {
        auto result = failed(source, error, reason);
        result["error_domain"] = "Win32"; result["enumerated_subcategory_count"] = enumerated ? Json(std::to_string(count)) : Json(nullptr);
        result["scope"] = "system advanced audit policy; per-user/effective-token policy, options and event delivery not queried";
        return result;
    };
    if (!enumerated) return fail("AuditEnumerateSubCategories", enumeration_error, "subcategory enumeration failed; system audit policy unknown");
    if (!count || !raw_categories) return fail("AuditEnumerateSubCategories", ERROR_INVALID_DATA, "successful enumeration returned empty or missing data; policy unknown");
    if (count > limit) return fail("AuditEnumerateSubCategories", ERROR_MORE_DATA, "subcategory count exceeds bounded snapshot; policy unknown");
    for (ULONG index = 0; index < count; ++index)
        for (ULONG earlier = 0; earlier < index; ++earlier)
            if (std::memcmp(&raw_categories[index], &raw_categories[earlier], sizeof(GUID)) == 0)
                return fail("AuditEnumerateSubCategories", ERROR_INVALID_DATA, "duplicate native subcategory identity; policy unknown");
    PAUDIT_POLICY_INFORMATION raw_policy = nullptr;
    const auto queried = AuditQuerySystemPolicy(raw_categories, count, &raw_policy);
    const auto query_error = queried ? ERROR_SUCCESS : GetLastError();
    std::unique_ptr<void, AuditCloser> policy{raw_policy};
    if (!queried) return fail("AuditQuerySystemPolicy", query_error, "system audit policy query failed; privilege/access failure is not disabled auditing");
    if (!raw_policy) return fail("AuditQuerySystemPolicy", ERROR_INVALID_DATA, "successful policy query returned no data; policy unknown");
    Json rows = Json::array(); bool uncertain = false;
    for (ULONG index = 0; index < count; ++index) {
        // Validate correlation rather than assuming returned order identifies a row.
        bool requested = false;
        for (ULONG request = 0; request < count; ++request)
            requested |= std::memcmp(&raw_policy[index].AuditSubCategoryGuid, &raw_categories[request], sizeof(GUID)) == 0;
        if (!requested) return fail("AuditQuerySystemPolicy", ERROR_INVALID_DATA, "returned subcategory was not requested; policy correlation unknown");
        const auto id = audit_guid(raw_policy[index].AuditSubCategoryGuid);
        for (const auto& previous : rows)
            if (previous.at("subcategory_guid") == id)
                return fail("AuditQuerySystemPolicy", ERROR_INVALID_DATA, "duplicate returned subcategory; policy completeness unknown");
        auto flags = detail::system_audit_flags(raw_policy[index].AuditingInformation);
        uncertain |= flags.at("state") != "healthy";
        rows.push_back({{"subcategory_guid", id}, {"category_guid", audit_guid(raw_policy[index].AuditCategoryGuid)}, {"flags", std::move(flags)}});
    }
    auto result = observed({{"subcategories", std::move(rows)}, {"queried_subcategory_count", std::to_string(count)},
        {"enumerated_subcategories_complete", true}, {"subcategory_limit", limit}, {"consistency", "non_atomic"},
        {"per_user_policy_complete", false}, {"effective_token_policy_complete", false}, {"audit_options_complete", false},
        {"security_log_delivery_verified", false}}, "AuditEnumerateSubCategories/AuditQuerySystemPolicy");
    result["scope"] = "system advanced audit policy at query time; does not prove Security event delivery or per-user effective policy";
    result["enumerated_subcategory_count"] = std::to_string(count);
    result["state"] = uncertain ? "degraded" : "healthy";
    if (uncertain) result["reason"] = "native rows preserved; zero, contradictory or unknown flags have no guessed effective setting";
    return result;
}
Json wide_text(const wchar_t* input) {
    if (!input) return nullptr;
    const std::wstring_view text{input};
    if (text.empty()) return "";
    const auto size = static_cast<int>(text.size());
    const auto needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, size, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        const std::string bytes{reinterpret_cast<const char*>(input), text.size() * sizeof(wchar_t)};
        std::string hex;
        constexpr char digits[] = "0123456789abcdef";
        for (const unsigned char byte : bytes) { hex += digits[byte >> 4]; hex += digits[byte & 15]; }
        return {{"encoding", "utf16le_hex"}, {"bytes", std::move(hex)}, {"byte_length", std::to_string(bytes.size())}};
    }
    std::string result(static_cast<std::size_t>(needed), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, size, result.data(), needed, nullptr, nullptr))
        return nullptr;
    return result;
}
Json name(COMPUTER_NAME_FORMAT format) {
    DWORD size = 0;
    GetComputerNameExW(format, nullptr, &size);
    if (!size || size > 32768) return failed("GetComputerNameExW", GetLastError());
    std::vector<wchar_t> value(size + 1);
    if (!GetComputerNameExW(format, value.data(), &size)) return failed("GetComputerNameExW", GetLastError());
    return observed(wide_text(value.data()), "GetComputerNameExW");
}
Json registry_result(Json result, const wchar_t* path, const wchar_t* key) {
    result["query"] = {{"hive", "HKLM"}, {"view", "64-bit"}, {"path", wide_text(path)}, {"value_name", wide_text(key)}};
    return result;
}
Json registry_string(const wchar_t* path, const wchar_t* key) {
    DWORD size = 0;
    constexpr DWORD flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;
    auto error = RegGetValueW(HKEY_LOCAL_MACHINE, path, key, flags, nullptr, nullptr, &size);
    if (error != ERROR_SUCCESS) return registry_result(failed("RegGetValueW/64-bit", error), path, key);
    if (size > 65536) return registry_result(failed("RegGetValueW/64-bit", ERROR_MORE_DATA, "registry value exceeds inventory buffer bound"), path, key);
    std::vector<wchar_t> value(size / sizeof(wchar_t) + 2);
    error = RegGetValueW(HKEY_LOCAL_MACHINE, path, key, flags, nullptr, value.data(), &size);
    if (error != ERROR_SUCCESS) return registry_result(failed("RegGetValueW/64-bit", error), path, key);
    return registry_result(observed(wide_text(value.data()), "RegGetValueW/64-bit"), path, key);
}
Json registry_dword(const wchar_t* path, const wchar_t* key) {
    DWORD value = 0, size = sizeof(value);
    const auto error = RegGetValueW(HKEY_LOCAL_MACHINE, path, key, RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &value, &size);
    return registry_result(error == ERROR_SUCCESS ? observed(value, "RegGetValueW/64-bit") : failed("RegGetValueW/64-bit", error), path, key);
}
Json version() {
    using Query = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (!query) return failed("RtlGetVersion", ERROR_PROC_NOT_FOUND);
    OSVERSIONINFOEXW value{};
    value.dwOSVersionInfoSize = sizeof(value);
    const auto status = query(reinterpret_cast<OSVERSIONINFOW*>(&value));
    if (status != 0) return failed("RtlGetVersion/NTSTATUS", static_cast<DWORD>(status));
    return observed({{"major", value.dwMajorVersion}, {"minor", value.dwMinorVersion}, {"build", value.dwBuildNumber},
        {"service_pack_major", value.wServicePackMajor}, {"service_pack_minor", value.wServicePackMinor},
        {"product_type", value.wProductType}, {"suite_mask", value.wSuiteMask}}, "RtlGetVersion");
}
Json architecture() {
    using Query = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    if (!query) return failed("IsWow64Process2", ERROR_PROC_NOT_FOUND, "API unavailable; native architecture is not inferred from emulated process information");
    USHORT process_machine = 0, native_machine = 0;
    if (!query(GetCurrentProcess(), &process_machine, &native_machine)) return failed("IsWow64Process2", GetLastError());
    return observed({{"native_machine", native_machine}, {"agent_process_machine", process_machine},
        {"machine_encoding", "IMAGE_FILE_MACHINE"}}, "IsWow64Process2");
}
Json memory() {
    MEMORYSTATUSEX value{};
    value.dwLength = sizeof(value);
    if (!GlobalMemoryStatusEx(&value)) return failed("GlobalMemoryStatusEx", GetLastError());
    return observed({{"physical_total_bytes", std::to_string(value.ullTotalPhys)},
        {"physical_available_bytes", std::to_string(value.ullAvailPhys)}, {"load_percent", value.dwMemoryLoad}}, "GlobalMemoryStatusEx");
}
Json firmware() {
    FIRMWARE_TYPE type = FirmwareTypeUnknown;
    if (!GetFirmwareType(&type)) return failed("GetFirmwareType", GetLastError());
    return observed({{"type_value", static_cast<int>(type)}, {"type", type == FirmwareTypeUefi ? "uefi" : type == FirmwareTypeBios ? "bios" : "unknown"}}, "GetFirmwareType");
}
Json join() {
    LPWSTR value = nullptr;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    const auto error = NetGetJoinInformation(nullptr, &value, &status);
    if (error != NERR_Success) { if (value) NetApiBufferFree(value); return failed("NetGetJoinInformation", error); }
    const auto text = wide_text(value);
    if (value) NetApiBufferFree(value);
    return observed({{"name", text}, {"status_value", static_cast<int>(status)},
        {"status", status == NetSetupDomainName ? "domain" : status == NetSetupWorkgroupName ? "workgroup" : status == NetSetupUnjoined ? "unjoined" : "unknown"}}, "NetGetJoinInformation");
}
Json tpm() {
    SystemModule module{L"tbs.dll"};
    if (!module.get()) {
        const DWORD error = GetLastError();
        auto result = failed("LoadLibraryExW/System32/tbs.dll", error);
        result["error_domain"] = "WIN32";
        return result;
    }
    const auto query = reinterpret_cast<decltype(&Tbsi_GetDeviceInfo)>(GetProcAddress(module.get(), "Tbsi_GetDeviceInfo"));
    if (!query) {
        auto result = failed("Tbsi_GetDeviceInfo", ERROR_PROC_NOT_FOUND, "native TPM device query export unavailable on this deployment");
        result["state"] = "unsupported";
        result["error_domain"] = "WIN32";
        return result;
    }
    TPM_DEVICE_INFO info{};
    info.structVersion = TPM_VERSION_20;
    const auto status = query(sizeof(info), &info);
    return detail::tpm_device_result(status, info.structVersion, info.tpmVersion, info.tpmInterfaceType, info.tpmImpRevision);
}
Json entra() {
    SystemModule module{L"netapi32.dll"};
    if (!module.get()) {
        const DWORD error = GetLastError();
        auto result = failed("LoadLibraryExW/System32/netapi32.dll", error);
        result["error_domain"] = "WIN32";
        return result;
    }
    const auto query = reinterpret_cast<decltype(&NetGetAadJoinInformation)>(GetProcAddress(module.get(), "NetGetAadJoinInformation"));
    const auto release = reinterpret_cast<decltype(&NetFreeAadJoinInformation)>(GetProcAddress(module.get(), "NetFreeAadJoinInformation"));
    if (!query || !release) {
        auto result = failed("NetGetAadJoinInformation/NetFreeAadJoinInformation", ERROR_PROC_NOT_FOUND,
            "native Entra query or release export unavailable on this deployment");
        result["state"] = "unsupported";
        result["error_domain"] = "WIN32";
        return result;
    }
    struct JoinOwner {
        PDSREG_JOIN_INFO value = nullptr;
        decltype(&NetFreeAadJoinInformation) release;
        ~JoinOwner() { if (value) release(value); }
    } owner{nullptr, release};
    const auto status = query(nullptr, &owner.value);
    if (FAILED(status) || !owner.value)
        return detail::entra_join_result(static_cast<std::uint32_t>(status), false, 0, Json::object());
    Json attributes = Json::object();
    bool bounded = false;
    auto truncated = Json::array();
    const auto text = [&](const char* field, const wchar_t* value) {
        if (value && wcsnlen_s(value, 4097) > 4096) {
            attributes[field] = nullptr;
            truncated.push_back(field);
            bounded = true;
        } else attributes[field] = wide_text(value);
    };
    text("device_id", owner.value->pszDeviceId);
    text("tenant_id", owner.value->pszTenantId);
    text("identity_provider_domain", owner.value->pszIdpDomain);
    text("tenant_display_name", owner.value->pszTenantDisplayName);
    text("join_user_email", owner.value->pszJoinUserEmail);
    text("mdm_enrollment_url", owner.value->pszMdmEnrollmentUrl);
    text("mdm_terms_of_use_url", owner.value->pszMdmTermsOfUseUrl);
    text("mdm_compliance_url", owner.value->pszMdmComplianceUrl);
    text("user_setting_sync_url", owner.value->pszUserSettingSyncUrl);
    attributes["join_certificate_present"] = owner.value->pJoinCertificate != nullptr;
    attributes["user_information_present"] = owner.value->pUserInfo != nullptr;
    attributes["text_bound_exceeded_fields"] = std::move(truncated);
    return detail::entra_join_result(static_cast<std::uint32_t>(status), true,
        static_cast<std::uint32_t>(owner.value->joinType), std::move(attributes), bounded);
}
Json mount_paths(const wchar_t* volume) {
    DWORD capacity = 256;
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        if (capacity > 65536) return failed("GetVolumePathNamesForVolumeNameW", ERROR_MORE_DATA, "mount-path buffer bound exceeded; list unknown");
        std::vector<wchar_t> buffer(capacity);
        DWORD written = 0;
        if (GetVolumePathNamesForVolumeNameW(volume, buffer.data(), capacity, &written)) {
            if (written > capacity) return failed("GetVolumePathNamesForVolumeNameW", ERROR_INVALID_DATA, "returned mount-path count exceeds buffer");
            return detail::volume_mount_paths(std::span<const wchar_t>{buffer.data(), written});
        }
        const DWORD error = GetLastError();
        if (error != ERROR_MORE_DATA) return failed("GetVolumePathNamesForVolumeNameW", error);
        if (written <= capacity) return failed("GetVolumePathNamesForVolumeNameW", error, "mount-path growth made no progress; list unknown");
        capacity = written;
    }
    return failed("GetVolumePathNamesForVolumeNameW", ERROR_MORE_DATA, "mount-path growth retry bound exceeded; list unknown");
}
Json volume_information(const wchar_t* volume) {
    std::array<wchar_t, MAX_PATH + 1> label{}, filesystem{};
    DWORD serial = 0, maximum_component = 0, flags = 0;
    if (!GetVolumeInformationW(volume, label.data(), static_cast<DWORD>(label.size()), &serial, &maximum_component,
        &flags, filesystem.data(), static_cast<DWORD>(filesystem.size()))) {
        const DWORD error = GetLastError();
        return failed("GetVolumeInformationW", error);
    }
    return observed({{"label", wide_text(label.data())}, {"filesystem_name", wide_text(filesystem.data())},
        {"filesystem_flags", flags}, {"serial_number", std::to_string(serial)},
        {"maximum_component_length", maximum_component}}, "GetVolumeInformationW");
}
Json volume_space(const wchar_t* volume) {
    ULARGE_INTEGER caller_available{}, caller_total{}, volume_free{};
    if (!GetDiskFreeSpaceExW(volume, &caller_available, &caller_total, &volume_free)) {
        const DWORD error = GetLastError();
        return failed("GetDiskFreeSpaceExW", error);
    }
    return observed({{"free_bytes_available_to_caller", std::to_string(caller_available.QuadPart)},
        {"total_bytes_available_to_caller", std::to_string(caller_total.QuadPart)},
        {"total_free_bytes", std::to_string(volume_free.QuadPart)},
        {"scope", "collector account quota-aware; not physical disk length or reserved spool capacity"}}, "GetDiskFreeSpaceExW");
}
Json storage() {
    struct ThreadErrorMode {
        DWORD previous = 0;
        bool changed = false;
        ~ThreadErrorMode() { if (changed) SetThreadErrorMode(previous, nullptr); }
    } error_mode;
    if (!SetThreadErrorMode(GetThreadErrorMode() | SEM_FAILCRITICALERRORS, &error_mode.previous)) {
        const DWORD error = GetLastError();
        return failed("SetThreadErrorMode", error, "noninteractive volume query mode could not be established; storage query refused");
    }
    error_mode.changed = true;
    std::array<wchar_t, 1024> name{};
    struct VolumeSearch {
        HANDLE handle;
        ~VolumeSearch() { if (handle != INVALID_HANDLE_VALUE) FindVolumeClose(handle); }
    } search{FindFirstVolumeW(name.data(), static_cast<DWORD>(name.size()))};
    if (search.handle == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        return failed("FindFirstVolumeW", error, "volume enumeration could not start; storage unknown");
    }
    auto volumes = Json::array();
    bool enumeration_complete = false, bounded = false;
    std::optional<DWORD> enumeration_error;
    std::size_t child_failures = 0, serialized_bytes = 2;
    for (;;) {
        if (volumes.size() >= 128) { bounded = true; break; }
        Json entry{{"volume_guid_path", wide_text(name.data())}, {"mount_paths", mount_paths(name.data())},
            {"volume_information", volume_information(name.data())}, {"space", volume_space(name.data())}};
        const UINT type = GetDriveTypeW(name.data());
        entry["drive_type"] = type < DRIVE_REMOVABLE || type > DRIVE_RAMDISK
            ? missing("GetDriveTypeW did not determine a valid drive type; not a physical removable-device inventory")
            : observed({{"type_value", type}, {"type", type == DRIVE_FIXED ? "fixed" : type == DRIVE_REMOVABLE ? "removable"
                : type == DRIVE_REMOTE ? "remote" : type == DRIVE_CDROM ? "cdrom" : type == DRIVE_RAMDISK ? "ramdisk" : "unknown"}}, "GetDriveTypeW");
        entry["drive_type"]["source"] = "GetDriveTypeW";
        entry["drive_type"]["query_return_value"] = type;
        const auto bytes = entry.dump().size() + 1;
        if (bytes > 256u * 1024 - serialized_bytes) { bounded = true; break; }
        serialized_bytes += bytes;
        for (const auto* field : {"mount_paths", "volume_information", "space", "drive_type"})
            if (entry[field]["state"] != "healthy") ++child_failures;
        volumes.push_back(std::move(entry));
        if (!FindNextVolumeW(search.handle, name.data(), static_cast<DWORD>(name.size()))) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_FILES) enumeration_complete = true;
            else enumeration_error = error;
            break;
        }
    }
    auto result = observed({{"volumes", std::move(volumes)}, {"volume_enumeration_complete", enumeration_complete},
        {"physical_disks_complete", false}, {"removable_devices_complete", false}, {"encryption_state_complete", false}}, "FindFirstVolumeW/FindNextVolumeW");
    result["error_domain"] = "WIN32";
    result["enumeration_error_code"] = enumeration_error ? Json(std::to_string(*enumeration_error)) : Json(nullptr);
    result["query_failures"] = std::to_string(child_failures);
    result["query_failures_scope"] = "retained volume child fields; enumeration failure reported separately";
    result["bound_exceeded"] = bounded;
    result["limits"] = {{"volumes", 128}, {"volume_payload_bytes", 256u * 1024}, {"mount_buffer_utf16_units", 65536},
        {"mount_growth_attempts", 4}, {"mount_paths_per_volume", 256}};
    result["scope"] = "local Windows volume enumeration; non-atomic queries; volume GUID path is not verified persistent device identity";
    result["state"] = "degraded";
    result["reason"] = !enumeration_complete ? "volume enumeration incomplete; bounds or native failure; retained subset only"
        : child_failures ? "volume names enumerated; some child facts unknown; disk/encryption/removable coverage incomplete"
        : "volume queries succeeded; disk topology/encryption/removable state and change continuity incomplete";
    return result;
}
Json address(const SOCKET_ADDRESS& value) {
    std::array<wchar_t, INET6_ADDRSTRLEN> text{};
    if (!value.lpSockaddr) return nullptr;
    const auto family = value.lpSockaddr->sa_family;
    const void* bytes = nullptr;
    ULONG scope = 0;
    if (family == AF_INET && value.iSockaddrLength >= sizeof(sockaddr_in)) bytes = &reinterpret_cast<const sockaddr_in*>(value.lpSockaddr)->sin_addr;
    else if (family == AF_INET6 && value.iSockaddrLength >= sizeof(sockaddr_in6)) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(value.lpSockaddr);
        bytes = &v6->sin6_addr;
        scope = v6->sin6_scope_id;
    }
    if (!bytes || !InetNtopW(family, bytes, text.data(), static_cast<DWORD>(text.size()))) return nullptr;
    return {{"family", family == AF_INET ? "ipv4" : "ipv6"}, {"address", wide_text(text.data())}, {"scope_id", scope}};
}
Json adapters() {
    ULONG size = 15 * 1024;
    std::vector<std::byte> storage;
    ULONG error = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && error == ERROR_BUFFER_OVERFLOW; ++attempt) {
        if (size > 4u * 1024 * 1024) return failed("GetAdaptersAddresses", ERROR_MORE_DATA, "adapter buffer bound exceeded; list unknown");
        storage.resize(size);
        error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
    }
    if (error != ERROR_SUCCESS) return failed("GetAdaptersAddresses", error);
    auto values = Json::array();
    std::size_t address_count = 0;
    bool incomplete = false;
    std::size_t invalid_addresses = 0;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()); adapter; adapter = adapter->Next) {
        if (values.size() >= 512) { incomplete = true; break; }
        auto unicast = Json::array();
        auto dns = Json::array();
        for (auto* item = adapter->FirstUnicastAddress; item; item = item->Next) {
            if (++address_count > 4096) { incomplete = true; break; }
            auto socket = address(item->Address);
            if (socket.is_null()) ++invalid_addresses;
            unicast.push_back({{"socket", std::move(socket)}, {"prefix_length", item->OnLinkPrefixLength}, {"dad_state", static_cast<int>(item->DadState)}});
        }
        for (auto* item = adapter->FirstDnsServerAddress; item; item = item->Next) {
            if (++address_count > 4096) { incomplete = true; break; }
            auto socket = address(item->Address);
            if (socket.is_null()) ++invalid_addresses;
            dns.push_back(std::move(socket));
        }
        std::string mac;
        if (adapter->PhysicalAddressLength > sizeof(adapter->PhysicalAddress)) incomplete = true;
        constexpr char digits[] = "0123456789abcdef";
        for (ULONG index = 0; index < adapter->PhysicalAddressLength && index < sizeof(adapter->PhysicalAddress); ++index) {
            const auto byte = adapter->PhysicalAddress[index]; mac += digits[byte >> 4]; mac += digits[byte & 15];
        }
        values.push_back({{"adapter_name", adapter->AdapterName ? pipeline::lossless_text(adapter->AdapterName) : Json(nullptr)},
            {"friendly_name", wide_text(adapter->FriendlyName)}, {"description", wide_text(adapter->Description)},
            {"dns_suffix", wide_text(adapter->DnsSuffix)}, {"luid", std::to_string(adapter->Luid.Value)},
            {"if_index", adapter->IfIndex}, {"ipv6_if_index", adapter->Ipv6IfIndex}, {"if_type", adapter->IfType},
            {"oper_status", static_cast<int>(adapter->OperStatus)}, {"flags", adapter->Flags}, {"mtu", adapter->Mtu},
            {"mac", adapter->PhysicalAddressLength ? Json(mac) : Json(nullptr)},
            {"mac_byte_length", adapter->PhysicalAddressLength}, {"mac_truncated", adapter->PhysicalAddressLength > sizeof(adapter->PhysicalAddress)},
            {"transmit_link_speed_bps", std::to_string(adapter->TransmitLinkSpeed)},
            {"receive_link_speed_bps", std::to_string(adapter->ReceiveLinkSpeed)}, {"unicast", std::move(unicast)}, {"dns_servers", std::move(dns)}});
    }
    auto result = observed(std::move(values), "GetAdaptersAddresses/AF_UNSPEC/current compartment/all interfaces");
    result["limits"] = {{"adapters", 512}, {"addresses", 4096}, {"buffer_bytes", 4u * 1024 * 1024}};
    result["invalid_or_unsupported_addresses"] = std::to_string(invalid_addresses);
    if (incomplete || invalid_addresses) { result["state"] = "degraded"; result["reason"] = "inventory bound or address conversion failure; returned list incomplete"; }
    return result;
}
}
Json detail::system_audit_flags(std::uint32_t flags) {
    constexpr std::uint32_t known = POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE | POLICY_AUDIT_EVENT_NONE;
    const bool success = (flags & POLICY_AUDIT_EVENT_SUCCESS) != 0;
    const bool failure = (flags & POLICY_AUDIT_EVENT_FAILURE) != 0;
    const bool none = (flags & POLICY_AUDIT_EVENT_NONE) != 0;
    const bool resolved = flags != 0 && (flags & ~known) == 0 && !(none && (success || failure));
    return {{"raw_mask", std::to_string(flags)}, {"unknown_bits", std::to_string(flags & ~known)},
        {"state", resolved ? "healthy" : "degraded"},
        {"audit_success_enabled", resolved ? Json(success) : Json(nullptr)},
        {"audit_failure_enabled", resolved ? Json(failure) : Json(nullptr)},
        {"no_auditing_selected", resolved ? Json(none) : Json(nullptr)},
        {"raw_success_bit", success}, {"raw_failure_bit", failure}, {"raw_none_bit", none},
        {"scope", "system query flags only; no per-user effective policy or delivered-event guarantee"}};
}
Json detail::volume_mount_paths(std::span<const wchar_t> characters) {
    auto paths = Json::array();
    std::size_t cursor = 0;
    while (cursor < characters.size()) {
        if (characters[cursor] == L'\0') {
            if (std::any_of(characters.begin() + cursor, characters.end(), [](wchar_t c) { return c != L'\0'; }))
                return failed("GetVolumePathNamesForVolumeNameW", ERROR_INVALID_DATA, "mount-path data follows terminal null; list unknown");
            return observed(std::move(paths), "GetVolumePathNamesForVolumeNameW");
        }
        const auto end = std::find(characters.begin() + cursor, characters.end(), L'\0');
        if (end == characters.end()) break;
        if (paths.size() >= 256) return failed("GetVolumePathNamesForVolumeNameW", ERROR_MORE_DATA, "mount-path count bound exceeded; list unknown");
        paths.push_back(wide_text(characters.data() + cursor));
        cursor = static_cast<std::size_t>(end - characters.begin()) + 1;
    }
    return failed("GetVolumePathNamesForVolumeNameW", ERROR_INVALID_DATA, "mount-path list lacks complete terminal null; list unknown");
}
Json detail::tpm_device_result(std::uint32_t status, std::uint32_t structure_version,
    std::uint32_t tpm_version, std::uint32_t reserved_interface_type, std::uint32_t reserved_implementation_revision) {
    Json result;
    if (status == TBS_E_TPM_NOT_FOUND) {
        result = observed({{"compatible_device_found", false}, {"version", nullptr}}, "Tbsi_GetDeviceInfo");
        result["reason"] = "native query found no compatible TPM; not a physical-hardware absence attestation";
    } else if (status != TBS_SUCCESS) result = failed("Tbsi_GetDeviceInfo", status, "TPM query failed; device presence/version unknown");
    else {
        result = observed({{"compatible_device_found", true}, {"structure_version", structure_version},
            {"version_value", tpm_version}, {"version", tpm_version == TPM_VERSION_12 ? "1.2" : tpm_version == TPM_VERSION_20 ? "2.0" : "unknown"},
            {"raw_reserved_interface_type", reserved_interface_type},
            {"raw_reserved_implementation_revision", reserved_implementation_revision}}, "Tbsi_GetDeviceInfo");
        if (tpm_version != TPM_VERSION_12 && tpm_version != TPM_VERSION_20) {
            result["state"] = "degraded";
            result["reason"] = "native query succeeded but TPM version is unknown; raw value preserved";
        }
    }
    result["error_domain"] = "TBS_RESULT";
    result["query_status_code"] = std::to_string(status);
    result["scope"] = "compatible TPM device version only; readiness, ownership, PCRs, keys and attestation not queried";
    return result;
}
Json detail::entra_join_result(std::uint32_t status, bool information_present, std::uint32_t join_type,
    Json attributes, bool text_bound_exceeded) {
    Json result;
    if ((status & 0x80000000u) != 0)
        result = failed("NetGetAadJoinInformation/default tenant", status, "Entra join query failed; state unknown");
    else {
        const auto kind = status != static_cast<std::uint32_t>(S_OK) ? "unknown"
            : !information_present ? "none" : join_type == DSREG_DEVICE_JOIN ? "device"
            : join_type == DSREG_WORKPLACE_JOIN ? "workplace" : "unknown";
        result = observed({{"information_present", information_present}, {"join_kind", kind},
            {"join_type_value", information_present ? Json(join_type) : Json(nullptr)},
            {"attributes", information_present ? std::move(attributes) : Json::object()}}, "NetGetAadJoinInformation/default tenant");
        if (status != static_cast<std::uint32_t>(S_OK) ||
            (information_present && join_type != DSREG_DEVICE_JOIN && join_type != DSREG_WORKPLACE_JOIN) || text_bound_exceeded) {
            result["state"] = "degraded";
            result["reason"] = status != static_cast<std::uint32_t>(S_OK)
                ? "informational success status; join interpretation unqualified; raw query facts preserved"
                : text_bound_exceeded ? "returned join text exceeds bound; affected fields unknown"
                : "join information returned with unknown join type; raw value preserved";
        }
    }
    result["error_domain"] = "HRESULT";
    result["query_status_code"] = std::to_string(status);
    result["scope"] = "device join or one default work account of collector current user; not all users or all tenants";
    result["all_users_complete"] = false;
    result["all_tenants_complete"] = false;
    result["limits"] = {{"text_utf16_code_units", 4096}};
    return result;
}
Json collect_host_inventory() {
    const auto started = GetTickCount64();
    constexpr auto current_version = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    constexpr auto bios = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    Json fields{{"hostname", name(ComputerNamePhysicalDnsHostname)}, {"fqdn", name(ComputerNamePhysicalDnsFullyQualified)},
        {"os_version", version()}, {"os_product_name", registry_string(current_version, L"ProductName")},
        {"os_edition_id", registry_string(current_version, L"EditionID")}, {"os_display_version", registry_string(current_version, L"DisplayVersion")},
        {"os_update_revision", registry_dword(current_version, L"UBR")}, {"architecture", architecture()}, {"memory", memory()},
        {"firmware", firmware()}, {"manufacturer", registry_string(bios, L"SystemManufacturer")},
        {"model", registry_string(bios, L"SystemProductName")}, {"bios_vendor", registry_string(bios, L"BIOSVendor")},
        {"bios_version", registry_string(bios, L"BIOSVersion")}, {"bios_release_date", registry_string(bios, L"BIOSReleaseDate")},
        {"domain_or_workgroup", join()}, {"network_adapters", adapters()},
        {"secure_boot_registry_report", registry_dword(L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled")},
        {"tpm", tpm()}, {"entra_join", entra()},
        {"storage", storage()}, {"system_audit_policy", audit_policy()},
        {"virtualization", missing("virtualization inventory not implemented")}};
    const auto processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    fields["active_logical_processors"] = processors ? observed(processors, "GetActiveProcessorCount/all groups") : failed("GetActiveProcessorCount", GetLastError());
    fields["uptime_ms"] = observed(std::to_string(GetTickCount64()), "GetTickCount64");
    return {{"host_state_version", "1.0"}, {"snapshot_type", "full_for_implemented_fields"},
        {"consistency", "non_atomic"}, {"inventory_complete", false},
        {"collection_clock", "windows_uptime_ms"}, {"collection_started_uptime_ms", std::to_string(started)},
        {"collection_completed_uptime_ms", std::to_string(GetTickCount64())}, {"fields", std::move(fields)}};
}
}
