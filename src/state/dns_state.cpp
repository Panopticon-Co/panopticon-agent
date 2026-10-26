#include "panopticon/officer/state/dns_state.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
constexpr std::size_t max_registry_value_bytes = 64 * 1024;
constexpr std::size_t max_registry_name_chars = 1024;
constexpr std::size_t max_native_adapter_nodes = 4096;
constexpr std::size_t max_doh_properties = 4096;

std::string utf8(const wchar_t* value, std::size_t byte_limit, bool& refused) {
    refused = false;
    if (!value) return {};
    std::size_t length = 0;
    while (length <= byte_limit / sizeof(wchar_t) && value[length] != L'\0') ++length;
    if (length > byte_limit / sizeof(wchar_t)) { refused = true; return {}; }
    if (length == 0) return {};
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (needed <= 0 || static_cast<std::size_t>(needed) > byte_limit) { refused = true; return {}; }
    std::string result(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length),
        result.data(), needed, nullptr, nullptr) != needed) { refused = true; return {}; }
    return result;
}

Json text_field(const wchar_t* value, std::size_t byte_limit, const char* api) {
    if (!value) return {{"state", "not_present"}, {"value", nullptr}, {"source", api}, {"reason", "null_native_field"}};
    bool refused = false;
    auto converted = utf8(value, byte_limit, refused);
    if (refused) return {{"state", "degraded"}, {"value", nullptr}, {"source", api}, {"bound_exceeded", true}};
    return {{"state", "healthy"}, {"value", std::move(converted)}, {"source", api}};
}

std::string sockaddr_text(const SOCKADDR* address, int length, bool& valid) {
    valid = false;
    if (!address || length <= 0 || (address->sa_family != AF_INET && address->sa_family != AF_INET6)) return {};
    std::array<wchar_t, 128> buffer{};
    const void* source = nullptr;
    if (address->sa_family == AF_INET && length >= sizeof(SOCKADDR_IN))
        source = &reinterpret_cast<const SOCKADDR_IN*>(address)->sin_addr;
    else if (address->sa_family == AF_INET6 && length >= sizeof(SOCKADDR_IN6))
        source = &reinterpret_cast<const SOCKADDR_IN6*>(address)->sin6_addr;
    if (!source || !InetNtopW(address->sa_family, const_cast<void*>(source), buffer.data(), static_cast<DWORD>(buffer.size()))) return {};
    if (address->sa_family == AF_INET6) {
        const auto scope = reinterpret_cast<const SOCKADDR_IN6*>(address)->sin6_scope_id;
        if (scope) {
            const auto length_now = wcslen(buffer.data());
            if (length_now + 1 >= buffer.size()) return {};
            buffer[length_now] = L'%';
            _ultow_s(scope, buffer.data() + length_now + 1, buffer.size() - length_now - 1, 10);
        }
    }
    bool refused = false;
    auto result = utf8(buffer.data(), 512, refused);
    valid = !refused;
    return result;
}

struct PageWriter {
    const std::function<bool(Json)>& consumer;
    const std::function<bool()>& cancelled;
    DnsStateLimits limits;
    std::uint64_t started = GetTickCount64();
    Json entries = Json::array();
    std::size_t encoded = 2, pages = 0, delivered = 0;
    bool consumer_refused = false, bound_exceeded = false, cancellation_seen = false, timeout = false;

    bool active() {
        if (consumer_refused || bound_exceeded || cancellation_seen || timeout) return false;
        if (cancelled && cancelled()) { cancellation_seen = true; return false; }
        if (GetTickCount64() - started > limits.soft_budget_ms) { timeout = true; return false; }
        return true;
    }
    bool flush() {
        if (entries.empty()) return true;
        if (!active() || pages >= limits.max_pages) { bound_exceeded = pages >= limits.max_pages; return false; }
        const auto count = entries.size();
        Json page{{"dns_state_version", "1.0"}, {"format", "paged_dns_state_v1"},
            {"source", "windows_dns_native_state"}, {"state", "degraded"},
            {"page_index", std::to_string(pages)}, {"entries", std::move(entries)},
            {"inventory_complete", false}, {"consistency", "non_atomic"},
            {"collection_started_uptime_ms", std::to_string(started)}};
        entries = Json::array(); encoded = 2; ++pages;
        if (!consumer(std::move(page))) { consumer_refused = true; return false; }
        delivered += count;
        return true;
    }
    bool add(Json row) {
        if (!active()) return false;
        constexpr std::size_t envelope_reserve = 1024;
        auto bytes = row.dump().size() + (entries.empty() ? 0 : 1);
        if (encoded + bytes + envelope_reserve > limits.page_bytes) {
            if (!entries.empty() && !flush()) return false;
            bytes = row.dump().size();
            if (bytes + 2 + envelope_reserve > limits.page_bytes) { bound_exceeded = true; return false; }
        } else if (entries.size() >= limits.page_entries) {
            if (!flush()) return false;
            bytes = row.dump().size();
        }
        if (bytes + encoded + envelope_reserve > limits.page_bytes) { bound_exceeded = true; return false; }
        encoded += bytes;
        entries.push_back(std::move(row));
        return true;
    }
};

Json registry_value(HKEY key, const wchar_t* name, const DnsStateLimits& limits,
    const char* source, bool& query_failed) {
    DWORD type = 0, bytes = 0;
    auto status = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (status == ERROR_FILE_NOT_FOUND) return {{"state", "not_present"}, {"value", nullptr}, {"source", source}};
    if (status != ERROR_SUCCESS) { query_failed = true; return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "Win32"}, {"error_code", std::to_string(status)}}; }
    if (bytes > max_registry_value_bytes || bytes > limits.max_field_bytes ||
        ((type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) && bytes % sizeof(wchar_t) != 0) ||
        (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ && type != REG_DWORD && type != REG_QWORD)) {
        return {{"state", "degraded"}, {"value", nullptr}, {"source", source}, {"bound_exceeded", bytes > std::min(max_registry_value_bytes, limits.max_field_bytes)}, {"reason", "unsupported_type_or_value_bound"}, {"reported_bytes", std::to_string(bytes)}, {"registry_type", std::to_string(type)}};
    }
    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
    DWORD actual = bytes;
    status = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &actual);
    if (status != ERROR_SUCCESS || actual > bytes) { query_failed = true; return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "Win32"}, {"error_code", std::to_string(status)}}; }
    if (type == REG_DWORD) {
        if (actual != sizeof(DWORD)) return {{"state", "degraded"}, {"value", nullptr}, {"source", source}, {"reason", "invalid_dword_length"}};
        DWORD value = 0; std::memcpy(&value, buffer.data(), sizeof(value));
        return {{"state", "healthy"}, {"value", std::to_string(value)}, {"source", source}, {"registry_type", "REG_DWORD"}};
    }
    if (type == REG_QWORD) {
        if (actual != sizeof(ULONGLONG)) return {{"state", "degraded"}, {"value", nullptr}, {"source", source}, {"reason", "invalid_qword_length"}};
        ULONGLONG value = 0; std::memcpy(&value, buffer.data(), sizeof(value));
        return {{"state", "healthy"}, {"value", std::to_string(value)}, {"source", source}, {"registry_type", "REG_QWORD"}};
    }
    Json values = Json::array();
    const auto units = actual / sizeof(wchar_t);
    std::size_t pos = 0;
    const bool multi = type == REG_MULTI_SZ;
    while (pos < units) {
        std::size_t end = pos;
        while (end < units && buffer[end] != L'\0') ++end;
        if (end == pos) break;
        bool refused = false;
        auto value = utf8(buffer.data() + pos, limits.max_field_bytes, refused);
        if (refused) return {{"state", "degraded"}, {"value", nullptr}, {"source", source}, {"bound_exceeded", true}};
        values.push_back(std::move(value));
        if (!multi) break;
        pos = end + 1;
        if (values.size() > 1024) return {{"state", "degraded"}, {"value", nullptr}, {"source", source}, {"bound_exceeded", true}, {"reason", "multi_string_element_limit"}};
    }
    return {{"state", "healthy"}, {"value", multi ? values : Json(values.empty() ? "" : values.front().get<std::string>())},
        {"source", source}, {"registry_type", type == REG_MULTI_SZ ? "REG_MULTI_SZ" : (type == REG_EXPAND_SZ ? "REG_EXPAND_SZ" : "REG_SZ")}};
}

void collect_global_policy(PageWriter& writer, Json& partitions, bool& source_failed) {
    struct Root { HKEY hive; const wchar_t* path; const char* name; };
    const Root roots[] = {
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "tcpip_global_parameters"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "dnsclient_policy"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DNSClient", "dnsclient_machine_configuration"}
    };
    constexpr const wchar_t* values[] = {L"Domain", L"SearchList", L"DhcpDomain", L"UseDomainNameDevolution", L"EnableMulticast", L"DoHPolicy", L"DoHTemplate"};
    for (const auto& root : roots) {
        if (!writer.active()) break;
        HKEY raw = nullptr;
        const auto open = RegOpenKeyExW(root.hive, root.path, 0, KEY_READ | KEY_WOW64_64KEY, &raw);
        if (open != ERROR_SUCCESS) {
            if (open != ERROR_FILE_NOT_FOUND) source_failed = true;
            partitions[root.name] = {{"state", open == ERROR_FILE_NOT_FOUND ? "not_present" : "unavailable"},
                {"source", "RegOpenKeyExW"}, {"error_domain", "Win32"}, {"error_code", std::to_string(open)},
                {"scope", "selected local machine registry path; absence does not prove effective setting absence"}};
            continue;
        }
        std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> key(raw, RegCloseKey);
        bool path_refused = false;
        auto path = utf8(root.path, 4096, path_refused);
        Json row{{"entry_kind", "global_dns_policy"}, {"source", "Windows Registry"}, {"registry_path", path_refused ? Json(nullptr) : Json(path)}, {"hive", "HKEY_LOCAL_MACHINE"}, {"policy_source", root.name}, {"values", Json::object()}, {"scope", "selected raw machine configuration; not a merged runtime/effective DNS policy view"}};
        bool failed = false;
        for (const auto* name : values) {
            bool field_failed = false;
            bool name_refused = false;
            const auto key_name = utf8(name, 512, name_refused);
            auto value = registry_value(key.get(), name, writer.limits, "RegQueryValueExW", field_failed);
            failed = failed || field_failed || name_refused || (value.value("state", "unavailable") != "healthy" && value.value("state", "unavailable") != "not_present");
            if (!name_refused) row["values"][key_name] = std::move(value);
        }
        row["state"] = failed ? "degraded" : "healthy";
        source_failed = source_failed || failed;
        (void)writer.add(std::move(row));
        partitions[root.name] = {{"state", failed ? "degraded" : "healthy"}, {"source", "RegOpenKeyExW/RegQueryValueExW"}, {"query_completed_uptime_ms", std::to_string(GetTickCount64())}};
    }
}

void collect_nrpt(PageWriter& writer, Json& partitions, bool& source_failed) {
    struct Root { HKEY hive; const wchar_t* path; const char* name; };
    const Root roots[] = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig", "group_policy_nrpt"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig", "local_nrpt"}
    };
    constexpr const wchar_t* values[] = {L"Name", L"GenericDNSServers", L"GenericDNSEnabled", L"ConfigOptions", L"Version", L"NameEncoding", L"DirectAccessEnabled", L"DirectAccessDnsServers", L"DirectAccessProxyType", L"DirectAccessProxyName"};
    std::size_t total = 0;
    for (const auto& root : roots) {
        if (!writer.active()) break;
        HKEY raw = nullptr;
        const auto open = RegOpenKeyExW(root.hive, root.path, 0, KEY_READ | KEY_WOW64_64KEY, &raw);
        if (open != ERROR_SUCCESS) {
            if (open != ERROR_FILE_NOT_FOUND) source_failed = true;
            partitions[root.name] = {{"state", open == ERROR_FILE_NOT_FOUND ? "not_present" : "unavailable"}, {"source", "RegOpenKeyExW"}, {"error_domain", "Win32"}, {"error_code", std::to_string(open)}, {"scope", "persisted NRPT registry representation; does not establish active policy"}};
            continue;
        }
        std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> key(raw, RegCloseKey);
        DWORD subkeys = 0;
        auto query = RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (query != ERROR_SUCCESS) {
            source_failed = true;
            partitions[root.name] = {{"state", "unavailable"}, {"source", "RegQueryInfoKeyW"}, {"error_code", std::to_string(query)}};
            continue;
        }
        bool enumeration_complete = true;
        for (DWORD index = 0; index < subkeys; ++index) {
            if (!writer.active()) { enumeration_complete = false; break; }
            if (total >= writer.limits.max_nrpt_rules) { writer.bound_exceeded = true; enumeration_complete = false; break; }
            std::vector<wchar_t> name(std::min<std::size_t>(max_registry_name_chars, 1024) + 1, L'\0');
            DWORD length = static_cast<DWORD>(name.size() - 1);
            FILETIME last_write{};
            auto status = RegEnumKeyExW(key.get(), index, name.data(), &length, nullptr, nullptr, nullptr, &last_write);
            if (status != ERROR_SUCCESS || length >= name.size()) {
                source_failed = true;
                enumeration_complete = false;
                (void)writer.add({{"entry_kind", "nrpt_rule_refusal"}, {"source", "RegEnumKeyExW"}, {"state", "unavailable"}, {"error_domain", "Win32"}, {"error_code", std::to_string(status)}, {"rule_index", std::to_string(index)}});
                continue;
            }
            HKEY child_raw = nullptr;
            status = RegOpenKeyExW(key.get(), name.data(), 0, KEY_READ | KEY_WOW64_64KEY, &child_raw);
            if (status != ERROR_SUCCESS) {
                source_failed = true;
                enumeration_complete = false;
                (void)writer.add({{"entry_kind", "nrpt_rule_refusal"}, {"source", "RegOpenKeyExW"}, {"state", "unavailable"}, {"error_domain", "Win32"}, {"error_code", std::to_string(status)}, {"rule_index", std::to_string(index)}});
                continue;
            }
            std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> child(child_raw, RegCloseKey);
            bool failed = false;
            bool path_refused = false;
            auto root_path = utf8(root.path, 4096, path_refused);
            bool rule_refused = false;
            auto rule_name = utf8(name.data(), 4096, rule_refused);
            Json row{{"entry_kind", "nrpt_rule"}, {"state", path_refused || rule_refused ? "degraded" : "healthy"}, {"source", "Windows Registry"}, {"registry_path", path_refused || rule_refused ? Json(nullptr) : Json(root_path + "\\" + rule_name)}, {"hive", "HKEY_LOCAL_MACHINE"}, {"registry_subkey_index", std::to_string(index)}, {"values", Json::object()}, {"scope", "persisted rule fields only; registry order is not policy precedence and active NRPT evaluation is not queried"}};
            for (const auto* value_name : values) {
                bool field_failed = false;
                bool name_refused = false;
                const auto value_key = utf8(value_name, 512, name_refused);
                auto value = registry_value(child.get(), value_name, writer.limits, "RegQueryValueExW", field_failed);
                failed = failed || field_failed || name_refused || (value.value("state", "unavailable") != "healthy" && value.value("state", "unavailable") != "not_present");
                if (!name_refused) row["values"][value_key] = std::move(value);
            }
            row["state"] = failed ? "degraded" : "healthy";
            source_failed = source_failed || failed;
            if (!writer.add(std::move(row))) { enumeration_complete = false; break; }
            ++total;
        }
        partitions[root.name] = {{"state", enumeration_complete ? "healthy" : "degraded"}, {"source", "RegQueryInfoKeyW/RegEnumKeyExW"},
            {"reported_subkeys", std::to_string(subkeys)}, {"rules_copied", std::to_string(total)}, {"enumeration_complete", enumeration_complete},
            {"query_completed_uptime_ms", std::to_string(GetTickCount64())}, {"scope", "persisted local machine NRPT roots only; does not include an asserted effective merged policy"}};
        source_failed = source_failed || !enumeration_complete;
    }
}

Json doh_properties(const DNS_SERVER_PROPERTY* properties, ULONG count, std::size_t bound, bool& degraded) {
    Json result = Json::array();
    if (count > max_doh_properties || (count != 0 && !properties)) {
        degraded = true;
        return {{"state", "degraded"}, {"value", nullptr}, {"reported_count", count}, {"bound_exceeded", count > max_doh_properties}, {"reason", "invalid_or_over_bound_native_property_list"}};
    }
    for (ULONG index = 0; index < count; ++index) {
        const auto& property = properties[index];
        if (property.Type != DnsServerDohProperty || property.Version != DNS_SERVER_PROPERTY_VERSION1 || !property.Property.DohSettings) {
            degraded = true;
            result.push_back({{"state", "unsupported"}, {"server_index", std::to_string(property.ServerIndex)}, {"property_type", std::to_string(property.Type)}, {"property_version", std::to_string(property.Version)}});
            continue;
        }
        bool refused = false;
        const auto& settings = *property.Property.DohSettings;
        auto templ = utf8(settings.Template, bound, refused);
        if (refused) degraded = true;
        result.push_back({{"state", refused ? "degraded" : "healthy"}, {"server_index", std::to_string(property.ServerIndex)},
            {"template", settings.Template && !refused ? Json(templ) : Json(nullptr)}, {"flags", std::to_string(settings.Flags)},
            {"enabled", (settings.Flags & DNS_DOH_SERVER_SETTINGS_ENABLE) != 0},
            {"automatic_template", (settings.Flags & DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO) != 0},
            {"fallback_to_cleartext", (settings.Flags & DNS_DOH_SERVER_SETTINGS_FALLBACK_TO_UDP) != 0},
            {"auto_upgrade", (settings.Flags & DNS_DOH_AUTO_UPGRADE_SERVER) != 0}});
    }
    return {{"state", degraded ? "degraded" : "healthy"}, {"value", std::move(result)}};
}

Json interface_dns_settings(const GUID& guid, const DnsStateLimits& limits) {
    DNS_INTERFACE_SETTINGS3 settings{};
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
    const auto status = GetInterfaceDnsSettings(guid, reinterpret_cast<DNS_INTERFACE_SETTINGS*>(&settings));
    const auto free_settings = [&]() { FreeInterfaceDnsSettings(reinterpret_cast<DNS_INTERFACE_SETTINGS*>(&settings)); };
    if (status != NO_ERROR) return {{"state", status == ERROR_NOT_SUPPORTED ? "unsupported" : "unavailable"}, {"value", nullptr}, {"source", "GetInterfaceDnsSettings(v3)"}, {"error_domain", "Win32"}, {"error_code", std::to_string(status)}, {"scope", "interface settings API unavailable or refused this interface"}};
    Json out{{"state", "healthy"}, {"source", "GetInterfaceDnsSettings(v3)"}, {"flags", std::to_string(settings.Flags)},
        {"ipv6_settings", (settings.Flags & DNS_SETTING_IPV6) != 0}, {"reported_server_property_count", std::to_string(settings.cServerProperties)},
        {"reported_profile_server_property_count", std::to_string(settings.cProfileServerProperties)},
        {"scope", "API-returned interface DNS configuration; this is not proof of current resolver selection or per-query transport"}};
    out["domain"] = text_field(settings.Domain, limits.max_field_bytes, "GetInterfaceDnsSettings");
    out["name_servers"] = text_field(settings.NameServer, limits.max_field_bytes, "GetInterfaceDnsSettings");
    out["profile_name_servers"] = text_field(settings.ProfileNameServer, limits.max_field_bytes, "GetInterfaceDnsSettings");
    out["search_list"] = text_field(settings.SearchList, limits.max_field_bytes, "GetInterfaceDnsSettings");
    out["supplemental_search_list"] = text_field(settings.SupplementalSearchList, limits.max_field_bytes, "GetInterfaceDnsSettings");
    out["registration_enabled"] = settings.RegistrationEnabled != 0;
    out["register_adapter_name"] = settings.RegisterAdapterName != 0;
    out["enable_llmnr_mdns"] = settings.EnableLLMNR != 0;
    out["query_adapter_name_as_suffix"] = settings.QueryAdapterName != 0;
    bool degraded = false;
    out["doh_server_properties"] = doh_properties(settings.ServerProperties, settings.cServerProperties, limits.max_field_bytes, degraded);
    out["profile_doh_server_properties"] = doh_properties(settings.ProfileServerProperties, settings.cProfileServerProperties, limits.max_field_bytes, degraded);
    for (const auto* name : {"domain", "name_servers", "profile_name_servers", "search_list", "supplemental_search_list"}) {
        const auto state = out[name].value("state", "unavailable");
        if (state != "healthy" && state != "not_present") degraded = true;
    }
    if (degraded) out["state"] = "degraded";
    free_settings();
    return out;
}

Json adapter_row(IP_ADAPTER_ADDRESSES* adapter, const DnsStateLimits& limits, bool& degraded) {
    std::string adapter_name;
    if (adapter->AdapterName) adapter_name.assign(adapter->AdapterName, strnlen(adapter->AdapterName, 4096));
    Json adapter_name_field;
    if (!adapter->AdapterName || adapter_name.size() >= 4096) adapter_name_field = {{"state", "degraded"}, {"value", nullptr}, {"source", "GetAdaptersAddresses.AdapterName"}, {"bound_exceeded", true}};
    else adapter_name_field = {{"state", "healthy"}, {"value", adapter_name}, {"source", "GetAdaptersAddresses.AdapterName"}};
    Json row{{"entry_kind", "dns_adapter"}, {"state", "healthy"}, {"source", "GetAdaptersAddresses"},
        {"if_index", std::to_string(adapter->IfIndex)}, {"ipv6_if_index", std::to_string(adapter->Ipv6IfIndex)},
        {"oper_status", std::to_string(adapter->OperStatus)}, {"interface_luid", std::to_string(adapter->Luid.Value)},
        {"adapter_name", std::move(adapter_name_field)},
        {"friendly_name", text_field(adapter->FriendlyName, limits.max_field_bytes, "GetAdaptersAddresses.FriendlyName")},
        {"dns_suffix", text_field(adapter->DnsSuffix, limits.max_field_bytes, "GetAdaptersAddresses.DnsSuffix")},
        {"dns_servers", Json::array()}, {"scope", "caller-visible adapter list; order and status do not establish active resolver selection"}};
    std::size_t count = 0;
    for (auto* item = adapter->FirstDnsServerAddress; item; item = item->Next) {
        if (++count > 256) { degraded = true; row["state"] = "degraded"; row["dns_server_list_bound_exceeded"] = true; break; }
        bool valid = false;
        auto value = sockaddr_text(item->Address.lpSockaddr, item->Address.iSockaddrLength, valid);
        row["dns_servers"].push_back({{"state", valid ? "healthy" : "unavailable"}, {"address", valid ? Json(value) : Json(nullptr)}, {"source", "GetAdaptersAddresses.FirstDnsServerAddress"}});
        if (!valid) { degraded = true; row["state"] = "degraded"; }
    }
    GUID interface_guid{};
    std::wstring wide_name(adapter_name.begin(), adapter_name.end());
    const auto parsed = wide_name.empty() ? E_INVALIDARG : CLSIDFromString(wide_name.data(), &interface_guid);
    if (SUCCEEDED(parsed)) row["interface_dns_settings"] = interface_dns_settings(interface_guid, limits);
    else row["interface_dns_settings"] = {{"state", "unavailable"}, {"value", nullptr}, {"source", "AdapterName GUID parse"}, {"error_domain", "HRESULT"}, {"error_code", std::to_string(static_cast<unsigned long>(parsed))}};
    if (row["interface_dns_settings"].value("state", "unavailable") != "healthy") { degraded = true; row["state"] = "degraded"; }
    return row;
}

} // namespace

Json collect_dns_state_pages(const std::function<bool(Json)>& consumer,
    const std::function<bool()>& cancelled, DnsStateLimits limits) {
    if (!consumer) throw std::invalid_argument("DNS state consumer missing");
    limits.adapter_buffer_bytes = std::clamp<std::size_t>(limits.adapter_buffer_bytes, 4096, 4 * 1024 * 1024);
    limits.max_adapters = std::clamp<std::size_t>(limits.max_adapters, 1, max_native_adapter_nodes);
    limits.max_nrpt_rules = std::clamp<std::size_t>(limits.max_nrpt_rules, 1, 8192);
    limits.max_pages = std::clamp<std::size_t>(limits.max_pages, 1, 4096);
    limits.page_entries = std::clamp<std::size_t>(limits.page_entries, 1, 256);
    limits.page_bytes = std::clamp<std::size_t>(limits.page_bytes, 4096, 512 * 1024);
    limits.max_field_bytes = std::clamp<std::size_t>(limits.max_field_bytes, 256, 64 * 1024);
    limits.soft_budget_ms = std::clamp<std::uint64_t>(limits.soft_budget_ms, 1, 120000);
    PageWriter writer{consumer, cancelled, limits};
    Json partitions = Json::object();
    bool adapter_partial = false;
    std::vector<std::byte> adapter_bytes(limits.adapter_buffer_bytes);
    ULONG adapter_size = static_cast<ULONG>(adapter_bytes.size());
    const auto adapter_started = GetTickCount64();
    const auto adapter_error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapter_bytes.data()), &adapter_size);
    std::size_t adapters_seen = 0;
    if (adapter_error != NO_ERROR) {
        adapter_partial = adapter_error != ERROR_NO_DATA;
        partitions["adapter_configuration"] = {{"state", adapter_error == ERROR_NO_DATA ? "healthy" : "unavailable"},
            {"source", "GetAdaptersAddresses"}, {"error_domain", "Win32"}, {"error_code", std::to_string(adapter_error)},
            {"required_buffer_bytes", std::to_string(adapter_size)}, {"application_buffer_bytes", limits.adapter_buffer_bytes},
            {"bound_exceeded", adapter_error == ERROR_BUFFER_OVERFLOW}, {"query_started_uptime_ms", std::to_string(adapter_started)},
            {"scope", "all-interface request in caller context; a buffer overflow refuses the complete adapter snapshot"}};
    } else {
        auto* first = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapter_bytes.data());
        auto* current = first;
        while (current && writer.active()) {
            if (++adapters_seen > limits.max_adapters) { writer.bound_exceeded = true; break; }
            const auto current_address = reinterpret_cast<std::uintptr_t>(current);
            const auto first_address = reinterpret_cast<std::uintptr_t>(first);
            const auto end_address = reinterpret_cast<std::uintptr_t>(adapter_bytes.data() + adapter_bytes.size());
            if (current_address < first_address || current_address > end_address ||
                sizeof(IP_ADAPTER_ADDRESSES) > end_address - current_address) {
                adapter_partial = true;
                (void)writer.add({{"entry_kind", "adapter_copy_refusal"}, {"state", "unavailable"}, {"source", "GetAdaptersAddresses"}, {"reason", "adapter_pointer_outside_caller_buffer"}});
                break;
            }
            bool degraded = false;
            (void)writer.add(adapter_row(current, limits, degraded));
            adapter_partial = adapter_partial || degraded;
            current = current->Next;
        }
        if (current && adapters_seen >= limits.max_adapters) writer.bound_exceeded = true;
        partitions["adapter_configuration"] = {{"state", adapter_partial || writer.bound_exceeded ? "degraded" : "healthy"},
            {"source", "GetAdaptersAddresses"}, {"reported_adapter_count", std::to_string(adapters_seen)},
            {"enumeration_complete", current == nullptr && !writer.bound_exceeded}, {"query_started_uptime_ms", std::to_string(adapter_started)},
            {"query_completed_uptime_ms", std::to_string(GetTickCount64())}, {"scope", "caller-visible all-interface snapshot; caller network compartment and API view apply"}};
    }
    bool policy_failed = false;
    collect_global_policy(writer, partitions, policy_failed);
    collect_nrpt(writer, partitions, policy_failed);
    if (writer.active()) (void)writer.add({{"entry_kind", "dns_non_observable_source"}, {"state", "unsupported"}, {"source", "documented metadata-only DNS cache interface"}, {"value", nullptr}, {"scope", "No cache names, answers, TTLs, cache entries, or cache contents are read; a documented bounded metadata-only cache inventory was not used."}});
    if (writer.active()) (void)writer.add({{"entry_kind", "dns_non_observable_source"}, {"state", "unavailable"}, {"source", "machine-wide merged DoH resolver policy"}, {"value", nullptr}, {"scope", "Per-interface DoH API values are reported where available; this capture does not establish the global automatic template catalog, effective policy merge, DoT, app-specific resolvers, proxy DNS, or the transport used by a query."}});
    if (!writer.consumer_refused && !writer.cancellation_seen && !writer.timeout && !writer.bound_exceeded) (void)writer.flush();
    const bool complete = !writer.consumer_refused && !writer.cancellation_seen && !writer.timeout && !writer.bound_exceeded && !adapter_partial && !policy_failed;
    return {{"state", complete ? "healthy" : "degraded"}, {"dns_state_version", "1.0"}, {"format", "paged_dns_state_v1"},
        {"source", "windows_dns_native_state"}, {"scope", "bounded read-only caller-visible Windows DNS configuration snapshot"},
        {"inventory_complete", false}, {"enumeration_complete", complete}, {"consistency", "non_atomic"},
        {"partitions", std::move(partitions)}, {"pages_produced", std::to_string(writer.pages)}, {"entries_delivered", std::to_string(writer.delivered)},
        {"consumer_refused", writer.consumer_refused}, {"bound_exceeded", writer.bound_exceeded}, {"cancelled", writer.cancellation_seen},
        {"soft_budget_exceeded", writer.timeout}, {"soft_budget_ms", std::to_string(limits.soft_budget_ms)},
        {"adapter_buffer_bytes", limits.adapter_buffer_bytes}, {"max_adapters", limits.max_adapters}, {"max_nrpt_rules", limits.max_nrpt_rules},
        {"page_limit", limits.max_pages}, {"page_entries_limit", limits.page_entries}, {"page_encoded_bytes_limit", limits.page_bytes},
        {"field_bytes_limit", limits.max_field_bytes}, {"native_api_allocation_bounded", false},
        {"collection_started_uptime_ms", std::to_string(writer.started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"limitations", Json::array({"not an atomic resolver-policy transaction", "does not compute the winning resolver for a name", "does not prove per-query DNS transport or process attribution", "does not enumerate DNS cache contents or metadata", "registry NRPT rows are persisted configuration and not an active merged policy result", "COM/Win32 calls and OS-internal allocations have no hard deadline guarantee"})}};
}
} // namespace panopticon::officer::state
