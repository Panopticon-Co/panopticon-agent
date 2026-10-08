#include "panopticon/officer/state/identity_inventory.hpp"
#include "persistence_native.hpp"
#include <lm.h>
#include <ntsecapi.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <optional>
#include <array>

namespace panopticon::officer::state {
using namespace native_persistence;
namespace {
Json invalid(const char* reason) {
    auto result = failure("native identity buffer validation", ERROR_INVALID_DATA, "validation"); result["reason"] = reason; return result;
}
Json observed(Json value) { return {{"state", "healthy"}, {"value", std::move(value)}}; }
std::optional<std::size_t> position(std::span<const std::byte> buffer, const void* pointer, std::size_t need) {
    const auto base = reinterpret_cast<std::uintptr_t>(buffer.data()), address = reinterpret_cast<std::uintptr_t>(pointer);
    if (!pointer || address < base || address - base > buffer.size() || need > buffer.size() - (address - base)) return {};
    return static_cast<std::size_t>(address - base);
}
struct NetBuffer { BYTE* value = nullptr; ~NetBuffer() { if (value) NetApiBufferFree(value); } };
struct LsaBuffer { void* value = nullptr; ~LsaBuffer() { if (value) LsaFreeReturnBuffer(value); } };
struct WtsBuffer { void* value = nullptr; ~WtsBuffer() { if (value) WTSFreeMemory(value); } };
std::span<const std::byte> net_view(const NetBuffer& buffer, Json& error) {
    DWORD bytes = 0; const auto status = NetApiBufferSize(buffer.value, &bytes);
    if (status || bytes > 1024 * 1024) {
        error = status ? failure("NetApiBufferSize", status, "NET_API_STATUS") : invalid("native_netapi_allocation_exceeds_copy_scope");
        error["reported_native_bytes"] = std::to_string(bytes); return {};
    }
    return {reinterpret_cast<const std::byte*>(buffer.value), bytes};
}
std::optional<std::wstring> query_name(const Json& fact) {
    if (fact.value("state", "unavailable") != "healthy" || !fact.contains("value") || !fact["value"].is_string()) return {};
    const auto& raw = fact["value"].get_ref<const std::string&>();
    if (raw.empty() || raw.size() > 1024 || raw.find('\0') != std::string::npos) return {};
    const auto units = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), nullptr, 0);
    if (!units) return {};
    std::wstring name(static_cast<std::size_t>(units), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), name.data(), units) != units) return {};
    return name;
}
Json account_detail(const std::wstring& name, Pager& pager) {
    NetBuffer buffer; const auto status = NetUserGetInfo(nullptr, name.c_str(), 23, &buffer.value);
    if (status) { ++pager.failures; return failure("NetUserGetInfo/local/23", status, "NET_API_STATUS"); }
    Json error; auto bytes = net_view(buffer, error);
    if (bytes.size() < sizeof(USER_INFO_23)) { ++pager.failures; return error.is_null() ? invalid("USER_INFO_23_truncated") : error; }
    USER_INFO_23 native{}; std::memcpy(&native, bytes.data(), sizeof(native));
    Json fields{{"name", detail::identity_buffer_text(bytes, native.usri23_name, 256)},
        {"full_name", detail::identity_buffer_text(bytes, native.usri23_full_name)},
        {"comment", detail::identity_buffer_text(bytes, native.usri23_comment)},
        {"sid", detail::identity_buffer_sid(bytes, native.usri23_user_sid)}};
    for (const auto& field : fields) pager.field(field);
    return {{"state", "degraded"}, {"source", "NetUserGetInfo/local/23"}, {"fields", std::move(fields)},
        {"reported_flags", std::to_string(native.usri23_flags)},
        {"consistency", "later name lookup; association with enumerated descriptor and account lifetime unverified"}};
}
Json accounts(Pager& pager) {
    DWORD resume = 0; bool complete = false; std::size_t descriptors = 0;
    while (pager.active()) {
        const auto previous = resume; DWORD read = 0, hint = 0;
        NetBuffer buffer; const auto status = NetUserEnum(nullptr, 20, 0, &buffer.value, 65536, &read, &hint, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            ++pager.failures; pager.add({{"entry_kind", "account_enumeration_error"}, {"query", failure("NetUserEnum/local/20/filter=0", status, "NET_API_STATUS")}}); break;
        }
        Json error; const auto bytes = buffer.value ? net_view(buffer, error) : std::span<const std::byte>{};
        if (!error.is_null() || read > bytes.size() / sizeof(USER_INFO_20)) {
            ++pager.failures; pager.add({{"entry_kind", "account_enumeration_error"}, {"query", error.is_null() ? invalid("NetUserEnum_returned_count_outside_buffer") : error}}); break;
        }
        for (DWORD index = 0; index < read && pager.active(); ++index) {
            USER_INFO_20 native{}; std::memcpy(&native, bytes.data() + index * sizeof(native), sizeof(native));
            Json fields{{"name", detail::identity_buffer_text(bytes, native.usri20_name, 256)},
                {"full_name", detail::identity_buffer_text(bytes, native.usri20_full_name)}, {"comment", detail::identity_buffer_text(bytes, native.usri20_comment)}};
            for (const auto& field : fields) pager.field(field);
            Json row{{"entry_kind", "account_descriptor"}, {"state", "degraded"}, {"source", "NetUserEnum/local/20/filter=0"},
                {"fields", fields}, {"reported_flags", std::to_string(native.usri20_flags)}, {"reported_rid", std::to_string(native.usri20_user_id)},
                {"user_entity_id", nullptr}, {"process_entity_id", nullptr}, {"password_material_collected", false}};
            const auto name = query_name(fields["name"]);
            row["later_sid_query"] = name ? account_detail(*name, pager) : invalid("unusable_enumerated_name_for_later_query");
            if (!pager.add(std::move(row))) break;
            ++descriptors;
        }
        if (!pager.active()) break;
        if (status == NERR_Success) { complete = true; break; }
        if (!read || resume == previous) {
            ++pager.failures; pager.add({{"entry_kind", "account_enumeration_error"}, {"query", invalid("NetUserEnum_resume_no_progress")}}); break;
        }
    }
    auto result = pager.finish("local server account reports (domain SAM on DC); caller-visible only, not all system/enterprise identities; separate later SID lookup; no password collection or effective privileges", complete);
    if (!descriptors && !complete) result["state"] = "unavailable";
    return result;
}
bool members(Pager& pager, const std::wstring& name, const Json& descriptor_name) {
    DWORD_PTR resume = 0; bool complete = false;
    while (pager.active()) {
        const auto previous = resume; DWORD read = 0, hint = 0; NetBuffer buffer;
        const auto status = NetLocalGroupGetMembers(nullptr, name.c_str(), 2, &buffer.value, 65536, &read, &hint, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            ++pager.failures; pager.add({{"entry_kind", "group_membership_error"}, {"group_name", descriptor_name},
                {"query", failure("NetLocalGroupGetMembers/local/2", status, "NET_API_STATUS")}}); break;
        }
        Json error; const auto bytes = buffer.value ? net_view(buffer, error) : std::span<const std::byte>{};
        if (!error.is_null() || read > bytes.size() / sizeof(LOCALGROUP_MEMBERS_INFO_2)) {
            ++pager.failures; pager.add({{"entry_kind", "group_membership_error"}, {"group_name", descriptor_name},
                {"query", error.is_null() ? invalid("group_members_count_outside_buffer") : error}}); break;
        }
        for (DWORD index = 0; index < read && pager.active(); ++index) {
            LOCALGROUP_MEMBERS_INFO_2 value{}; std::memcpy(&value, bytes.data() + index * sizeof(value), sizeof(value));
            auto sid = detail::identity_buffer_sid(bytes, value.lgrmi2_sid); auto account = detail::identity_buffer_text(bytes, value.lgrmi2_domainandname);
            pager.field(sid); pager.field(account);
            if (!pager.add({{"entry_kind", "local_group_membership_report"}, {"state", "degraded"}, {"group_name", descriptor_name},
                {"member_sid", std::move(sid)}, {"reported_member_name", std::move(account)}, {"reported_sid_name_use", std::to_string(value.lgrmi2_sidusage)},
                {"group_entity_id", nullptr}, {"effective_token_privileges", nullptr}, {"consistency", "later group name lookup; group lifetime/descriptor association and transitive membership unverified"}})) break;
        }
        if (!pager.active()) break;
        if (status == NERR_Success) { complete = true; break; }
        if (!read || resume == previous) { ++pager.failures; pager.add({{"entry_kind", "group_membership_error"}, {"query", invalid("group_member_resume_no_progress")}}); break; }
    }
    pager.add({{"entry_kind", "local_group_membership_scan"}, {"group_name", descriptor_name}, {"enumeration_complete", complete}});
    return complete;
}
Json groups(Pager& pager) {
    DWORD_PTR resume = 0; bool complete = false, member_complete = true; std::size_t descriptors = 0;
    while (pager.active()) {
        const auto previous = resume; DWORD read = 0, hint = 0; NetBuffer buffer;
        const auto status = NetLocalGroupEnum(nullptr, 1, &buffer.value, 65536, &read, &hint, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            ++pager.failures; pager.add({{"entry_kind", "group_enumeration_error"}, {"query", failure("NetLocalGroupEnum/local/1", status, "NET_API_STATUS")}}); break;
        }
        Json error; const auto bytes = buffer.value ? net_view(buffer, error) : std::span<const std::byte>{};
        if (!error.is_null() || read > bytes.size() / sizeof(LOCALGROUP_INFO_1)) {
            ++pager.failures; pager.add({{"entry_kind", "group_enumeration_error"}, {"query", error.is_null() ? invalid("group_count_outside_buffer") : error}}); break;
        }
        for (DWORD index = 0; index < read && pager.active(); ++index) {
            LOCALGROUP_INFO_1 value{}; std::memcpy(&value, bytes.data() + index * sizeof(value), sizeof(value));
            auto name = detail::identity_buffer_text(bytes, value.lgrpi1_name, 256); auto comment = detail::identity_buffer_text(bytes, value.lgrpi1_comment);
            pager.field(name); pager.field(comment);
            if (!pager.add({{"entry_kind", "local_group_descriptor"}, {"state", "degraded"}, {"name", name}, {"comment", comment}, {"group_entity_id", nullptr}})) break;
            ++descriptors;
            const auto query = query_name(name);
            if (query) member_complete = members(pager, *query, name) && member_complete;
            else { member_complete = false; ++pager.failures; }
        }
        if (!pager.active()) break;
        if (status == NERR_Success) { complete = true; break; }
        if (!read || resume == previous) { ++pager.failures; pager.add({{"entry_kind", "group_enumeration_error"}, {"query", invalid("group_resume_no_progress")}}); break; }
    }
    pager.partitions.push_back({{"source", "local_group_members"}, {"enumeration_complete", member_complete && complete}});
    auto result = pager.finish("local caller-visible aliases and later direct-member reports; no global/domain group census, effective/transitive token rights or verified group lifetimes", complete && member_complete);
    if (!descriptors && !complete) result["state"] = "unavailable";
    return result;
}
Json logons(Pager& pager) {
    ULONG count = 0; LsaBuffer identifiers;
    const auto status = LsaEnumerateLogonSessions(&count, reinterpret_cast<PLUID*>(&identifiers.value));
    if (status || (count && !identifiers.value) || count > 65536) {
        ++pager.failures; pager.add({{"entry_kind", "logon_enumeration_error"}, {"query", status ? failure("LsaEnumerateLogonSessions", static_cast<std::uint32_t>(status), "NTSTATUS") : invalid("LSA_count_or_null_output")}, {"reported_count", std::to_string(count)}});
        auto result = pager.finish("local caller-visible LSA logon reports", false); result["state"] = "unavailable"; return result;
    }
    const auto* luids = static_cast<const LUID*>(identifiers.value); ULONG read = 0;
    for (; read < count && pager.active(); ++read) {
        const auto requested = luids[read]; const auto luid = (static_cast<std::uint64_t>(static_cast<std::uint32_t>(requested.HighPart)) << 32) | requested.LowPart;
        Json row{{"entry_kind", "lsa_logon_session_report"}, {"state", "degraded"}, {"requested_logon_luid", std::to_string(luid)},
            {"logon_entity_id", nullptr}, {"process_entity_id", nullptr}, {"fields", Json::object()}};
        {
            LsaBuffer data; auto copy = requested;
            const auto query = LsaGetLogonSessionData(&copy, reinterpret_cast<PSECURITY_LOGON_SESSION_DATA*>(&data.value));
            if (query || !data.value) {
                ++pager.failures; row["query"] = query ? failure("LsaGetLogonSessionData", static_cast<std::uint32_t>(query), "NTSTATUS") : invalid("LSA_success_null_data");
            } else {
                const auto* native = static_cast<const SECURITY_LOGON_SESSION_DATA*>(data.value);
                if (native->Size < offsetof(SECURITY_LOGON_SESSION_DATA, Upn) + sizeof(native->Upn)) {
                    ++pager.failures; row["query"] = invalid("LSA_base_report_size_incomplete");
                } else {
                    row["reported_logon_luid"] = std::to_string((static_cast<std::uint64_t>(static_cast<std::uint32_t>(native->LogonId.HighPart)) << 32) | native->LogonId.LowPart);
                    row["reported_logon_type"] = std::to_string(native->LogonType); row["reported_wts_session_id"] = std::to_string(native->Session);
                    row["reported_logon_time_100ns"] = std::to_string(native->LogonTime.QuadPart);
                    row["logon_time_interpretation"] = "native LARGE_INTEGER; zero/negative/sentinel unverified";
                    const auto field = [&](const char* key, const LSA_UNICODE_STRING& value) {
                        auto fact = detail::identity_counted_text(&value, pager.limits.field_bytes); pager.field(fact); row["fields"][key] = std::move(fact);
                    };
                    field("user_name", native->UserName); field("logon_domain", native->LogonDomain); field("authentication_package", native->AuthenticationPackage);
                    field("logon_server", native->LogonServer); field("dns_domain", native->DnsDomainName); field("upn", native->Upn);
                    if (native->Sid && IsValidSid(native->Sid)) {
                        const auto length = GetLengthSid(native->Sid);
                        row["fields"]["sid"] = detail::identity_buffer_sid({static_cast<const std::byte*>(native->Sid), length}, native->Sid);
                    } else row["fields"]["sid"] = invalid("LSA_null_or_invalid_SID");
                    pager.field(row["fields"]["sid"]);
                    row["native_pointer_scope"] = "LSA documented allocated object and nested pointers; total allocation extent unavailable; selected copies bounded";
                    if (row["reported_logon_luid"] != row["requested_logon_luid"]) { ++pager.failures; row["query"] = invalid("LSA_returned_LUID_mismatch"); }
                }
            }
        }
        if (!pager.add(std::move(row))) break;
    }
    pager.partitions.push_back({{"source", "LSA"}, {"reported_logon_count", std::to_string(count)}, {"descriptors_read", std::to_string(read)}});
    return pager.finish("local LSA enumerated logon LUIDs and later reports; native source identity in collection boot only; no token/process association or full session lifetime reconciliation", read == count);
}
Json terminal(Pager& pager) {
    WtsBuffer buffer; DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, reinterpret_cast<PWTS_SESSION_INFOW*>(&buffer.value), &count)) {
        ++pager.failures; pager.add({{"entry_kind", "wts_enumeration_error"}, {"query", failure("WTSEnumerateSessionsW/local", GetLastError(), "Win32")}});
        auto result = pager.finish("local caller-visible WTS reports", false); result["state"] = "unavailable"; return result;
    }
    if (count > 65536 || (count && !buffer.value)) {
        ++pager.failures; pager.add({{"entry_kind", "wts_enumeration_error"}, {"query", invalid("WTS_count_or_null_output")}}); return pager.finish("local WTS reports", false);
    }
    const auto* values = static_cast<const WTS_SESSION_INFOW*>(buffer.value); DWORD read = 0;
    for (; read < count && pager.active(); ++read) {
        const auto value = values[read];
        Json row{{"entry_kind", "wts_session_descriptor"}, {"state", "degraded"}, {"reported_session_id", std::to_string(value.SessionId)},
            {"reported_connect_state", std::to_string(value.State)}, {"session_entity_id", nullptr}, {"process_entity_id", nullptr},
            {"fields", Json::object()}, {"consistency", "later queries by reusable numeric session ID; association/lifetime unverified"}};
        for (const auto cls : {WTSUserName, WTSDomainName, WTSClientName, WTSWinStationName, WTSClientProtocolType, WTSClientAddress}) {
            WtsBuffer output; DWORD bytes = 0;
            Json fact;
            if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, value.SessionId, cls, reinterpret_cast<LPWSTR*>(&output.value), &bytes))
                fact = failure("WTSQuerySessionInformationW/local", GetLastError(), "Win32");
            else if (bytes > pager.limits.field_bytes || (bytes && !output.value)) {
                fact = invalid("WTS_field_copy_bound_or_null_output"); fact["reported_bytes"] = std::to_string(bytes); fact["bound_exceeded"] = bytes > pager.limits.field_bytes;
            } else fact = detail::identity_wts_field(cls, {static_cast<const std::byte*>(output.value), bytes});
            fact["information_class"] = std::to_string(cls); pager.field(fact); row["fields"][std::to_string(cls)] = std::move(fact);
        }
        if (!pager.add(std::move(row))) break;
    }
    return pager.finish("local caller-visible WTS sessions and selected later identity/client/protocol reports; raw client address bytes unverified; no unique session lifetime, logon/process relationship or complete remote-access coverage", read == count);
}
}
Json detail::identity_buffer_text(std::span<const std::byte> buffer, const void* pointer, std::size_t limit) {
    const auto start = position(buffer, pointer, sizeof(wchar_t));
    if (!start || reinterpret_cast<std::uintptr_t>(pointer) % alignof(wchar_t)) return invalid("text_pointer_outside_buffer_or_unaligned");
    std::wstring value;
    for (std::size_t at = *start; at + sizeof(wchar_t) <= buffer.size(); at += sizeof(wchar_t)) {
        wchar_t unit = 0; std::memcpy(&unit, buffer.data() + at, sizeof(unit));
        if (!unit) { auto output = text(value.data(), value.size()); return {{"state", output.is_string() ? "healthy" : "degraded"}, {"value", std::move(output)}}; }
        if (value.size() >= limit) { auto result = invalid("text_copy_bound"); result["bound_exceeded"] = true; return result; }
        value += unit;
    }
    return invalid("native_text_not_terminated_in_buffer");
}
Json detail::identity_buffer_sid(std::span<const std::byte> buffer, const void* pointer) {
    const auto at = position(buffer, pointer, 8);
    if (!at) return invalid("SID_header_outside_buffer");
    const auto count = std::to_integer<unsigned>(buffer[*at + 1]);
    const auto length = 8 + count * sizeof(DWORD);
    if (count > SID_MAX_SUB_AUTHORITIES || !position(buffer, pointer, length)) return invalid("SID_body_outside_buffer_or_invalid_count");
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE> copy{}; std::memcpy(copy.data(), buffer.data() + *at, length);
    if (!IsValidSid(copy.data())) return invalid("invalid_native_SID");
    LPWSTR encoded = nullptr;
    if (!ConvertSidToStringSidW(copy.data(), &encoded)) return failure("ConvertSidToStringSidW", GetLastError(), "Win32");
    std::unique_ptr<wchar_t, decltype(&LocalFree)> owner(encoded, LocalFree);
    return {{"state", "healthy"}, {"value", text(encoded, std::wcslen(encoded))}, {"raw_sid_hex", hex({copy.data(), length})}};
}
Json detail::identity_counted_text(const void* borrowed, std::size_t limit) {
    if (!borrowed) return invalid("missing_LSA_unicode_descriptor");
    const auto& value = *static_cast<const LSA_UNICODE_STRING*>(borrowed);
    if (value.Length % sizeof(wchar_t) || value.Length > value.MaximumLength || (value.Length && !value.Buffer)) return invalid("invalid_LSA_unicode_lengths_or_null");
    if (value.Length > limit) { auto result = invalid("LSA_text_copy_bound"); result["bound_exceeded"] = true; return result; }
    auto decoded = text(value.Buffer, value.Length / sizeof(wchar_t));
    return {{"state", decoded.is_string() ? "healthy" : "degraded"}, {"value", std::move(decoded)}, {"byte_length", std::to_string(value.Length)}};
}
Json detail::identity_wts_field(std::uint32_t cls, std::span<const std::byte> bytes) {
    if (cls == WTSClientProtocolType) {
        if (bytes.size() != sizeof(USHORT)) return invalid("WTS_protocol_size_mismatch");
        USHORT value = 0; std::memcpy(&value, bytes.data(), sizeof(value)); return observed(std::to_string(value));
    }
    if (cls == WTSClientAddress) {
        if (bytes.size() != sizeof(WTS_CLIENT_ADDRESS)) return invalid("WTS_address_size_mismatch");
        WTS_CLIENT_ADDRESS value{}; std::memcpy(&value, bytes.data(), sizeof(value));
        return {{"state", "healthy"}, {"value", {{"reported_address_family", std::to_string(value.AddressFamily)},
            {"reported_address_hex", hex({reinterpret_cast<const std::byte*>(value.Address), sizeof(value.Address)})}, {"interpreted_ip_address", nullptr}}}};
    }
    if (cls != WTSUserName && cls != WTSDomainName && cls != WTSClientName && cls != WTSWinStationName) return invalid("unimplemented_WTS_information_class");
    if (bytes.empty()) return observed("");
    if (bytes.size() % sizeof(wchar_t)) return invalid("odd_WTS_text_length");
    return identity_buffer_text(bytes, bytes.data(), bytes.size() / sizeof(wchar_t));
}
const char* identity_source_name(IdentitySource source) {
    switch (source) {
    case IdentitySource::accounts: return "account_inventory";
    case IdentitySource::groups: return "local_group_inventory";
    case IdentitySource::logons: return "logon_session_inventory";
    case IdentitySource::terminal_sessions: return "terminal_session_inventory";
    }
    throw std::invalid_argument("unknown identity state source");
}
Json collect_identity_inventory_pages(IdentitySource source, const std::function<bool(Json)>& consumer,
    NativeInventoryLimits limits, const std::function<bool()>& cancelled) {
    if (!consumer || !limits.page_entries || limits.page_entries > 4096 || limits.encoded_bytes < 4096 || limits.encoded_bytes > 512 * 1024
        || !limits.total_entries || limits.total_entries > 65536 || !limits.pages || limits.pages > 1024 || !limits.field_bytes || limits.field_bytes > 128 * 1024
        || !limits.soft_budget_ms || limits.soft_budget_ms > 300000) throw std::invalid_argument("invalid identity inventory limits");
    Pager pager{limits, identity_source_name(source), consumer, cancelled, "identity_state_version"};
    switch (source) {
    case IdentitySource::accounts: return accounts(pager);
    case IdentitySource::groups: return groups(pager);
    case IdentitySource::logons: return logons(pager);
    case IdentitySource::terminal_sessions: return terminal(pager);
    }
    throw std::invalid_argument("unknown identity state source");
}
}
