#include "panopticon/officer/state/service_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <cstring>
#include <memory>
#include <vector>
#include <algorithm>

namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
constexpr const char* source = "QueryServiceObjectSecurity/OWNER|GROUP|DACL";
Json fact(Json value) { return {{"state", "healthy"}, {"value", std::move(value)}, {"source", source}, {"error_code", nullptr}}; }
Json invalid(const char* reason) { return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "validation"}, {"error_code", reason}}; }
Json failed(const char* api, DWORD error) { return {{"state", "unavailable"}, {"value", nullptr}, {"source", api}, {"error_domain", "Win32"}, {"error_code", std::to_string(error)}}; }
std::string hex(std::span<const std::byte> buffer) {
    constexpr char digits[] = "0123456789abcdef"; std::string result; result.reserve(buffer.size() * 2);
    for (const auto byte : buffer) { const auto value = std::to_integer<unsigned char>(byte); result += digits[value >> 4]; result += digits[value & 15]; }
    return result;
}
bool within(std::span<const std::byte> buffer, DWORD position, std::size_t size) {
    return position >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) && position % alignof(DWORD) == 0
        && position <= buffer.size() && size <= buffer.size() - position;
}
Json sid(std::span<const std::byte> buffer, DWORD position, std::size_t& extent) {
    if (!position) return fact(nullptr);
    if (!within(buffer, position, 8)) return invalid("sid_offset_outside_buffer_or_unaligned");
    const auto revision = std::to_integer<unsigned>(buffer[position]);
    const auto count = std::to_integer<unsigned>(buffer[position + 1]);
    if (revision != SID_REVISION || count > SID_MAX_SUB_AUTHORITIES || !within(buffer, position, 8 + count * sizeof(DWORD)))
        return invalid("sid_revision_count_or_length_invalid");
    std::uint64_t authority = 0;
    for (std::size_t index = 0; index < 6; ++index) authority = (authority << 8) | std::to_integer<unsigned>(buffer[position + 2 + index]);
    Json subs = Json::array();
    for (unsigned index = 0; index < count; ++index) { DWORD value = 0; std::memcpy(&value, buffer.data() + position + 8 + index * sizeof(DWORD), sizeof(value)); subs.push_back(std::to_string(value)); }
    const auto size = 8 + count * sizeof(DWORD); extent = (std::max)(extent, position + size);
    return fact({{"reported_revision", std::to_string(revision)}, {"reported_identifier_authority", std::to_string(authority)},
        {"sub_authorities", std::move(subs)}, {"binary_hex", hex(buffer.subspan(position, size))}, {"account_reference", nullptr}});
}
Json acl(std::span<const std::byte> buffer, DWORD position, bool present, std::size_t& extent) {
    if (!present) return position ? invalid("acl_offset_present_without_control_flag") : fact({{"representation", "not_present"}});
    if (!position) return fact({{"representation", "null_acl"}});
    if (!within(buffer, position, sizeof(ACL))) return invalid("acl_offset_outside_buffer_or_unaligned");
    ACL header{}; std::memcpy(&header, buffer.data() + position, sizeof(header));
    if (header.AclSize < sizeof(ACL) || !within(buffer, position, header.AclSize)) return invalid("acl_size_outside_buffer");
    extent = (std::max)(extent, static_cast<std::size_t>(position) + header.AclSize);
    Json value{{"representation", "acl"}, {"reported_revision", std::to_string(header.AclRevision)},
        {"reported_size", std::to_string(header.AclSize)}, {"reported_ace_count", std::to_string(header.AceCount)},
        {"binary_hex", hex(buffer.subspan(position, header.AclSize))}};
    Json entries = Json::array(); std::size_t cursor = sizeof(ACL); bool invalid_array = false;
    if (header.AceCount > 256) {
        value["aces"] = invalid("ace_detail_count_limit_exceeded"); value["ace_detail_limit"] = 256;
        auto result = fact(std::move(value)); result["state"] = "degraded"; result["bound_exceeded"] = true;
        return result;
    }
    for (WORD index = 0; index < header.AceCount; ++index) {
        if (sizeof(ACE_HEADER) > header.AclSize - cursor) { invalid_array = true; break; }
        ACE_HEADER entry{}; std::memcpy(&entry, buffer.data() + position + cursor, sizeof(entry));
        if (entry.AceSize < sizeof(ACE_HEADER) || entry.AceSize % alignof(DWORD) || entry.AceSize > header.AclSize - cursor) { invalid_array = true; break; }
        entries.push_back({{"reported_type", std::to_string(entry.AceType)}, {"reported_flags", std::to_string(entry.AceFlags)},
            {"reported_size", std::to_string(entry.AceSize)}, {"binary_hex", hex(buffer.subspan(position + cursor, entry.AceSize))},
            {"interpretation", "opaque ACE; no effective access or actor decision"}});
        cursor += entry.AceSize;
    }
    value["aces"] = invalid_array ? invalid("ace_count_or_size_outside_acl") : fact(std::move(entries));
    auto result = fact(std::move(value));
    // ACE semantics, including conditional/object/callback forms, are retained
    // as binary evidence and deliberately not passed to AccessCheck.
    result["state"] = "degraded"; result["validation_failure_count"] = invalid_array ? "1" : "0";
    return result;
}
struct Closer { void operator()(void* handle) const noexcept { if (handle) CloseServiceHandle(static_cast<SC_HANDLE>(handle)); } };
}
Json detail::service_security_descriptor(std::span<const std::byte> buffer) {
    if (buffer.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || buffer.size() > 8192) return invalid("native_buffer_size_invalid");
    SECURITY_DESCRIPTOR_RELATIVE header{}; std::memcpy(&header, buffer.data(), sizeof(header));
    Json value{{"reported_revision", std::to_string(header.Revision)}, {"reported_control", std::to_string(header.Control)},
        {"reported_owner_offset", std::to_string(header.Owner)}, {"reported_group_offset", std::to_string(header.Group)},
        {"reported_dacl_offset", std::to_string(header.Dacl)}, {"reported_sacl_offset", std::to_string(header.Sacl)},
        {"header_hex", hex(buffer.first(sizeof(header)))}};
    if (header.Revision != SECURITY_DESCRIPTOR_REVISION || !(header.Control & SE_SELF_RELATIVE)) {
        auto result = fact(std::move(value)); result["state"] = "degraded";
        result["validation_failure_count"] = "1"; result["component_status"] = invalid("descriptor_revision_or_self_relative_flag_invalid");
        result["value"]["captured_buffer_hex"] = hex(buffer);
        return result;
    }
    std::size_t extent = sizeof(header); std::uint64_t failures = 0;
    value["owner"] = sid(buffer, header.Owner, extent); value["group"] = sid(buffer, header.Group, extent);
    value["dacl"] = acl(buffer, header.Dacl, (header.Control & SE_DACL_PRESENT) != 0, extent);
    for (const auto* name : {"owner", "group", "dacl"}) {
        const auto& component = value[name];
        if (component["state"] == "unavailable") ++failures;
        if (component.contains("validation_failure_count")) failures += std::stoull(component["validation_failure_count"].get<std::string>());
    }
    value["sacl"] = {{"state", "unavailable"}, {"value", nullptr}, {"reason", "not requested; SACL/label/effective access coverage not established"}};
    // This prefix extent is derived only from bounded selected components;
    // the API does not document an output byte count on success.
    value["selected_component_prefix_hex"] = hex(buffer.first(extent));
    value["selected_component_prefix_byte_count"] = std::to_string(extent);
    auto result = fact(std::move(value)); result["state"] = "degraded";
    if (failures) result["value"]["captured_buffer_hex"] = hex(buffer);
    result["bound_exceeded"] = result["value"]["dacl"].value("bound_exceeded", false);
    result["validation_failure_count"] = std::to_string(failures);
    result["scope"] = "selected service-object owner/group/DACL binary evidence; ACE semantics/effective access/SACL/label are unqualified";
    return result;
}
Json query_service_security(void* manager, const wchar_t* name) {
    const auto started = GetTickCount64(); Json result;
    if (!manager || !name || !*name) result = invalid("manager_handle_or_service_name_invalid");
    else {
        std::unique_ptr<void, Closer> handle{OpenServiceW(static_cast<SC_HANDLE>(manager), name, READ_CONTROL)};
        if (!handle) result = failed("OpenServiceW/READ_CONTROL", GetLastError());
        else {
            std::vector<std::byte> bytes(8192); DWORD needed = 0;
            if (!QueryServiceObjectSecurity(static_cast<SC_HANDLE>(handle.get()), OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                bytes.data(), static_cast<DWORD>(bytes.size()), &needed)) {
                const auto error = GetLastError(); result = failed(source, error); result["native_query_succeeded"] = false;
                if (error == ERROR_INSUFFICIENT_BUFFER) { result["required_bytes"] = std::to_string(needed); result["bound_exceeded"] = needed > bytes.size(); }
            } else { result = detail::service_security_descriptor(bytes); result["native_query_succeeded"] = true; }
        }
    }
    result["query_started_uptime_ms"] = std::to_string(started); result["query_completed_uptime_ms"] = std::to_string(GetTickCount64());
    result["buffer_byte_limit"] = "8192"; result["requested_security_information"] = "7";
    result["object_relation"] = "separate READ_CONTROL name lookup; descriptor/configuration/security object identity association unverified";
    return result;
}
}
