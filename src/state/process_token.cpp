#include "panopticon/officer/state/process_token.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <cstring>
#include <memory>
#include <vector>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
constexpr DWORD byte_limit = 64 * 1024;
struct HandleCloser { void operator()(void* value) const noexcept { if (value) CloseHandle(value); } };
struct LocalCloser { void operator()(void* value) const noexcept { if (value) LocalFree(value); } };
Json failure(const char* source, DWORD error) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", source},
        {"error_domain", "Win32"}, {"error_code", std::to_string(error)}};
}
Json refused(const char* source, const char* reason) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", source},
        {"error_domain", "validation"}, {"error_code", reason}};
}
Json observed(Json value, const char* source) {
    return {{"state", "healthy"}, {"value", std::move(value)}, {"source", source}, {"error_code", nullptr}};
}
template<class T> T fixed(std::span<const std::byte> bytes) {
    T value{}; std::memcpy(&value, bytes.data(), sizeof(value)); return value;
}
template<class Decode> Json information(HANDLE token, TOKEN_INFORMATION_CLASS kind,
    DWORD minimum, const char* source, Decode decode) {
    // Fixed classes can reject a null/zero-size probe with ERROR_BAD_LENGTH.
    // Start with the documented structure size; variable classes resize twice.
    DWORD required = minimum;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (required < minimum) return refused(source, "returned_size_below_structure");
        if (required > byte_limit) {
            auto result = refused(source, "token_information_byte_limit");
            result["error_domain"] = "collection_bound";
            result["required_bytes"] = std::to_string(required); result["byte_limit"] = byte_limit;
            return result;
        }
        std::vector<std::byte> bytes(required); DWORD returned = 0;
        if (GetTokenInformation(token, kind, bytes.data(), required, &returned)) {
            if (returned < minimum || returned > bytes.size()) return refused(source, "returned_size_outside_buffer");
            return decode(std::span<const std::byte>{bytes.data(), returned});
        }
        const DWORD query_error = GetLastError();
        if (query_error != ERROR_INSUFFICIENT_BUFFER || attempt == 2) return failure(source, query_error);
        required = returned;
    }
    return refused(source, "unreachable_query_state");
}
Json luid(LUID value) {
    const auto raw = (static_cast<std::uint64_t>(static_cast<std::uint32_t>(value.HighPart)) << 32) | value.LowPart;
    return {{"raw_uint64", std::to_string(raw)}, {"low_part", std::to_string(value.LowPart)},
        {"high_part_signed", std::to_string(value.HighPart)}};
}
}
Json detail::bounded_token_sid(std::span<const std::byte> buffer, const void* sid) {
    constexpr auto source = "GetTokenInformation/SID validation and ConvertSidToStringSidW";
    const auto base = reinterpret_cast<std::uintptr_t>(buffer.data());
    const auto address = reinterpret_cast<std::uintptr_t>(sid);
    if (!sid || address < base || address - base > buffer.size()
        || buffer.size() - (address - base) < 8 || address % alignof(DWORD) != 0)
        return refused(source, "sid_pointer_outside_buffer_or_unaligned");
    const auto offset = static_cast<std::size_t>(address - base);
    const auto revision = std::to_integer<unsigned>(buffer[offset]);
    const auto count = std::to_integer<unsigned>(buffer[offset + 1]);
    if (revision != SID_REVISION || count > SID_MAX_SUB_AUTHORITIES
        || 8 + count * sizeof(DWORD) > buffer.size() - offset)
        return refused(source, "sid_header_or_length_invalid");
    auto native_sid = const_cast<void*>(sid);
    if (!IsValidSid(native_sid)) return refused(source, "sid_native_validation_failed");
    LPWSTR encoded = nullptr;
    if (!ConvertSidToStringSidW(native_sid, &encoded)) return failure(source, GetLastError());
    if (!encoded) return refused(source, "sid_text_pointer_null");
    std::unique_ptr<void, LocalCloser> owned{encoded}; std::string text;
    // Canonical SID text contains only ASCII characters; maximum SID has 15 RIDs.
    for (std::size_t index = 0; index < 256; ++index) {
        const auto character = encoded[index];
        if (!character) return observed(text, source);
        if (character > 127) return refused(source, "sid_text_non_ascii");
        text += static_cast<char>(character);
    }
    return refused(source, "sid_text_exceeds_bound");
}
Json detail::integrity_level_name(std::uint32_t rid) {
    switch (rid) {
        case SECURITY_MANDATORY_UNTRUSTED_RID: return "untrusted";
        case SECURITY_MANDATORY_LOW_RID: return "low";
        case SECURITY_MANDATORY_MEDIUM_RID: return "medium";
        case SECURITY_MANDATORY_MEDIUM_PLUS_RID: return "medium_plus";
        case SECURITY_MANDATORY_HIGH_RID: return "high";
        case SECURITY_MANDATORY_SYSTEM_RID: return "system";
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: return "protected_process";
        default: return nullptr;
    }
}
Json detail::token_elevation_type_result(std::uint32_t raw) {
    const char* name = raw == TokenElevationTypeDefault ? "default" : raw == TokenElevationTypeFull ? "full"
        : raw == TokenElevationTypeLimited ? "limited" : nullptr;
    auto fact = observed({{"raw", std::to_string(raw)}, {"known_type", name ? Json(name) : Json(nullptr)}}, "GetTokenInformation/TokenElevationType");
    if (!name) fact["state"] = "degraded";
    return fact;
}
ProcessTokenQuery query_primary_process_token(void* held_process) {
    ProcessTokenQuery result; HANDLE raw_token = nullptr;
    if (!OpenProcessToken(held_process, TOKEN_QUERY, &raw_token)) {
        const DWORD error = GetLastError(); result.fact = failure("OpenProcessToken/TOKEN_QUERY/held process", error); return result;
    }
    std::unique_ptr<void, HandleCloser> token{raw_token}; result.opened = true;
    Json fields = Json::object();
    const auto retain = [&](const char* name, Json fact) {
        if (fact["state"] == "unavailable") ++result.failed_fields;
        else { ++result.successful_fields; if (fact["state"] == "degraded") ++result.uninterpreted_fields; }
        fields[name] = std::move(fact);
    };
    retain("user", information(token.get(), TokenUser, sizeof(TOKEN_USER), "GetTokenInformation/TokenUser", [](auto bytes) {
        const auto value = fixed<TOKEN_USER>(bytes); auto sid = detail::bounded_token_sid(bytes, value.User.Sid);
        if (sid["state"] != "healthy") return sid;
        return observed({{"sid", sid["value"]}, {"attributes", std::to_string(value.User.Attributes)}}, "GetTokenInformation/TokenUser");
    }));
    retain("integrity", information(token.get(), TokenIntegrityLevel, sizeof(TOKEN_MANDATORY_LABEL), "GetTokenInformation/TokenIntegrityLevel", [](auto bytes) {
        const auto value = fixed<TOKEN_MANDATORY_LABEL>(bytes); auto sid = detail::bounded_token_sid(bytes, value.Label.Sid);
        if (sid["state"] != "healthy") return sid;
        const SID_IDENTIFIER_AUTHORITY expected = SECURITY_MANDATORY_LABEL_AUTHORITY;
        const bool mandatory = *GetSidSubAuthorityCount(value.Label.Sid) == 1
            && std::memcmp(GetSidIdentifierAuthority(value.Label.Sid), &expected, sizeof(expected)) == 0;
        const auto rid = mandatory ? *GetSidSubAuthority(value.Label.Sid, 0) : 0;
        const auto name = mandatory ? detail::integrity_level_name(rid) : Json(nullptr);
        auto fact = observed({{"sid", sid["value"]}, {"attributes", std::to_string(value.Label.Attributes)},
            {"mandatory_label_authority", mandatory}, {"rid", mandatory ? Json(std::to_string(rid)) : Json(nullptr)},
            {"known_level", name}}, "GetTokenInformation/TokenIntegrityLevel");
        if (name.is_null()) fact["state"] = "degraded";
        return fact;
    }));
    retain("elevation", information(token.get(), TokenElevation, sizeof(TOKEN_ELEVATION), "GetTokenInformation/TokenElevation", [](auto bytes) {
        const auto value = fixed<TOKEN_ELEVATION>(bytes).TokenIsElevated;
        return observed({{"raw", std::to_string(value)}, {"is_elevated", value != 0}}, "GetTokenInformation/TokenElevation");
    }));
    retain("elevation_type", information(token.get(), TokenElevationType, sizeof(TOKEN_ELEVATION_TYPE), "GetTokenInformation/TokenElevationType", [](auto bytes) {
        static_assert(sizeof(TOKEN_ELEVATION_TYPE) == sizeof(DWORD));
        return detail::token_elevation_type_result(fixed<DWORD>(bytes));
    }));
    retain("session_id", information(token.get(), TokenSessionId, sizeof(DWORD), "GetTokenInformation/TokenSessionId", [](auto bytes) {
        return observed(std::to_string(fixed<DWORD>(bytes)), "GetTokenInformation/TokenSessionId");
    }));
    retain("statistics", information(token.get(), TokenStatistics, sizeof(TOKEN_STATISTICS), "GetTokenInformation/TokenStatistics", [](auto bytes) {
        const auto value = fixed<TOKEN_STATISTICS>(bytes);
        DWORD raw_type = 0; static_assert(sizeof(TOKEN_TYPE) == sizeof(raw_type));
        std::memcpy(&raw_type, bytes.data() + offsetof(TOKEN_STATISTICS, TokenType), sizeof(raw_type));
        return observed({{"token_id", luid(value.TokenId)}, {"authentication_id", luid(value.AuthenticationId)},
            {"modified_id", luid(value.ModifiedId)}, {"raw_token_type", std::to_string(raw_type)},
            {"group_count", std::to_string(value.GroupCount)}, {"privilege_count", std::to_string(value.PrivilegeCount)},
            {"identifier_scope", "native LUIDs require host/boot scope; no token/logon entity or cross-host association inferred"}},
            "GetTokenInformation/TokenStatistics");
    }));
    result.fact = {{"state", result.successful_fields ? "degraded" : "unavailable"}, {"fields", std::move(fields)},
        {"source", "one primary token opened from the held process with TOKEN_QUERY"},
        {"consistency", "same_token_non_atomic_fields"}, {"inventory_complete", false},
        {"scope", "selected primary token attributes; thread impersonation/effective access/groups/privilege contents and changes unverified"},
        {"successful_fields", std::to_string(result.successful_fields)}, {"failed_fields", std::to_string(result.failed_fields)},
        {"uninterpreted_fields", std::to_string(result.uninterpreted_fields)}};
    return result;
}
}
