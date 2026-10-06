#include "panopticon/officer/state/process_inventory.hpp"
#include "panopticon/officer/state/process_token.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <array>
#include <cstring>
#include <memory>
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct CloseToken { void operator()(void* value) const noexcept { if (value) CloseHandle(value); } };
void verify_primary_token(const Json& fact) {
    HANDLE raw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "owned primary token opens read-only");
    std::unique_ptr<void, CloseToken> token{raw}; DWORD returned = 0, session = 0;
    TOKEN_ELEVATION elevation{}; TOKEN_STATISTICS statistics{};
    require(GetTokenInformation(token.get(), TokenSessionId, &session, sizeof(session), &returned)
        && GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &returned)
        && GetTokenInformation(token.get(), TokenStatistics, &statistics, sizeof(statistics), &returned),
        "owned token baseline native queries succeed");
    alignas(TOKEN_USER) std::array<std::byte, 512> user_bytes{};
    require(GetTokenInformation(token.get(), TokenUser, user_bytes.data(), static_cast<DWORD>(user_bytes.size()), &returned),
        "owned token SID native query succeeds");
    TOKEN_USER user{}; std::memcpy(&user, user_bytes.data(), sizeof(user)); LPWSTR sid = nullptr;
    require(ConvertSidToStringSidW(user.User.Sid, &sid), "owned SID converts with native API");
    std::wstring sid_wide{sid}; LocalFree(sid); std::string expected_sid;
    for (const auto character : sid_wide) { require(character <= 127, "native SID text is ASCII"); expected_sid += static_cast<char>(character); }
    const auto& fields = fact["fields"];
    if (fact["successful_fields"] != "6" || fact["failed_fields"] != "0") {
        for (const auto& field : fields.items()) {
            std::cerr << field.key() << ':' << field.value()["state"] << ':' << field.value().value("error_code", Json(nullptr)) << '\n';
        }
    }
    require(fact["state"] == "degraded" && fact["inventory_complete"] == false
        && fact["successful_fields"] == "6" && fact["failed_fields"] == "0", "selected primary attributes do not invent complete token/effective access");
    require(fields["user"]["value"]["sid"] == expected_sid
        && fields["session_id"]["value"] == std::to_string(session)
        && fields["elevation"]["value"]["is_elevated"] == (elevation.TokenIsElevated != 0),
        "primary token SID/session/elevation match owned object native calls");
    const auto token_id = (static_cast<std::uint64_t>(static_cast<std::uint32_t>(statistics.TokenId.HighPart)) << 32) | statistics.TokenId.LowPart;
    require(fields["statistics"]["value"]["token_id"]["raw_uint64"] == std::to_string(token_id)
        && fields["statistics"]["value"]["group_count"] == std::to_string(statistics.GroupCount)
        && fields["statistics"]["value"]["privilege_count"] == std::to_string(statistics.PrivilegeCount),
        "native token LUID and counts remain exact without group/privilege membership inference");
    require(fields["integrity"]["value"]["mandatory_label_authority"] == true
        && fields["integrity"]["value"]["rid"].is_string(), "owned integrity derives only from mandatory label SID");
}
int main(int argc, char** argv) {
    try {
        std::string error; const auto boot = core::query_native_boot_id(error);
        const auto data = state::collect_process_inventory("host-1", boot);
        require(data["state"] == "degraded" && data["inventory_complete"] == false && data["parent_instances_verified"] == false,
            "snapshot cannot invent complete lifecycle or parent associations");
        bool self_found = false;
        std::uint64_t critical_success = 0, critical_failure = 0, protection_success = 0, protection_failure = 0, not_attempted = 0;
        std::uint64_t tokens_opened = 0, token_open_failures = 0, token_fields_success = 0, token_fields_failed = 0;
        std::uint64_t architecture_success = 0, architecture_failure = 0, architecture_unsupported = 0, architecture_unknown = 0;
        const auto full = state::collect_process_inventory_pages("host-1", boot, [&](Json page) {
        for (const auto& row : page["entries"]) {
            require(row["parent_reference"].is_null() && row["descriptor_instance_relation"].is_string(), "reported parent PID is not a verified instance");
            const auto& child_query = row["later_pid_query"];
            if (child_query.contains("reference")) {
                const auto count = [](const Json& fact, std::uint64_t& success, std::uint64_t& failure) {
                    if (fact["error_code"].is_null()) ++success;
                    else { ++failure; require(fact["value"].is_null() && fact["error_domain"] == "Win32", "native refusal remains null with exact domain/code"); }
                };
                count(child_query["critical_process"], critical_success, critical_failure);
                count(child_query["protection_level"], protection_success, protection_failure);
                const auto& architecture = child_query["architecture"];
                if (architecture["state"] == "unsupported") ++architecture_unsupported;
                else {
                    count(architecture, architecture_success, architecture_failure);
                    if (architecture["error_code"].is_null() && architecture["state"] == "degraded") ++architecture_unknown;
                }
                const auto& primary = child_query["primary_token"];
                if (primary.contains("fields")) {
                    ++tokens_opened;
                    for (const auto& field : primary["fields"].items()) {
                        if (field.value()["state"] == "unavailable") ++token_fields_failed;
                        else ++token_fields_success;
                    }
                } else {
                    ++token_open_failures;
                    require(primary["value"].is_null() && primary["error_domain"] == "Win32",
                        "token access refusal is not an absent/unprivileged user guess");
                }
            } else ++not_attempted;
            if (row["snapshot_descriptor"]["pid"] != GetCurrentProcessId()) continue;
            self_found = true; const auto& query = row["later_pid_query"];
            FILETIME born{}, exited{}, kernel{}, user{};
            require(GetProcessTimes(GetCurrentProcess(), &born, &exited, &kernel, &user), "owned self creation query succeeds");
            const auto ticks = (static_cast<std::uint64_t>(born.dwHighDateTime) << 32) | born.dwLowDateTime;
            core::ProcessInstanceStore identities{"host-1", boot};
            require(query["reference"] == identities.observe(GetCurrentProcessId(), ticks, std::nullopt, "Win32:held-process-query").json(),
                "native snapshot identity agrees with full creation token and shared canonical formula");
            require(query["times"]["value"]["creation_ticks"] == std::to_string(ticks) && query["times"]["value"]["exit_ticks"].is_null(),
                "full token retained; undefined live exit time not interpreted");
            require(query["image"]["state"] == "healthy" && query["liveness"] == "unverified", "same handle image query does not invent liveness");
            BOOL critical = FALSE; PROCESS_PROTECTION_LEVEL_INFORMATION protection{};
            require(IsProcessCritical(GetCurrentProcess(), &critical)
                && GetProcessInformation(GetCurrentProcess(), ProcessProtectionLevelInfo, &protection, sizeof(protection)),
                "owned self security queries succeed with native APIs");
            require(query["critical_process"]["value"] == (critical != FALSE)
                && query["protection_level"] == state::detail::process_protection_result(protection.ProtectionLevel),
                "snapshot security values match held owned object native queries");
            verify_primary_token(query["primary_token"]);
            USHORT process_machine = 0, native_machine = 0;
            require(IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine), "owned architecture API succeeds");
            require(query["architecture"] == state::detail::process_machine_result(process_machine, native_machine),
                "held-object architecture matches actual API codes rather than collector/image guesses");
        }
        return true;
        });
        require(self_found && full["enumeration_complete"] == true,
            "paged native enumeration includes owned test process without assuming single-prefix membership");
        const auto& summary = full["security_query_summary"];
        require(summary["architecture"]["successful_queries"] == std::to_string(architecture_success)
            && summary["architecture"]["failed_queries"] == std::to_string(architecture_failure)
            && summary["architecture"]["unsupported_queries"] == std::to_string(architecture_unsupported)
            && summary["architecture"]["uninterpreted_results"] == std::to_string(architecture_unknown),
            "architecture summary preserves success/refusal/unsupported/unknown units");
        const auto native_x64 = state::detail::process_machine_result(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_AMD64);
        const auto wow_x86 = state::detail::process_machine_result(IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64);
        const auto wow_x64_arm = state::detail::process_machine_result(IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64);
        require(native_x64["value"]["is_wow64"] == false && native_x64["value"]["process_machine"] == "0"
            && native_x64["state"] == "healthy" && wow_x86["value"]["is_wow64"] == true
            && wow_x64_arm["value"]["native_machine_symbol"] == "IMAGE_FILE_MACHINE_ARM64",
            "zero process code means not-WOW; supported emulation pairs preserve separate process/host machines");
        const auto unknown_machine = state::detail::process_machine_result(0xffffU, IMAGE_FILE_MACHINE_ARM64);
        const auto unknown_host = state::detail::process_machine_result(0, 0);
        require(unknown_machine["state"] == "degraded" && unknown_machine["value"]["process_machine"] == "65535"
            && unknown_machine["value"]["process_machine_symbol"].is_null() && unknown_host["state"] == "degraded",
            "full-width unknown machine codes survive and unknown native host is not guessed as x86");
        require(summary["primary_token"]["opened_tokens"] == std::to_string(tokens_opened)
            && summary["primary_token"]["failed_token_opens"] == std::to_string(token_open_failures)
            && summary["primary_token"]["successful_field_queries"] == std::to_string(token_fields_success)
            && summary["primary_token"]["failed_field_queries"] == std::to_string(token_fields_failed),
            "primary-token summary separates opened tokens, access refusals and individual field failures");
        const auto invalid_token = state::query_primary_process_token(nullptr);
        require(!invalid_token.opened && invalid_token.fact["state"] == "unavailable"
            && invalid_token.fact["value"].is_null() && invalid_token.fact["error_code"] == std::to_string(ERROR_INVALID_HANDLE),
            "invalid held-process handle preserves native token failure and cannot become caller token");
        alignas(DWORD) std::array<std::byte, 128> sid_bytes{};
        SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        require(InitializeSid(sid_bytes.data(), &authority, 1), "owned bounded SID fixture initializes");
        *GetSidSubAuthority(sid_bytes.data(), 0) = SECURITY_MANDATORY_HIGH_RID;
        require(state::detail::bounded_token_sid(std::span<const std::byte>{sid_bytes.data(), 12}, sid_bytes.data())["value"] == "S-1-16-12288",
            "bounded complete SID is decoded losslessly");
        for (const auto fact : {
            state::detail::bounded_token_sid(std::span<const std::byte>{sid_bytes.data(), 11}, sid_bytes.data()),
            state::detail::bounded_token_sid(sid_bytes, sid_bytes.data() + 1),
            state::detail::bounded_token_sid(sid_bytes, sid_bytes.data() + sid_bytes.size()),
            state::detail::bounded_token_sid(sid_bytes, nullptr)}) {
            require(fact["state"] == "unavailable" && fact["value"].is_null() && fact["error_domain"] == "validation",
                "truncated/outside/unaligned/null SID pointers fail before native dereference");
        }
        sid_bytes[1] = std::byte{SID_MAX_SUB_AUTHORITIES + 1};
        require(state::detail::bounded_token_sid(sid_bytes, sid_bytes.data())["state"] == "unavailable",
            "oversized SID subauthority header is refused before dereference");
        require(state::detail::integrity_level_name(0x80000000U).is_null(), "unknown integrity RID is never guessed into a known level");
        for (const auto raw : {0U, 0x80000000U, 0xffffffffU}) {
            const auto fact = state::detail::token_elevation_type_result(raw);
            require(fact["state"] == "degraded" && fact["value"]["raw"] == std::to_string(raw)
                && fact["value"]["known_type"].is_null(),
                "zero/future full-width elevation types remain raw rather than a default type guess");
        }
        require(summary["process_queries_not_attempted"] == std::to_string(not_attempted),
            "unopenable descriptors remain explicitly counted as unattempted security queries");
        if (not_attempted) require(summary["critical_process"]["state"] != "healthy"
            && summary["protection_level"]["state"] != "healthy", "partial descriptor query visibility cannot claim healthy aggregate coverage");
        require(summary["critical_process"]["successful_queries"] == std::to_string(critical_success)
            && summary["critical_process"]["failed_queries"] == std::to_string(critical_failure)
            && summary["protection_level"]["successful_queries"] == std::to_string(protection_success)
            && summary["protection_level"]["failed_queries"] == std::to_string(protection_failure),
            "security summary counts actual attempted child queries rather than unopenable descriptors");
        const auto none = state::detail::process_protection_result(PROTECTION_LEVEL_NONE);
        const auto zero = state::detail::process_protection_result(0);
        require(none["value"]["classification"] == "not_protected"
            && zero["value"]["classification"] == "documented_level"
            && zero["value"]["documented_symbol"] == "PROTECTION_LEVEL_WINTCB_LIGHT",
            "zero protection level is not confused with the full-width NONE sentinel");
        const auto unknown = state::detail::process_protection_result(0x80000000U);
        require(unknown["state"] == "degraded" && unknown["value"]["raw_protection_level"] == "2147483648"
            && unknown["value"]["documented_symbol"].is_null() && unknown["value"]["classification"] == "unknown_level",
            "future full-width protection values survive without an unprotected guess");
        const auto reserved = state::detail::process_protection_result(PROTECTION_LEVEL_AUTHENTICODE);
        require(reserved["state"] == "degraded" && reserved["value"]["classification"] == "documented_not_implemented",
            "documented unimplemented levels remain uninterpreted");
        const auto unscoped = state::collect_process_inventory("host-1", std::nullopt);
        for (const auto& row : unscoped["entries"]) {
            const auto& query = row["later_pid_query"];
            if (query.contains("reference")) require(query["reference"]["entity_id"].is_null(), "missing boot scope never becomes an exact process identity");
        }
        const auto bounded = state::collect_process_inventory("host-1", boot, {1, 512 * 1024});
        require(bounded["entries"].size() == 1 && bounded["enumeration_complete"] == false && bounded["bound_exceeded"] == true,
            "count refusal remains observable and cannot claim complete enumeration");
        const auto byte_bound = state::collect_process_inventory("host-1", boot, {2048, 2});
        require(byte_bound["entries"].empty() && byte_bound["bound_exceeded"] == true, "encoded byte bound preserves unknown remainder");
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), boot, 1};
        const auto record = factory.state("process_inventory", data);
        if (argc == 2 && std::string{argv[1]} == "--emit-paged") {
            auto records = Json::array(); auto ids = Json::array();
            const auto begin = factory.state("process_inventory_begin", {{"format", "paged_process_inventory_begin_v1"}});
            const auto capture_id = begin.at("record_id"); records.push_back(begin);
            auto summary = state::collect_process_inventory_pages("host-1", boot, [&](Json page) {
                page["capture_id"] = capture_id;
                const auto item = factory.state("process_inventory_page", std::move(page));
                ids.push_back(item.at("record_id")); records.push_back(item); return true;
            }, {64, 64 * 1024});
            summary["capture_id"] = capture_id; summary["page_record_ids"] = ids;
            records.push_back(factory.state("process_inventory", std::move(summary)));
            std::cout << records.dump() << '\n'; return 0;
        }
        std::size_t page_index = 0, delivered = 0;
        const auto paged = state::collect_process_inventory_pages("host-1", boot, [&](Json page) {
            require(page["page_index"] == std::to_string(page_index++), "pages have contiguous indices");
            require(page["entries"].size() <= 2 && page["entries"].dump().size() <= 512 * 1024, "each page is bounded");
            delivered += page["entries"].size(); return true;
        }, {2, 512 * 1024});
        require(paged["enumeration_complete"] == true && delivered > 2 && paged["entries_delivered"] == std::to_string(delivered),
            "paging continues past one-page count bound on the same native snapshot");
        const auto refused = state::collect_process_inventory_pages("host-1", boot, [](Json) { return false; }, {2, 512 * 1024});
        require(refused["consumer_refused"] == true && refused["enumeration_complete"] == false && refused["entries_delivered"] == "0",
            "refused page is not counted as accepted enumeration");
        std::size_t accepted_rows = 0;
        const auto total_bound = state::collect_process_inventory_pages("host-1", boot, [&](Json page) {
            accepted_rows += page["entries"].size(); return true;
        }, {2, 512 * 1024}, 3);
        require(accepted_rows == 3 && total_bound["entries_delivered"] == "3" && total_bound["bound_exceeded"] == true
            && total_bound["enumeration_complete"] == false, "total bound retains final partial page and reports unknown remainder");
        std::size_t accepted_pages = 0;
        const auto page_bound = state::collect_process_inventory_pages("host-1", boot, [&](Json) {
            ++accepted_pages; return true;
        }, {2, 512 * 1024}, 65536, 1);
        require(accepted_pages == 1 && page_bound["entries_delivered"] == "2" && page_bound["pages_produced"] == "1"
            && page_bound["bound_exceeded"] == true && page_bound["enumeration_complete"] == false,
            "page cap cannot invoke consumer or count undelivered rows beyond admission");
        const auto tiny_page = state::collect_process_inventory_pages("host-1", boot, [](Json) {
            throw std::runtime_error("oversized row must not produce an empty page"); return true;
        }, {2, 2});
        require(tiny_page["entries_delivered"] == "0" && tiny_page["pages_produced"] == "0"
            && tiny_page["bound_exceeded"] == true && tiny_page["enumeration_complete"] == false,
            "oversized row stops capture explicitly rather than silently skipping it");
        if (argc == 2 && std::string{argv[1]} == "--emit-live") std::cout << record.dump() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
