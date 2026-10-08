#include "panopticon/officer/state/host_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv) {
    try {
        if (argc == 3 && (std::string{argv[1]} == "--read-spool" || std::string{argv[1]} == "--read-spool-lines" || std::string{argv[1]} == "--read-process-history-lines")) {
            const auto history = std::string{argv[1]} == "--read-process-history-lines";
            const auto lines = history || std::string{argv[1]} == "--read-spool-lines";
            const std::filesystem::path path{argv[2]};
            require(std::filesystem::is_directory(path), "read probe requires an existing owned spool");
            require(std::filesystem::is_regular_file(path / "journal.db"), "read probe must not initialize an unrelated or missing journal");
            delivery::DurableJournal journal{{path}};
            const auto stats = journal.stats();
            const auto pending = history ? stats.process_history_records : stats.pending_events;
            auto records = Json::array();
            std::uint64_t cursor = 0, recovered_count = 0; std::size_t bytes = 0;
            for (;;) {
                const auto page = history ? journal.inspect_process_history(cursor, 1000, 8u * 1024 * 1024) :
                    journal.inspect_pending(cursor, 1000, 8u * 1024 * 1024);
                if (page.empty()) break;
                for (const auto& entry : page) {
                    require(entry.local_sequence > cursor, "inspection cursor must advance");
                    cursor = entry.local_sequence; ++recovered_count;
                    if (lines) {
                        // Bounded inspect pages and one parsed row at a time;
                        // never accumulate an unbounded recovery JSON array.
                        (void)Json::parse(entry.original.body);
                        std::cout << entry.original.body << '\n';
                        require(static_cast<bool>(std::cout), "owned streaming read probe output failed");
                    } else {
                        require(records.size() < 10000 && entry.original.body.size() <= 64u * 1024 * 1024 - bytes,
                            "owned read probe aggregate limit exceeded; never present partial recovery as journal loss");
                        bytes += entry.original.body.size(); records.push_back(Json::parse(entry.original.body));
                    }
                }
            }
            require(recovered_count == pending, "owned stopped journal inspection must recover all pending records");
            if (!lines) std::cout << records.dump() << '\n';
            return 0;
        }
        const auto original_error_mode = GetThreadErrorMode();
        const auto snapshot = state::collect_host_inventory();
        require(GetThreadErrorMode() == original_error_mode, "volume query must restore caller thread error mode");
        require(snapshot["consistency"] == "non_atomic" && snapshot["inventory_complete"] == false, "partial native snapshot must not claim complete atomic state");
        const auto start = std::stoull(snapshot["collection_started_uptime_ms"].get<std::string>());
        const auto end = std::stoull(snapshot["collection_completed_uptime_ms"].get<std::string>());
        require(end >= start, "native collection window must be ordered on uptime clock");
        const std::set<std::string> states{"healthy", "degraded", "unavailable", "disabled", "unsupported", "blind"};
        for (const auto& field : snapshot["fields"]) {
            require(states.contains(field["state"].get<std::string>()), "per-field capability state is explicit");
            if (field["state"] == "unavailable") require(field["value"].is_null(), "unavailable query cannot invent an empty or false fact");
        }
        for (const auto* pending : {"virtualization"})
            require(snapshot["fields"][pending]["state"] == "unavailable", "unimplemented domains cannot be marked unsupported or healthy");
        const wchar_t multiple_paths[]{L'C', L':', L'\\', L'\0', L'C', L':', L'\\', L'm', L'n', L't', L'\\', L'\0', L'\0'};
        const auto paths = state::detail::volume_mount_paths(multiple_paths);
        require(paths["state"] == "healthy" && paths["value"] == Json::array({"C:\\", "C:\\mnt\\"}),
            "mount enumeration retains drive roots and mounted folders distinctly");
        const wchar_t empty_paths[]{L'\0'};
        require(state::detail::volume_mount_paths(empty_paths)["value"] == Json::array(),
            "successful empty mount list differs from query failure");
        const wchar_t incomplete_paths[]{L'C', L':', L'\\', L'\0'};
        require(state::detail::volume_mount_paths(incomplete_paths)["value"].is_null(),
            "missing final MULTISZ terminator must not invent a complete mount list");
        const wchar_t malformed_paths[]{L'\0', L'x'};
        require(state::detail::volume_mount_paths(malformed_paths)["state"] == "unavailable",
            "data after terminal mount null must not be silently discarded");
        std::vector<wchar_t> many_paths;
        for (unsigned index = 0; index < 257; ++index) { many_paths.push_back(L'x'); many_paths.push_back(L'\0'); }
        many_paths.push_back(L'\0');
        require(state::detail::volume_mount_paths(many_paths)["value"].is_null(),
            "mount count exhaustion reports unknown instead of presenting a complete truncated list");
        const auto& storage = snapshot["fields"]["storage"];
        if (!storage["value"].is_null()) {
            require(storage["state"] == "degraded" && storage["value"]["physical_disks_complete"] == false &&
                storage["value"]["encryption_state_complete"] == false, "volume inventory cannot claim complete disk or encryption coverage");
            require(storage["value"]["volumes"].size() <= 128 && storage["value"]["volumes"].dump().size() <= 256u * 1024,
                "retained native volume list respects count and encoded-byte bounds");
            for (const auto& volume : storage["value"]["volumes"]) {
                require(volume["volume_guid_path"].is_string(), "volume identity retains native GUID path");
                if (volume["space"]["state"] == "healthy") {
                    for (const auto* key : {"free_bytes_available_to_caller", "total_bytes_available_to_caller", "total_free_bytes"})
                        require(volume["space"]["value"][key].is_string(), "volume byte counts never narrow to numeric JSON or 32 bits");
                }
            }
        }
        for (const auto flags : {0u, 5u, 6u, 7u, 8u, 0xffffffffu}) {
            const auto unknown = state::detail::system_audit_flags(flags);
            require(unknown["state"] == "degraded" && unknown["audit_success_enabled"].is_null() &&
                unknown["raw_mask"] == std::to_string(flags), "ambiguous/unknown audit flags preserve raw bits without guessing enabled or disabled");
        }
        const auto disabled_audit = state::detail::system_audit_flags(4);
        require(disabled_audit["state"] == "healthy" && disabled_audit["no_auditing_selected"] == true &&
            disabled_audit["audit_success_enabled"] == false, "known NONE is an observed scoped setting, not query failure");
        require(state::detail::system_audit_flags(1)["audit_success_enabled"] == true &&
            state::detail::system_audit_flags(2)["audit_failure_enabled"] == true &&
            state::detail::system_audit_flags(3)["audit_failure_enabled"] == true, "known system audit bits retain success/failure selection");
        const auto& audit = snapshot["fields"]["system_audit_policy"];
        if (audit["value"].is_null()) {
            require(audit["state"] == "unavailable" && audit["error_domain"] == "Win32", "failed audit query preserves unknown state and native error domain");
        } else {
            require(audit["value"]["security_log_delivery_verified"] == false && audit["value"]["per_user_policy_complete"] == false &&
                audit["value"]["subcategories"].size() <= 256, "system audit rows cannot claim effective user policy or event-delivery coverage");
        }
        const auto tpm_absent = state::detail::tpm_device_result(0x8028400Fu);
        require(tpm_absent["state"] == "healthy" && tpm_absent["value"]["compatible_device_found"] == false &&
            tpm_absent["query_status_code"] == "2150121487", "documented TPM-not-found is an observed scoped fact");
        const auto tpm_failure = state::detail::tpm_device_result(0x80284008u);
        require(tpm_failure["state"] == "unavailable" && tpm_failure["value"].is_null() &&
            tpm_failure["error_domain"] == "TBS_RESULT", "TPM service failure must not invent absence");
        const auto tpm_known = state::detail::tpm_device_result(0, 2, 2, 7, 9);
        require(tpm_known["value"]["version"] == "2.0" && tpm_known["value"]["raw_reserved_interface_type"] == 7,
            "TPM version maps known values and preserves uninterpreted reserved fields");
        const auto tpm_unknown = state::detail::tpm_device_result(0, 2, 99);
        require(tpm_unknown["state"] == "degraded" && tpm_unknown["value"]["version_value"] == 99,
            "unknown TPM version must not become a known version or unsupported device");
        const auto no_join = state::detail::entra_join_result(0, false, 0, Json::object());
        require(no_join["state"] == "healthy" && no_join["value"]["join_kind"] == "none" &&
            no_join["all_users_complete"] == false, "successful null Entra information is scoped absence, not all-user inventory");
        const auto informational_join = state::detail::entra_join_result(1, false, 0, Json::object());
        require(informational_join["state"] == "degraded" && informational_join["value"]["join_kind"] == "unknown" &&
            informational_join["query_status_code"] == "1" && informational_join["error_code"].is_null(),
            "S_FALSE is informational success, not failed HRESULT or proven absence");
        const auto join_failure = state::detail::entra_join_result(0x80070005u, false, 0, Json::object());
        require(join_failure["state"] == "unavailable" && join_failure["value"].is_null() &&
            join_failure["error_code"] == "2147942405", "Entra failure preserves HRESULT and unknown state");
        const auto joined = state::detail::entra_join_result(0, true, 1, {{"tenant_id", "tenant-fixture"}});
        require(joined["value"]["join_kind"] == "device" && joined["value"]["attributes"]["tenant_id"] == "tenant-fixture",
            "device join preserves native tenant attributes");
        const auto workplace = state::detail::entra_join_result(0, true, 2, Json::object());
        require(workplace["value"]["join_kind"] == "workplace", "registered work account differs from device join");
        const auto unknown_join = state::detail::entra_join_result(0, true, 99, Json::object());
        require(unknown_join["state"] == "degraded" && unknown_join["value"]["join_type_value"] == 99,
            "unknown native join type preserves uncertainty instead of becoming unjoined");
        require(state::detail::entra_join_result(0, true, 1, {{"tenant_id", nullptr}}, true)["state"] == "degraded",
            "bounded-out native join text must mark incomplete evidence");
        require(snapshot["fields"]["hostname"]["state"] == "healthy", "read-only native hostname query must work on this test host");
        require(snapshot["fields"]["os_version"]["state"] == "healthy", "native OS version query must work on this test host");
        require(snapshot["fields"]["memory"]["state"] == "healthy", "native memory query must work on this test host");
        require(std::stoull(snapshot["fields"]["memory"]["value"]["physical_total_bytes"].get<std::string>()) > 0, "physical memory retains exact positive byte count");
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
        const auto record = factory.state("host_inventory", snapshot);
        require(record["subject"].is_null() && record["kind"] == "state", "host state must not create a process actor");
        require(Json::parse(record.dump())["data"] == snapshot, "snapshot must survive canonical JSON exactly");
        if (argc == 2 && std::string{argv[1]} == "--emit-live") { std::cout << record.dump() << '\n'; return 0; }
        std::cout << "native host inventory query/uncertainty tests passed; fields=" << snapshot["fields"].size()
                  << "; elapsed_ms=" << end - start << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
