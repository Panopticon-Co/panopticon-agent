#include "panopticon/officer/state/thread_inventory.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <fstream>
#include <stdexcept>
using Json = nlohmann::json;
using namespace panopticon::officer;
void require(bool value, const char* text) { if (!value) throw std::runtime_error(text); }
std::uint64_t ticks(FILETIME v) { return (std::uint64_t(v.dwHighDateTime) << 32) | v.dwLowDateTime; }
int main(int argc, char** argv) {
    try {
        std::string error; const auto boot = core::query_native_boot_id(error);
        Json pages = Json::array(); bool self_found = false;
        const auto result = state::collect_thread_inventory_pages("thread-test-host", boot, [&](Json page) {
            require(page["inventory_complete"] == false && page["state"] == "degraded", "no complete thread census claim");
            for (const auto& row : page["entries"]) {
                if (row.contains("entry_kind")) continue;
                const auto& query = row["later_tid_query"];
                require(row["descriptor_instance_relation"].is_string(), "descriptor relation remains unverified");
                if (!query.contains("reference")) { require(query["value"].is_null() && query["error_code"].is_string(), "native refusal not invented thread"); continue; }
                require(query["owner_process_reference"].is_null() && query["owner_process_instance_verified"] == false
                    && query["start_address"].is_null(), "no PID-only owner or invented start address");
                if (row["snapshot_descriptor"]["tid"] != GetCurrentThreadId()) continue;
                self_found = true;
                FILETIME born{}, exit{}, kernel{}, user{};
                require(GetThreadTimes(GetCurrentThread(), &born, &exit, &kernel, &user), "owned native times baseline");
                require(query["reference"]["native_creation_ticks"] == std::to_string(ticks(born))
                    && query["times"]["value"]["creation_ticks"] == std::to_string(ticks(born)), "exact owned creation token");
                require(query["reference"]["resolution"] == (boot ? "native_exact" : "unresolved"), "boot qualification controls reference");
                require(query["reported_owner_pid"]["value"] == GetCurrentProcessId()
                    && query["priority"]["value"] == GetThreadPriority(GetCurrentThread())
                    && query["termination_observed"]["value"] == false, "owned APIs agree with actual held thread");
                require(query["times"]["value"]["exit_ticks"].is_null() && query["cpu_cycles"]["value"].is_string(), "undefined exit omitted and cycles exact string");
            }
            pages.push_back(std::move(page)); return true;
        });
        require(self_found && result["enumeration_complete"] == true && result["inventory_complete"] == false,
            "actual system snapshot includes owned live thread but no continuous coverage");
        state::NativeInventoryLimits bounds; bounds.total_entries = 1;
        std::size_t delivered = 0;
        const auto bounded = state::collect_thread_inventory_pages("host", boot, [&](Json page) { delivered += page["entries"].size(); return true; }, bounds);
        require(delivered == 1 && bounded["bound_exceeded"] == true && bounded["enumeration_complete"] == false, "total admission bound explicit");
        bounds = {}; bounds.page_entries = 1;
        const auto refused = state::collect_thread_inventory_pages("host", boot, [](Json) { return false; }, bounds);
        require(refused["consumer_refused"] == true && refused["entries_delivered"] == "0" && refused["enumeration_complete"] == false, "refused page not delivered");
        const auto cancelled = state::collect_thread_inventory_pages("host", boot, [](Json) { return true; }, {}, [] { return true; });
        require(cancelled["cancelled"] == true && cancelled["enumeration_complete"] == false, "cancelled capture no success inference");
        bool unresolved_found = false;
        (void)state::collect_thread_inventory_pages("host", std::nullopt, [&](Json page) {
            for (const auto& row : page["entries"]) if (row.contains("later_tid_query") && row["later_tid_query"].contains("reference")) {
                const auto& reference = row["later_tid_query"]["reference"];
                require(reference["resolution"] == "unresolved" && reference["entity_id"].is_null(), "no boot no stable identity"); unresolved_found = true;
            }
            return true;
        });
        require(unresolved_found, "unknown boot test exercised real handle");
        bounds.page_entries = 0; bool threw = false;
        try { (void)state::collect_thread_inventory_pages("host", boot, [](Json) { return true; }, bounds); }
        catch (const std::invalid_argument&) { threw = true; }
        require(threw, "invalid bounds refuse before capture");
        if (argc == 3 && std::string(argv[1]) == "--capture") {
            std::ofstream file(argv[2], std::ios::binary); require(bool(file), "capture file opens");
            file << Json{{"manifest", result}, {"pages", pages}, {"owned_tid", GetCurrentThreadId()}, {"owned_pid", GetCurrentProcessId()}}.dump();
            require(bool(file), "capture file writes");
        }
        std::cout << "native thread inventory tests passed\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
