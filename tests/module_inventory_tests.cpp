#include "panopticon/officer/state/module_inventory.hpp"
#include "panopticon/officer/health/state_freshness.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <stdexcept>
using Json = nlohmann::json;
using namespace panopticon::officer;
void require(bool condition, const char* reason) { if (!condition) throw std::runtime_error(reason); }
int main() {
    try {
        state::ModuleInventoryLimits limits;
        limits.pages.page_entries = 2;
        const auto self = GetCurrentProcessId();
        bool own_image = false, exact = false, zero_refused = false;
        std::size_t delivered = 0, pages = 0;
        auto manifest = state::collect_module_inventory_pages("module-test-host", "module-test-boot",
            [&](Json page) {
                require(page["module_state_version"] == "1.0" && page["inventory_complete"] == false,
                    "page version/coverage incorrect");
                require(page["page_index"] == std::to_string(pages++), "page ordering incorrect");
                for (const auto& row : page["entries"]) {
                    if (row["entry_kind"] == "process_identity_refusal" && row["requested_pid"] == 0)
                        zero_refused = row["process_reference"].is_null();
                    if (row["entry_kind"] != "module_descriptor") continue;
                    ++delivered;
                    require(row["observed_pid"] == self && row["held_process_alive_before_and_after_snapshot"] == true,
                        "module attributed to incorrect process");
                    require(row["module_instance_identity"].is_null() && row["file_identity"].is_null()
                        && row["content_read"] == false && row["signer_verified"] == false
                        && row["injection_verified"] == false, "module metadata overclaims evidence");
                    exact |= row["process_reference"]["resolution"] == "native_exact";
                    own_image |= row["base_address"] == std::to_string(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)));
                }
                return true;
            }, limits, {}, {0, self});
        require(delivered && own_image && exact && zero_refused, "owned image/identity or PID-zero refusal absent");
        require(manifest["modules_delivered"] == std::to_string(delivered) && manifest["module_inventory_complete"] == false,
            "accepted module accounting incorrect");
        bool unscoped = false;
        (void)state::collect_module_inventory_pages("module-test-host", std::nullopt, [&](Json page) {
            for (const auto& row : page["entries"]) if (row["entry_kind"] == "module_descriptor")
                unscoped |= row["process_reference"]["resolution"] == "native_unscoped";
            return true;
        }, {}, {}, {self});
        require(unscoped, "missing boot identity silently promoted");
        limits.modules_per_process = 1;
        bool bounded = false;
        manifest = state::collect_module_inventory_pages("module-test-host", "boot", [&](Json page) {
            for (const auto& row : page["entries"]) if (row["entry_kind"] == "process_summary")
                bounded |= row["module_limit_exceeded"] == true;
            return true;
        }, limits, {}, {self});
        require(bounded && manifest["modules_delivered"] == "1", "module limit incorrect");
        manifest = state::collect_module_inventory_pages("module-test-host", "boot", [](Json) { return false; }, limits, {}, {self});
        require(manifest["consumer_refused"] == true && manifest["modules_delivered"] == "0",
            "refused page counted as delivered");
        manifest = state::collect_module_inventory_pages("module-test-host", "boot", [](Json) { return true; }, {}, [] { return true; }, {self});
        require(manifest["cancelled"] == true && manifest["modules_delivered"] == "0", "cancelled query not accounted");
        limits.snapshot_attempts = 0;
        bool rejected = false;
        try { (void)state::collect_module_inventory_pages("host", "boot", [](Json) { return true; }, limits); }
        catch (const std::invalid_argument&) { rejected = true; }
        require(rejected, "invalid snapshot retry bounds accepted");
        Json health{{"module_inventory", {{"state", "degraded"}, {"last_committed_record_id", "module-capture"},
            {"last_committed_capture_started_uptime_ms", "10"}, {"last_committed_uptime_ms", "20"}}},
            {"capabilities", Json::array({{{"id", "state.module_inventory"}, {"state", "degraded"}}})}};
        health::apply_state_capture_freshness(health, 400000);
        require(health["module_inventory"]["state"] == "blind" && health["capabilities"][0]["state"] == "blind",
            "stale module state remains available");
        std::cout << "native module inventory: owned image, identity, refusal, bounds, cancellation and freshness passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
