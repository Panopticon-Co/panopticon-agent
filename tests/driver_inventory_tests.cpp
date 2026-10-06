#include "panopticon/officer/state/driver_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <limits>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <vector>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* text) { if (!value) throw std::runtime_error(text); }
std::vector<std::byte> token_privileges() {
    HANDLE token = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE, "owned token query opens");
    DWORD needed = 0; (void)GetTokenInformation(token, TokenPrivileges, nullptr, 0, &needed);
    if (!needed || needed > 65536) { CloseHandle(token); throw std::runtime_error("owned privilege query bound"); }
    std::vector<std::byte> bytes(needed); DWORD returned = 0;
    const auto success = GetTokenInformation(token, TokenPrivileges, bytes.data(), needed, &returned);
    CloseHandle(token); require(success != FALSE && returned <= bytes.size(), "owned privilege query succeeds");
    bytes.resize(returned); return bytes;
}
int main(int argc, char** argv) {
    try {
        const std::array<std::uintptr_t, 3> hidden{};
        auto visibility = state::detail::driver_address_visibility(hidden);
        require(visibility["state"] == "blind" && visibility["reported_slots"] == "3" && visibility["non_null_address_slots"] == "0", "successful NULL-only enumeration is blind, not empty/healthy");
        const std::array<std::uintptr_t, 3> mixed{0, std::numeric_limits<std::uintptr_t>::max(), 1};
        visibility = state::detail::driver_address_visibility(mixed);
        require(visibility["state"] == "degraded" && visibility["null_address_slots"] == "1", "mixed visibility retains unknown slots instead of asserting complete coverage");
        std::string error; const auto boot = core::query_native_boot_id(error);
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), boot, 1};
        Json records = Json::array(), ids = Json::array(); std::size_t count = 0, pages = 0, nulls = 0;
        const auto begin = factory.state("loaded_driver_inventory_begin", {{"inventory_complete", false}});
        records.push_back(begin);
        const auto privileges_before = token_privileges();
        auto summary = state::collect_loaded_driver_pages([&](Json page) {
            require(page["page_index"] == std::to_string(pages++), "loaded-driver pages ordered");
            require(page["entries"].size() <= 256 && page["entries"].dump().size() <= 512 * 1024, "loaded-driver page bounds apply");
            for (const auto& row : page["entries"]) {
                require(row["module_instance_reference"].is_null() && row["service_instance_reference"].is_null() && row["file_reference"].is_null(), "address/path never promoted to instance/file identity");
                ++count; if (row["reported_image_base"] == "0") { ++nulls; require(row["later_file_name"]["value"].is_null(), "hidden address cannot invent a driver path"); }
            }
            page["capture_id"] = begin.at("record_id"); const auto record = factory.state("loaded_driver_inventory_page", std::move(page));
            ids.push_back(record.at("record_id")); records.push_back(record); return true;
        });
        require(token_privileges() == privileges_before, "native loaded-driver collection does not change owned token privileges");
        if (summary.contains("entries_delivered")) {
            require(summary["entries_delivered"] == std::to_string(count) && summary["null_address_slots"] == std::to_string(nulls), "native loaded-driver counts match all delivered slots");
            if (count && nulls == count) require(summary["state"] == "blind", "actual restricted native enumeration remains blind");
        } else require(summary["state"] == "unavailable" && summary["value"].is_null(), "native enumeration refusal is explicit");
        summary["capture_id"] = begin.at("record_id"); summary["page_record_ids"] = ids;
        records.push_back(factory.state("loaded_driver_inventory", summary));
        if (argc == 2 && std::string{argv[1]} == "--emit-live") std::cout << records.dump() << '\n';
        else if (pages) {
            const auto refused = state::collect_loaded_driver_pages([](Json) { return false; });
            require(refused["consumer_refused"] == true && refused["entries_delivered"] == "0", "consumer refusal cannot count uncommitted driver pages");
        }
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
