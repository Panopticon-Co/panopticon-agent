#include "panopticon/officer/state/memory_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using Json = nlohmann::json;
namespace fs = std::filesystem;
using namespace panopticon::officer;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Allocation {
    void* value = nullptr;
    explicit Allocation(DWORD protection) : value(VirtualAlloc(nullptr, 0x3000, MEM_COMMIT | MEM_RESERVE, protection)) {
        require(value != nullptr, "owned native allocation");
    }
    ~Allocation() { if (value) VirtualFree(value, 0, MEM_RELEASE); }
    Allocation(const Allocation&) = delete;
};
bool span_contains(const Json& row, std::uintptr_t address) {
    const auto base = std::stoull(row["base_address"].get<std::string>());
    const auto size = std::stoull(row["region_bytes"].get<std::string>());
    return address >= base && address - base < size;
}
struct Capture { Json manifest; Json pages = Json::array(); };
Capture capture(const std::optional<std::string>& boot, const std::vector<std::uint32_t>& pids, state::MemoryInventoryLimits limits = {}) {
    Capture result;
    result.manifest = state::collect_memory_inventory_pages("memory-test-host", boot, [&](Json page) {
        result.pages.push_back(std::move(page)); return true;
    }, limits, {}, pids);
    return result;
}
void check_primary(Capture& value, void* writable, void* executable, const std::optional<std::string>& boot) {
    bool writable_found = false, executable_found = false, refusal_found = false, self_begin = false;
    const auto self = GetCurrentProcessId();
    for (const auto& page : value.pages) {
        require(page["memory_state_version"] == "1.0" && page["inventory_complete"] == false,
            "memory pages cannot imply complete coverage");
        for (const auto& row : page["entries"]) {
            if (row["entry_kind"] == "process_open_refusal" && row["requested_pid"] == 0) {
                refusal_found = true;
                require(row["process_reference"].is_null() && row["query"]["state"] == "unavailable",
                    "unopenable process retains refusal without invented identity");
            }
            if (row["entry_kind"] == "process_begin" && row["requested_pid"] == self) {
                self_begin = true;
                const auto& ref = row["process_reference"];
                require(ref["observed_pid"] == self && ref["resolution"] == (boot ? "native_exact" : "native_unscoped")
                    && row["content_read"] == false, "held process identity/content semantics");
            }
            if (row["entry_kind"] != "memory_region" || row["process_reference"]["observed_pid"] != self) continue;
            require(row["content_read"] == false && row["injection_verified"] == false && row["mapping_instance_identity"].is_null(),
                "region metadata must not become content, mapping identity or injection proof");
            if (span_contains(row, reinterpret_cast<std::uintptr_t>(writable))) {
                writable_found = true;
                require(row["native_state"] == std::to_string(MEM_COMMIT) && row["native_type"] == std::to_string(MEM_PRIVATE)
                    && row["write_capable_reported"] == true && row["executable_reported"] == false
                    && row["private_executable_reported"] == false, "owned RW allocation metadata disagrees");
            }
            if (span_contains(row, reinterpret_cast<std::uintptr_t>(executable))) {
                executable_found = true;
                require(row["native_state"] == std::to_string(MEM_COMMIT) && row["native_type"] == std::to_string(MEM_PRIVATE)
                    && row["executable_reported"] == true && row["write_capable_reported"] == false
                    && row["private_executable_reported"] == true, "owned RX allocation metadata disagrees");
            }
        }
    }
    require(self_begin && writable_found && executable_found && refusal_found, "real held process regions/refusal absent");
    require(value.manifest["requested_pid_scope"] == true && value.manifest["memory_inventory_complete"] == false
        && value.manifest["content_read"] == false && value.manifest["injection_verified"] == false,
        "manifest overclaims memory coverage");
}
Json canonical_records(const Capture& input, const std::optional<std::string>& boot) {
    pipeline::NormalizationContext context{{"agent-memory-test", "dev"}, {"host-memory-test", "LAB", {"Windows", "native"}}};
    pipeline::EndpointRecordFactory factory{context, "device-memory-test", std::string(64, 'e'), boot, 1};
    Json result = Json::array();
    auto begin = factory.state("memory_region_inventory_begin", {{"format", "paged_memory_region_inventory_begin_v1"},
        {"inventory_complete", false}});
    const auto capture_id = begin["record_id"];
    result.push_back(std::move(begin)); Json page_ids = Json::array();
    for (auto page : input.pages) {
        page["capture_id"] = capture_id;
        auto record = factory.state("memory_region_inventory_page", std::move(page));
        page_ids.push_back(record["record_id"]); result.push_back(std::move(record));
    }
    auto manifest = input.manifest; manifest["format"] = "paged_memory_region_inventory_v1";
    manifest["capture_id"] = capture_id; manifest["page_record_ids"] = page_ids;
    result.push_back(factory.state("memory_region_inventory", std::move(manifest)));
    return result;
}
int main(int argc, char** argv) {
    try {
        std::string error; const auto boot = core::query_native_boot_id(error);
        Allocation writable{PAGE_READWRITE}, executable{PAGE_EXECUTE_READ};
        auto primary = capture(boot, {0, GetCurrentProcessId(), GetCurrentProcessId()});
        check_primary(primary, writable.value, executable.value, boot);
        state::MemoryInventoryLimits bounds; bounds.regions_per_process = 1;
        const auto limited = capture(boot, {GetCurrentProcessId()}, bounds);
        require(limited.manifest["process_limit_exceeded"] == false && limited.manifest["memory_inventory_complete"] == false,
            "one region process cap cannot claim complete memory inventory");
        bool bounded_summary = false;
        for (const auto& page : limited.pages) for (const auto& row : page["entries"])
            if (row["entry_kind"] == "process_summary") bounded_summary |= row["process_bound_exceeded"] == true;
        require(bounded_summary, "per-process memory bound unreported");
        state::MemoryInventoryLimits refused_bounds; bool callback = false;
        const auto refused = state::collect_memory_inventory_pages("host", boot, [&](Json) { callback = true; return false; }, refused_bounds, {}, {GetCurrentProcessId()});
        require(callback && refused["consumer_refused"] == true && refused["entries_delivered"] == "0"
            && refused["memory_inventory_complete"] == false, "consumer refusal changes capture accounting");
        const auto cancelled = state::collect_memory_inventory_pages("host", boot, [](Json) { return true; }, {}, [] { return true; }, {GetCurrentProcessId()});
        require(cancelled["cancelled"] == true && cancelled["memory_inventory_complete"] == false, "cancelled capture cannot claim coverage");
        const auto unknown_boot = capture(std::nullopt, {GetCurrentProcessId()});
        bool unresolved = false;
        for (const auto& page : unknown_boot.pages) for (const auto& row : page["entries"])
            if (row["entry_kind"] == "process_begin") unresolved |= row["process_reference"]["entity_id"].is_null()
                && row["process_reference"]["resolution"] == "native_unscoped";
        require(unresolved, "missing boot cannot mint stable process identity");
        state::MemoryInventoryLimits invalid; invalid.processes = 0; bool threw = false;
        try { (void)capture(boot, {GetCurrentProcessId()}, invalid); } catch (const std::invalid_argument&) { threw = true; }
        require(threw, "invalid memory limits fail before collection");
        if (argc == 3 && std::string(argv[1]) == "--report") {
            const fs::path target{argv[2]}; require(!fs::exists(target), "preserve existing native memory report");
            Json report{{"real_windows_memory_region_verified", true}, {"held_process_identity_verified", true},
                {"rw_and_rx_regions_verified", true}, {"open_refusal_verified", true}, {"content_read", false},
                {"injection_verified", false}, {"full_memory_coverage_verified", false}, {"records", canonical_records(primary, boot)},
                {"owned", {{"pid", GetCurrentProcessId()}, {"rw_address", std::to_string(reinterpret_cast<std::uintptr_t>(writable.value))},
                    {"rx_address", std::to_string(reinterpret_cast<std::uintptr_t>(executable.value))}}}};
            std::ofstream out(target, std::ios::binary); require(bool(out), "memory report open"); out << report.dump(); require(bool(out), "memory report write");
        }
        std::cout << "native memory region inventory tests passed\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
