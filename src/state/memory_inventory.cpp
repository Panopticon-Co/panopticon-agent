#include "panopticon/officer/state/memory_inventory.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#include "persistence_native.hpp"
#include <tlhelp32.h>
#include <limits>
#include <set>
#include <stdexcept>
namespace panopticon::officer::state {
namespace {
using namespace native_persistence;
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
};
std::uint64_t ticks(FILETIME v) { return (std::uint64_t(v.dwHighDateTime) << 32) | v.dwLowDateTime; }
Json termination(HANDLE process, Pager& pager) {
    const auto result = WaitForSingleObject(process, 0);
    if (result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT)
        return {{"state", "healthy"}, {"value", result == WAIT_OBJECT_0}, {"source", "WaitForSingleObject/held process/zero timeout"}};
    const auto error = result == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
    ++pager.failures; return failure("WaitForSingleObject/held process", error, "Win32");
}
bool process(DWORD pid, core::ProcessInstanceStore& identities, Pager& pager, const MemoryInventoryLimits& limits) {
    Handle held{OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pid)};
    if (!held.value) {
        const auto error = GetLastError(); ++pager.failures;
        return pager.add({{"entry_kind", "process_open_refusal"}, {"requested_pid", pid}, {"process_reference", nullptr},
            {"query", failure("OpenProcess/PROCESS_QUERY_INFORMATION+SYNCHRONIZE", error, "Win32")}});
    }
    const auto actual = GetProcessId(held.value);
    if (!actual || actual != pid) {
        const auto error = actual ? ERROR_INVALID_DATA : GetLastError(); ++pager.failures;
        return pager.add({{"entry_kind", "process_identity_refusal"}, {"requested_pid", pid}, {"process_reference", nullptr},
            {"query", failure("GetProcessId/held process", error, "Win32")}});
    }
    FILETIME born{}, exit{}, kernel{}, user{}; std::optional<std::uint64_t> creation;
    Json identity_error = nullptr;
    if (GetProcessTimes(held.value, &born, &exit, &kernel, &user)) creation = ticks(born);
    else { const auto error = GetLastError(); ++pager.failures; identity_error = failure("GetProcessTimes/held process", error, "Win32"); }
    const auto reference = identities.observe(actual, creation, std::nullopt, "Win32:held-memory-query").json();
    const auto started = GetTickCount64();
    if (!pager.add({{"entry_kind", "process_begin"}, {"requested_pid", pid}, {"process_reference", reference},
        {"identity_query_failure", identity_error}, {"termination_observed", termination(held.value, pager)},
        {"descriptor_instance_relation", "unverified; PID may have been reused before OpenProcess"},
        {"query_started_uptime_ms", std::to_string(started)}, {"content_read", false}})) return false;
    std::uintptr_t address = 0;
    std::size_t queries = 0, regions = 0, free_ranges = 0;
    bool boundary = false, bounded = false; Json query_error = nullptr;
    while (pager.active()) {
        if (queries >= limits.queries_per_process || regions >= limits.regions_per_process) { bounded = true; break; }
        MEMORY_BASIC_INFORMATION info{}; ++queries;
        const auto query_started = GetTickCount64();
        const auto returned = VirtualQueryEx(held.value, reinterpret_cast<const void*>(address), &info, sizeof(info));
        if (!returned) {
            const auto error = GetLastError();
            // Preserve native end/error evidence. An invalid parameter at a later
            // address is an observed API boundary, not proof of stable/full memory.
            boundary = error == ERROR_INVALID_PARAMETER && address != 0;
            if (!boundary) ++pager.failures;
            query_error = failure("VirtualQueryEx/held process", error, "Win32"); break;
        }
        const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        if (returned != sizeof(info) || !info.RegionSize || base > address
            || info.RegionSize > std::numeric_limits<std::uintptr_t>::max() - base || base + info.RegionSize <= address) {
            ++pager.failures; query_error = failure("VirtualQueryEx/invalid native region span", ERROR_INVALID_DATA, "Win32"); break;
        }
        const auto next = base + info.RegionSize;
        if (info.State == MEM_FREE) { ++free_ranges; address = next; continue; }
        const bool committed = info.State == MEM_COMMIT;
        const bool allocated = committed || info.State == MEM_RESERVE;
        Json executable = nullptr, writable = nullptr, guard = nullptr;
        if (committed) {
            const auto protection = info.Protect & 0xff;
            const bool known = protection == PAGE_NOACCESS || protection == PAGE_READONLY || protection == PAGE_READWRITE
                || protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ
                || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
            if (known) {
                executable = protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
                writable = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
            }
            guard = (info.Protect & PAGE_GUARD) != 0;
        }
        Json row{{"entry_kind", "memory_region"}, {"process_reference", reference}, {"source", "VirtualQueryEx/held process"},
            {"requested_address", std::to_string(address)}, {"base_address", std::to_string(base)},
            {"region_bytes", std::to_string(info.RegionSize)}, {"native_state", std::to_string(info.State)},
            {"allocation_base", allocated ? Json(std::to_string(reinterpret_cast<std::uintptr_t>(info.AllocationBase))) : Json(nullptr)},
            {"allocation_protection_mask", allocated ? Json(std::to_string(info.AllocationProtect)) : Json(nullptr)},
            {"protection_mask", committed ? Json(std::to_string(info.Protect)) : Json(nullptr)},
            {"native_type", allocated ? Json(std::to_string(info.Type)) : Json(nullptr)},
            {"executable_reported", executable}, {"write_capable_reported", writable}, {"guard_reported", guard},
            {"private_executable_reported", committed && !executable.is_null() ? Json(info.Type == MEM_PRIVATE && executable == true) : Json(nullptr)},
            {"query_started_uptime_ms", std::to_string(query_started)}, {"query_completed_uptime_ms", std::to_string(GetTickCount64())},
            {"content_read", false}, {"injection_verified", false}, {"mapping_instance_identity", nullptr},
            {"consistency", "one held process; region observations non_atomic; mappings can change/reuse between calls"}};
        if (!pager.add(std::move(row))) return false;
        ++regions; address = next;
    }
    return pager.add({{"entry_kind", "process_summary"}, {"process_reference", reference}, {"queries_attempted", std::to_string(queries)},
        {"regions_observed", std::to_string(regions)}, {"free_ranges_skipped", std::to_string(free_ranges)},
        {"last_requested_or_next_address", std::to_string(address)}, {"native_address_boundary_observed", boundary},
        {"process_bound_exceeded", bounded}, {"query_failure_or_boundary", query_error},
        {"termination_observed", termination(held.value, pager)}, {"query_started_uptime_ms", std::to_string(started)},
        {"query_completed_uptime_ms", std::to_string(GetTickCount64())}, {"memory_inventory_complete", false}});
}
}
Json collect_memory_inventory_pages(const std::string& host, const std::optional<std::string>& boot,
    const std::function<bool(Json)>& consumer, MemoryInventoryLimits limits, const std::function<bool()>& cancelled,
    const std::vector<std::uint32_t>& requested) {
    const auto& b = limits.pages;
    if (host.empty() || (boot && boot->empty()) || !consumer || !b.page_entries || b.page_entries > 4096
        || b.encoded_bytes < 4096 || b.encoded_bytes > 512 * 1024 || !b.total_entries || b.total_entries > 65536
        || !b.pages || b.pages > 1024 || !b.soft_budget_ms || b.soft_budget_ms > 300000
        || !limits.processes || limits.processes > 256 || !limits.regions_per_process || limits.regions_per_process > 16384
        || !limits.queries_per_process || limits.queries_per_process > 65536 || requested.size() > 256)
        throw std::invalid_argument("invalid native memory inventory scope/bounds");
    std::size_t accepted_regions = 0;
    const std::function<bool(Json)> sink = [&](Json page) {
        std::size_t count = 0;
        for (const auto& row : page["entries"]) count += row.value("entry_kind", "") == "memory_region";
        if (!consumer(std::move(page))) return false;
        accepted_regions += count; return true;
    };
    Pager pager{b, "memory_region_inventory", sink, cancelled, "memory_state_version"};
    std::set<DWORD> candidates; bool enumerated = !requested.empty(), descriptor_bound = false; Json enumeration_error = nullptr;
    if (!requested.empty()) candidates.insert(requested.begin(), requested.end());
    else if (pager.active()) {
        Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
        if (snapshot.value == INVALID_HANDLE_VALUE) { ++pager.failures; enumeration_error = failure("CreateToolhelp32Snapshot/process", GetLastError(), "Win32"); }
        else {
            PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry); BOOL available = Process32FirstW(snapshot.value, &entry);
            for (;;) {
                if (!available) {
                    const auto error = GetLastError(); enumerated = error == ERROR_NO_MORE_FILES;
                    if (!enumerated) { ++pager.failures; enumeration_error = failure("Process32First/Next", error, "Win32"); }
                    break;
                }
                if (!pager.active()) break;
                if (entry.dwSize < offsetof(PROCESSENTRY32W, th32ProcessID) + sizeof(entry.th32ProcessID)) {
                    ++pager.failures; enumeration_error = failure("PROCESSENTRY32/short descriptor", ERROR_INVALID_DATA, "Win32"); break;
                }
                if (candidates.size() >= 65536) { descriptor_bound = true; break; }
                candidates.insert(entry.th32ProcessID); entry = {}; entry.dwSize = sizeof(entry);
                available = Process32NextW(snapshot.value, &entry);
            }
        }
    }
    std::vector<DWORD> order;
    const auto split = candidates.upper_bound(limits.after_pid);
    order.insert(order.end(), split, candidates.end()); order.insert(order.end(), candidates.begin(), split);
    core::ProcessInstanceStore identities{host, boot, 256};
    std::size_t attempted = 0; DWORD last = limits.after_pid;
    for (const auto pid : order) {
        if (attempted >= limits.processes || !pager.active()) break;
        ++attempted; last = pid;
        if (!process(pid, identities, pager, limits)) break;
    }
    auto result = pager.finish("bounded rotating PID candidates; held-process VirtualQueryEx metadata; no content/injection/continuous coverage", enumerated && attempted == candidates.size());
    result["descriptor_enumeration_complete"] = enumerated; result["descriptor_bound_exceeded"] = descriptor_bound;
    result["enumeration_failure"] = enumeration_error; result["candidate_processes"] = std::to_string(candidates.size());
    result["processes_attempted"] = std::to_string(attempted); result["process_limit_exceeded"] = attempted < candidates.size();
    result["next_after_pid"] = last; result["requested_pid_scope"] = !requested.empty();
    result["process_limits"] = {{"processes", limits.processes}, {"regions_per_process", limits.regions_per_process}, {"queries_per_process", limits.queries_per_process}};
    result["resource_scope"] = "bounded application rows/pages/candidates/native queries; native calls and Toolhelp snapshot lack hard deadline/allocation bounds";
    result["content_read"] = false; result["injection_verified"] = false; result["memory_inventory_complete"] = false;
    result["memory_regions_delivered"] = std::to_string(accepted_regions);
    if (!accepted_regions) result["state"] = "unavailable";
    return result;
}
}
