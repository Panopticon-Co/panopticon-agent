#include "panopticon/officer/state/module_inventory.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#include "persistence_native.hpp"
#include <tlhelp32.h>
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
template<std::size_t N> Json descriptor_text(const wchar_t (&v)[N]) {
    const auto end = std::find(v, v + N, L'\0');
    return {{"value", text(v, static_cast<std::size_t>(end - v))}, {"terminated", end != v + N},
        {"scope", "bounded native descriptor; no file identity or path resolution"}};
}
bool process(DWORD pid, core::ProcessInstanceStore& identities, Pager& pager, const ModuleInventoryLimits& limits) {
    const auto refuse = [&](const char* kind, const char* api, DWORD error) {
        ++pager.failures;
        return pager.add({{"entry_kind", kind}, {"requested_pid", pid}, {"process_reference", nullptr},
            {"query", failure(api, error, "Win32")}});
    };
    // PID zero means current process to Toolhelp. Never silently substitute it.
    if (!pid) return refuse("process_identity_refusal", "Toolhelp/PID zero is not an explicit process target", ERROR_INVALID_PARAMETER);
    Handle held{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid)};
    if (!held.value) return refuse("process_open_refusal", "OpenProcess/query-limited+SYNCHRONIZE", GetLastError());
    const auto actual = GetProcessId(held.value);
    if (!actual) return refuse("process_identity_refusal", "GetProcessId", GetLastError());
    if (actual != pid) return refuse("process_identity_refusal", "held PID mismatch", ERROR_INVALID_DATA);
    FILETIME born{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(held.value, &born, &exit, &kernel, &user))
        return refuse("process_identity_refusal", "GetProcessTimes", GetLastError());
    if (!ticks(born)) return refuse("process_identity_refusal", "zero native creation time", ERROR_INVALID_DATA);
    const auto reference = identities.observe(actual, ticks(born), std::nullopt, "Win32:held-module-query").json();
    if (!pager.add({{"entry_kind", "process_begin"}, {"requested_pid", pid}, {"process_reference", reference},
        {"descriptor_instance_relation", "process census PID remains unverified; held process used for snapshot guard"},
        {"content_read", false}})) return false;
    auto before = WaitForSingleObject(held.value, 0);
    if (before != WAIT_TIMEOUT) return refuse("process_liveness_refusal", "WaitForSingleObject/before snapshot",
        before == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED);
    constexpr DWORD flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    HANDLE raw = INVALID_HANDLE_VALUE; DWORD error = ERROR_CANCELLED;
    std::size_t attempts = 0;
    while (attempts < limits.snapshot_attempts && pager.active()) {
        ++attempts; raw = CreateToolhelp32Snapshot(flags, pid);
        if (raw != INVALID_HANDLE_VALUE) break;
        error = GetLastError();
        if (error != ERROR_BAD_LENGTH) break;
    }
    Handle snapshot{raw};
    if (raw == INVALID_HANDLE_VALUE) {
        ++pager.failures;
        return pager.add({{"entry_kind", "module_snapshot_refusal"}, {"process_reference", reference},
            {"attempts", std::to_string(attempts)}, {"snapshot_flags", std::to_string(flags)},
            {"query", failure("CreateToolhelp32Snapshot/modules", error, "Win32")}});
    }
    const auto after = WaitForSingleObject(held.value, 0);
    if (after != WAIT_TIMEOUT) return refuse("process_liveness_refusal", "WaitForSingleObject/after snapshot",
        after == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED);
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    BOOL available = Module32FirstW(snapshot.value, &entry);
    DWORD iteration_error = available ? ERROR_SUCCESS : GetLastError();
    bool complete = false, bounded = false; Json query_error = nullptr;
    std::size_t count = 0;
    while (pager.active()) {
        if (!available) {
            error = iteration_error; complete = error == ERROR_NO_MORE_FILES;
            if (!complete) { ++pager.failures; query_error = failure("Module32First/Next", error, "Win32"); }
            break;
        }
        if (count >= limits.modules_per_process) { bounded = true; break; }
        if (entry.dwSize != sizeof(entry) || entry.th32ProcessID != pid) {
            ++pager.failures; query_error = failure("MODULEENTRY32/size or PID mismatch", ERROR_INVALID_DATA, "Win32"); break;
        }
        if (!pager.add({{"entry_kind", "module_descriptor"}, {"source", "Toolhelp/MODULEENTRY32W"},
            {"process_reference", reference}, {"observed_pid", entry.th32ProcessID},
            {"base_address", std::to_string(reinterpret_cast<std::uintptr_t>(entry.modBaseAddr))},
            {"image_bytes", std::to_string(entry.modBaseSize)}, {"module_name", descriptor_text(entry.szModule)},
            {"reported_path", descriptor_text(entry.szExePath)}, {"snapshot_attempts", std::to_string(attempts)},
            {"snapshot_flags", std::to_string(flags)}, {"held_process_alive_before_and_after_snapshot", true},
            {"descriptor_observed_uptime_ms", std::to_string(GetTickCount64())},
            {"module_instance_identity", nullptr}, {"file_identity", nullptr}, {"signer_verified", false},
            {"content_read", false}, {"injection_verified", false},
            {"consistency", "loader snapshot descriptors; module mappings can unload/reuse; manual/datafile mappings not covered"}})) return false;
        ++count; entry = {}; entry.dwSize = sizeof(entry);
        available = Module32NextW(snapshot.value, &entry);
        iteration_error = available ? ERROR_SUCCESS : GetLastError();
    }
    return pager.add({{"entry_kind", "process_summary"}, {"process_reference", reference},
        {"modules_observed", std::to_string(count)}, {"module_enumeration_complete", complete},
        {"module_limit_exceeded", bounded}, {"query_failure", query_error}, {"module_inventory_complete", false}});
}
}
Json collect_module_inventory_pages(const std::string& host, const std::optional<std::string>& boot,
    const std::function<bool(Json)>& consumer, ModuleInventoryLimits limits, const std::function<bool()>& cancelled,
    const std::vector<std::uint32_t>& requested) {
    const auto& b = limits.pages;
    if (host.empty() || (boot && boot->empty()) || !consumer || !b.page_entries || b.page_entries > 4096
        || b.encoded_bytes < 4096 || b.encoded_bytes > 512 * 1024 || !b.total_entries || b.total_entries > 65536
        || !b.pages || b.pages > 1024 || !b.soft_budget_ms || b.soft_budget_ms > 300000
        || !limits.processes || limits.processes > 256 || !limits.modules_per_process || limits.modules_per_process > 4096
        || !limits.snapshot_attempts || limits.snapshot_attempts > 8 || requested.size() > 256)
        throw std::invalid_argument("invalid native module inventory scope/bounds");
    std::size_t accepted_modules = 0;
    const std::function<bool(Json)> sink = [&](Json page) {
        std::size_t count = 0;
        for (const auto& row : page["entries"]) count += row.value("entry_kind", "") == "module_descriptor";
        if (!consumer(std::move(page))) return false;
        accepted_modules += count; return true;
    };
    Pager pager{b, "module_inventory", sink, cancelled, "module_state_version"};
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
    auto result = pager.finish("bounded rotating PID candidates; guarded Toolhelp loader-list metadata; no content/signature/injection/continuous coverage", enumerated && attempted == candidates.size());
    result["descriptor_enumeration_complete"] = enumerated; result["descriptor_bound_exceeded"] = descriptor_bound;
    result["enumeration_failure"] = enumeration_error; result["candidate_processes"] = std::to_string(candidates.size());
    result["processes_attempted"] = std::to_string(attempted); result["process_limit_exceeded"] = attempted < candidates.size();
    result["next_after_pid"] = last; result["requested_pid_scope"] = !requested.empty();
    result["process_limits"] = {{"processes", limits.processes}, {"modules_per_process", limits.modules_per_process}, {"snapshot_attempts", limits.snapshot_attempts}};
    result["resource_scope"] = "bounded application rows/pages/candidates/native queries; native calls and Toolhelp snapshot lack hard deadline/allocation bounds";
    result["content_read"] = false; result["injection_verified"] = false; result["module_inventory_complete"] = false;
    result["modules_delivered"] = std::to_string(accepted_modules);
    if (!accepted_modules) result["state"] = "unavailable";
    return result;
}
}
