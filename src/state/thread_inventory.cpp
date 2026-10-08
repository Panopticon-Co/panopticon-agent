#include "panopticon/officer/state/thread_inventory.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "persistence_native.hpp"
#include <tlhelp32.h>
#include <cstddef>
#include <stdexcept>
namespace panopticon::officer::state {
namespace {
using namespace native_persistence;
struct Handle {
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    explicit Handle(HANDLE h) : value(h) {}
};
std::uint64_t ticks(FILETIME value) { return (std::uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
Json observed(Json value, const char* api) {
    return {{"state", "healthy"}, {"source", api}, {"value", std::move(value)}, {"error_code", nullptr}};
}
Json query(DWORD tid, const std::string& host, const std::optional<std::string>& boot, Pager& pager) {
    Handle thread{OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid)};
    if (!thread.value) { const auto code = GetLastError(); ++pager.failures; return failure("OpenThread/query-limited+synchronize", code, "Win32"); }
    const auto actual = GetThreadId(thread.value);
    if (!actual || actual != tid) {
        const auto code = actual ? ERROR_INVALID_DATA : GetLastError(); ++pager.failures;
        return failure("GetThreadId/held handle", code, "Win32");
    }
    Json reference{{"observed_tid", actual}, {"boot_id", boot ? Json(*boot) : Json(nullptr)},
        {"entity_id", nullptr}, {"native_creation_ticks", nullptr}, {"resolution", "unresolved"},
        {"source_namespace", "Win32:held-thread-query"}};
    FILETIME born{}, exited{}, kernel{}, user{};
    Json times;
    const bool times_ok = GetThreadTimes(thread.value, &born, &exited, &kernel, &user) != FALSE;
    if (!times_ok) { const auto code = GetLastError(); ++pager.failures; times = failure("GetThreadTimes/held handle", code, "Win32"); }
    else {
        const auto creation = ticks(born);
        reference["native_creation_ticks"] = std::to_string(creation);
        if (creation && boot) {
            const auto field = [](const std::string& s) { return std::to_string(s.size()) + ":" + s; };
            std::string error;
            const auto hash = core::sha256_hex("windows-thread-instance-v1" + field(host) + field(*boot)
                + field(std::to_string(actual)) + field(std::to_string(creation)), error);
            if (!hash) throw std::runtime_error(error);
            reference["entity_id"] = "thread_" + *hash;
            reference["resolution"] = "native_exact";
        }
        times = observed({{"creation_ticks", std::to_string(creation)}, {"kernel_cpu_ticks", std::to_string(ticks(kernel))},
            {"user_cpu_ticks", std::to_string(ticks(user))}, {"exit_ticks", nullptr}}, "GetThreadTimes/held handle/100ns FILETIME");
    }
    const auto owner = GetProcessIdOfThread(thread.value);
    Json owner_fact;
    if (owner) owner_fact = observed(owner, "GetProcessIdOfThread/held handle");
    else { const auto code = GetLastError(); ++pager.failures; owner_fact = failure("GetProcessIdOfThread/held handle", code, "Win32"); }
    const auto priority = GetThreadPriority(thread.value);
    Json priority_fact;
    if (priority == THREAD_PRIORITY_ERROR_RETURN) { const auto code = GetLastError(); ++pager.failures; priority_fact = failure("GetThreadPriority/held handle", code, "Win32"); }
    else priority_fact = observed(priority, "GetThreadPriority/held handle/raw relative priority");
    ULONG64 cycles = 0; Json cycle_fact;
    if (QueryThreadCycleTime(thread.value, &cycles)) cycle_fact = observed(std::to_string(cycles), "QueryThreadCycleTime/held handle/raw CPU cycles");
    else { const auto code = GetLastError(); ++pager.failures; cycle_fact = failure("QueryThreadCycleTime/held handle", code, "Win32"); }
    // Only the exact held object's signaled state is reported, at this query.
    // Times were obtained earlier; do not turn an earlier undefined exit output
    // into evidence merely because the thread terminated between calls.
    const auto wait = WaitForSingleObject(thread.value, 0);
    Json termination;
    if (wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT)
        termination = observed(wait == WAIT_OBJECT_0, "WaitForSingleObject/held thread/zero timeout");
    else { const auto code = wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA; ++pager.failures;
        termination = failure("WaitForSingleObject/held thread", code, "Win32"); }
    return {{"state", "degraded"}, {"reference", std::move(reference)}, {"times", std::move(times)},
        {"reported_owner_pid", std::move(owner_fact)}, {"owner_process_reference", nullptr},
        {"owner_process_instance_verified", false}, {"priority", std::move(priority_fact)}, {"cpu_cycles", std::move(cycle_fact)},
        {"termination_observed", std::move(termination)}, {"consistency", "same_object_non_atomic_fields"},
        {"start_address", nullptr}, {"start_address_queried", false}};
}
}
Json collect_thread_inventory_pages(const std::string& host, const std::optional<std::string>& boot,
    const std::function<bool(Json)>& consumer, NativeInventoryLimits limits, const std::function<bool()>& cancelled) {
    if (host.empty() || (boot && boot->empty()) || !consumer || !limits.page_entries || limits.page_entries > 4096
        || limits.encoded_bytes < 4096 || limits.encoded_bytes > 512 * 1024 || !limits.total_entries || limits.total_entries > 65536
        || !limits.pages || limits.pages > 1024 || !limits.soft_budget_ms || limits.soft_budget_ms > 300000)
        throw std::invalid_argument("invalid thread inventory scope/bounds");
    Pager pager{limits, "thread_inventory", consumer, cancelled, "thread_state_version"};
    constexpr auto scope = "caller-visible Toolhelp thread descriptors and separate held-object queries; owner process instances, start addresses, interactions and continuous lifecycle unverified";
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    bool complete = false; Json enumeration_failure = nullptr;
    if (snapshot.value == INVALID_HANDLE_VALUE) {
        const auto code = GetLastError(); ++pager.failures;
        enumeration_failure = failure("CreateToolhelp32Snapshot/TH32CS_SNAPTHREAD", code, "Win32");
    } else {
        THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
        BOOL available = Thread32First(snapshot.value, &entry);
        for (;;) {
            if (!available) {
                const auto code = GetLastError(); complete = code == ERROR_NO_MORE_FILES;
                if (!complete) { ++pager.failures; enumeration_failure = failure("Thread32First/Next", code, "Win32"); }
                break;
            }
            if (!pager.active()) break;
            if (entry.dwSize < offsetof(THREADENTRY32, tpBasePri) + sizeof(entry.tpBasePri)) {
                ++pager.failures; enumeration_failure = failure("THREADENTRY32/short descriptor", ERROR_INVALID_DATA, "Win32"); break;
            }
            const auto started = GetTickCount64();
            auto held = query(entry.th32ThreadID, host, boot, pager);
            Json row{{"snapshot_descriptor", {{"tid", entry.th32ThreadID}, {"reported_owner_pid", entry.th32OwnerProcessID},
                {"reported_base_priority", entry.tpBasePri}, {"source", "THREADENTRY32"}}},
                {"later_tid_query", std::move(held)}, {"descriptor_instance_relation", "unverified; TID may have been reused before OpenThread"},
                {"query_started_uptime_ms", std::to_string(started)}, {"query_completed_uptime_ms", std::to_string(GetTickCount64())}};
            if (!pager.add(std::move(row))) break;
            entry = {}; entry.dwSize = sizeof(entry); available = Thread32Next(snapshot.value, &entry);
        }
    }
    auto result = pager.finish(scope, complete);
    result["enumeration_failure"] = std::move(enumeration_failure);
    result["resource_scope"] = "bounded application rows/pages; Toolhelp native snapshot allocation and API calls have no hard memory/time bound";
    result["thread_lifecycle_complete"] = false; result["owner_process_instances_verified"] = false;
    if (!result["enumeration_failure"].is_null() && result["entries_delivered"] == "0") result["state"] = "unavailable";
    return result;
}
}
