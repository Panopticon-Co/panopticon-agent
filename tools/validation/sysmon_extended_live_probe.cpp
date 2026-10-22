#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
#include <tlhelp32.h>
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <stdexcept>

using namespace panopticon::officer;
using Json = nlohmann::json;
namespace fs = std::filesystem;
namespace {
void save(const fs::path& path, const Json& value) {
    std::ofstream out(path, std::ios::binary); out << value.dump(2) << '\n';
    if (!out) throw std::runtime_error("evidence write failed");
}
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct OwnedChild {
    PROCESS_INFORMATION value{};
    ~OwnedChild() {
        // Only this invocation's retained child handle can be terminated.
        if (value.hProcess) {
            if (WaitForSingleObject(value.hProcess, 0) == WAIT_TIMEOUT) {
                TerminateProcess(value.hProcess, 0); WaitForSingleObject(value.hProcess, 5000);
            }
            CloseHandle(value.hProcess);
        }
        if (value.hThread) CloseHandle(value.hThread);
    }
};
LPTHREAD_START_ROUTINE child_exit_thread(DWORD pid) {
    const auto function = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread");
    HMODULE owner = nullptr;
    if (!function || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(function), &owner)) throw std::runtime_error("ExitThread module lookup failed");
    wchar_t path[32768]{};
    if (!GetModuleFileNameW(owner, path, 32768)) throw std::runtime_error("ExitThread module path unavailable");
    const auto basename = fs::path(path).filename().wstring();
    const auto offset = reinterpret_cast<std::uintptr_t>(function) - reinterpret_cast<std::uintptr_t>(owner);
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)};
    if (snapshot.value == INVALID_HANDLE_VALUE) throw std::runtime_error("owned child module snapshot failed");
    MODULEENTRY32W module{}; module.dwSize = sizeof(module);
    if (Module32FirstW(snapshot.value, &module)) do {
        if (_wcsicmp(module.szModule, basename.c_str()) == 0 && offset < module.modBaseSize)
            return reinterpret_cast<LPTHREAD_START_ROUTINE>(module.modBaseAddr + offset);
    } while (Module32NextW(snapshot.value, &module));
    throw std::runtime_error("system ExitThread module absent from owned child");
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view{argv[1]} == L"--owned-child") { Sleep(45000); return 0; }
    if (argc != 2) return 2;
    const auto output = fs::absolute(argv[1]); bool owned = false;
    try {
        if (!fs::create_directory(output)) throw std::runtime_error("new evidence directory required");
        owned = true;
        std::mutex mutex; std::condition_variable ready;
        std::map<unsigned, telemetry::RawSysmonExtendedEvent> captured;
        std::atomic<DWORD> child_pid{0}; std::string source_error, error;
        const auto pid = GetCurrentProcessId();
        collectors::SysmonEventCollector collector;
        if (!collector.start([&](telemetry::RawEvent event) {
            const auto* raw = std::get_if<telemetry::RawSysmonExtendedEvent>(&event);
            if (!raw || raw->process.pid != pid || (raw->event_id != 22 &&
                (!raw->target || !child_pid || raw->target->pid != child_pid.load()))) return;
            std::scoped_lock lock{mutex}; captured.try_emplace(raw->event_id, *raw); ready.notify_one();
        }, [&](std::string_view, std::string message) { std::scoped_lock lock{mutex}; source_error = std::move(message); }, error))
            throw std::runtime_error("Sysmon subscription failed: " + error);
        wchar_t executable[32768]{};
        if (!GetModuleFileNameW(nullptr, executable, 32768)) throw std::runtime_error("probe path unavailable");
        auto command = L"\"" + std::wstring{executable} + L"\" --owned-child";
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); OwnedChild child;
        if (!CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, output.c_str(), &startup, &child.value))
            throw std::runtime_error("owned child could not start");
        child_pid = child.value.dwProcessId;
        Sleep(500); // Let the same-bitness owned child's system DLLs initialize.
        Handle read_handle{OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, child_pid)};
        if (!read_handle.value) throw std::runtime_error("read-only owned child access failed");
        const auto entry = child_exit_thread(child_pid);
        Handle thread{CreateRemoteThread(child.value.hProcess, nullptr, 0, entry, nullptr, 0, nullptr)};
        if (!thread.value || WaitForSingleObject(thread.value, 5000) != WAIT_OBJECT_0)
            throw std::runtime_error("owned child ExitThread probe failed");
        // No executable allocation, remote writes, or payload: one system ExitThread call.
        PDNS_RECORD answers = nullptr;
        const auto dns_status = DnsQuery_W(L"www.example.com", DNS_TYPE_A,
            DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, nullptr, &answers, nullptr);
        if (answers) DnsRecordListFree(answers, DnsFreeRecordList);
        {
            std::unique_lock lock{mutex}; ready.wait_for(lock, std::chrono::seconds{30}, [&] { return captured.size() == 3; });
        }
        collector.stop();
        std::string boot_error;
        pipeline::NormalizationContext context{{"officer-live-validation", "sysmon-extended-probe"},
            {"validation-host", "validation-host", {"Windows", "live-validation"}}};
        pipeline::EndpointRecordFactory factory{context, "validation-only-device", std::string(64, 'b'), core::query_native_boot_id(boot_error), 1};
        Json records = Json::array(), ids = Json::object(), missing = Json::array();
        { delivery::DurableJournal journal{{output / "journal"}};
          for (const auto& [id, raw] : captured) {
              const auto record = factory.sysmon_extended(raw); journal.append(record.dump()); records.push_back(record);
              ids[std::to_string(id)] = raw.source.record_id ? Json(std::to_string(*raw.source.record_id)) : Json(nullptr);
          } }
        bool exact = true;
        { delivery::DurableJournal journal{{output / "journal"}}; const auto batch = journal.peek(10, 1024 * 1024);
          exact = records.empty() ? !batch : batch && batch->entries.size() == records.size();
          if (exact && batch) for (std::size_t i = 0; i < records.size(); ++i) exact &= batch->entries[i].body == records[i].dump(); }
        for (unsigned id : {8u,10u,22u}) if (!captured.contains(id)) missing.push_back(id);
        save(output / "canonical-records.json", records);
        const auto passed = exact && missing.empty();
        save(output / "report.json", {{"status", passed ? "passed" : "incomplete"}, {"synthetic", false},
            {"probe_pid", pid}, {"owned_child_pid", child_pid.load()}, {"native_record_ids", ids},
            {"missing_event_ids", missing}, {"dns_api_status", dns_status}, {"journal_restart_exact", exact},
            {"configuration_changed", false}, {"collector_error", source_error},
            {"scope", "own child only; read-only handle and system ExitThread; public example-domain DNS"}});
        return passed ? 0 : 3;
    } catch (const std::exception& error) {
        if (owned) try { save(output / "failure.json", {{"status", "failed"}, {"error", error.what()}}); } catch (...) {}
        return 1;
    }
}
