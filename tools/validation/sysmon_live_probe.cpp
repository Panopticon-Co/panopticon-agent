#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>

using namespace panopticon::officer;
using Json = nlohmann::json;
namespace fs = std::filesystem;
namespace {
void save(const fs::path& path, const Json& value) {
    std::ofstream output(path, std::ios::binary);
    output << value.dump(2) << '\n';
    if (!output) throw std::runtime_error("cannot save live evidence");
}
struct Child {
    PROCESS_INFORMATION native{};
    ~Child() {
        if (native.hThread) CloseHandle(native.hThread);
        if (native.hProcess) CloseHandle(native.hProcess);
    }
};
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) { std::cerr << "Usage: officer-sysmon-live-probe <new-evidence-directory>\n"; return 2; }
    const fs::path output = fs::absolute(argv[1]);
    bool owned_directory = false;
    try {
        if (!fs::create_directory(output)) throw std::runtime_error("evidence directory must be newly owned");
        owned_directory = true;
        const auto marker = "officer-sysmon-live-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
        std::mutex mutex;
        std::condition_variable ready;
        std::optional<telemetry::RawProcessEvent> captured;
        std::string source_error;
        collectors::SysmonEventCollector collector;
        std::string error;
        if (!collector.start([&](telemetry::RawEvent event) {
                const auto* process = std::get_if<telemetry::RawProcessEvent>(&event);
                if (!process || process->terminated || !process->command_line ||
                    process->command_line->find(marker) == std::string::npos) return;
                std::scoped_lock lock{mutex};
                if (!captured) captured = *process;
                ready.notify_one();
            }, [&](std::string_view, std::string message) {
                std::scoped_lock lock{mutex}; source_error = std::move(message);
            }, error)) throw std::runtime_error("live Sysmon subscription failed: " + error);
        wchar_t system_directory[MAX_PATH]{};
        const auto length = GetSystemDirectoryW(system_directory, MAX_PATH);
        if (!length || length >= MAX_PATH) throw std::runtime_error("system directory unavailable");
        const fs::path executable = fs::path(system_directory) / L"cmd.exe";
        const std::wstring wide_marker(marker.begin(), marker.end());
        auto command = L"\"" + executable.wstring() + L"\" /d /c echo " + wide_marker;
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        Child child;
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, output.c_str(), &startup, &child.native))
            throw std::runtime_error("owned benign process could not start");
        if (WaitForSingleObject(child.native.hProcess, 10000) != WAIT_OBJECT_0) {
            TerminateProcess(child.native.hProcess, 98);
            WaitForSingleObject(child.native.hProcess, 5000);
            throw std::runtime_error("owned benign process did not exit promptly");
        }
        {
            std::unique_lock lock{mutex};
            ready.wait_for(lock, std::chrono::seconds{20}, [&] { return captured.has_value(); });
        }
        collector.stop();
        if (!captured) throw std::runtime_error("no matching live EID1 within 20 seconds; " + source_error);
        if (captured->pid != child.native.dwProcessId || !captured->sysmon_fields || !captured->source.record_id)
            throw std::runtime_error("captured event does not bind to the owned process/source record");
        char hostname[MAX_COMPUTERNAME_LENGTH + 1]{}; DWORD host_length = sizeof(hostname);
        if (!GetComputerNameA(hostname, &host_length)) throw std::runtime_error("host name unavailable");
        // Probe-local envelope identity, not a production enrollment or response target.
        pipeline::NormalizationContext context{{"officer-live-validation", "5501139-probe"},
            {hostname, hostname, {"Windows", "live-validation"}}};
        enrichment::EnrichedProcessEvent enriched;
        enriched.raw = *captured; enriched.sha256 = captured->sha256;
        const auto normalized = pipeline::normalize_process_event(enriched, context, error);
        if (!normalized) throw std::runtime_error("live event normalization failed: " + error);
        const auto boot = core::query_native_boot_id(error);
        pipeline::EndpointRecordFactory factory{context, "validation-only-device", std::string(64, 'b'), boot, 1};
        const auto record = factory.observation(telemetry::RawEvent{*captured}, *normalized);
        const auto body = record.dump();
        { delivery::DurableJournal journal{{output / "journal"}}; journal.append(body); }
        bool recovered = false;
        { delivery::DurableJournal journal{{output / "journal"}};
          const auto batch = journal.peek(10, 1024 * 1024);
          recovered = batch && batch->protocol == 2 && batch->entries.size() == 1 && batch->entries[0].body == body; }
        save(output / "canonical-record.json", record);
        const auto& facts = record.at("data").at("source_facts").at("process").at("sysmon_fields");
        const auto& fields = facts.at("fields");
        const bool required = !fields.at("ParentCommandLine").is_null() &&
            !fields.at("IntegrityLevel").is_null() && !fields.at("OriginalFileName").is_null();
        Json report{{"status", recovered && required ? "passed" : "failed"},
            {"capture", "native_SysmonEventCollector_live_subscription"}, {"synthetic", false},
            {"marker", marker}, {"owned_process_id", child.native.dwProcessId},
            {"native_record_id", std::to_string(*captured->source.record_id)},
            {"process_guid", captured->process_guid ? Json(*captured->process_guid) : Json(nullptr)},
            {"host", hostname}, {"identity_scope", "probe_local_not_production_enrollment"},
            {"fields", fields}, {"unavailable", facts.at("unavailable")},
            {"journal_restart_exact", recovered}, {"native_creation_ticks_derived", false},
            {"collector_error", source_error.empty() ? Json(nullptr) : Json(source_error)}};
        save(output / "report.json", report);
        std::cout << report.dump() << '\n';
        return recovered && required ? 0 : 1;
    } catch (const std::exception& error) {
        if (owned_directory) {
            try { save(output / "failure.json", {{"status", "failed"}, {"error", error.what()}, {"synthetic", false}}); } catch (...) {}
        }
        std::cerr << error.what() << '\n'; return 1;
    }
}
