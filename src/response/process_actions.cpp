#include "panopticon/officer/response/process_actions.hpp"
#include "panopticon/officer/core/process_instance.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <vector>

namespace panopticon::officer::response {

namespace {

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueHandle() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_;
};

std::uint64_t filetime_to_ticks(const FILETIME& time) {
    ULARGE_INTEGER value{};
    value.LowPart = time.dwLowDateTime;
    value.HighPart = time.dwHighDateTime;
    return value.QuadPart;
}

std::optional<telemetry::UtcTimestamp> ticks_to_utc(std::uint64_t filetime_ticks) {
    constexpr std::uint64_t unix_epoch_in_filetime_ticks = 116'444'736'000'000'000ULL;
    if (filetime_ticks < unix_epoch_in_filetime_ticks) return std::nullopt;
    const std::uint64_t unix_ticks = filetime_ticks - unix_epoch_in_filetime_ticks;
    if (unix_ticks > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() / 100)) return std::nullopt;
    return telemetry::UtcTimestamp{std::chrono::nanoseconds{static_cast<std::int64_t>(unix_ticks * 100)}};
}

std::string lowered_base_name(const std::string& path) {
    const auto separator = path.find_last_of("\\/");
    std::string base = separator == std::string::npos ? path : path.substr(separator + 1);
    std::transform(base.begin(), base.end(), base.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return base;
}

std::optional<std::string> query_full_image_path(HANDLE process, std::optional<std::uint32_t>* native_error = nullptr) {
    if (native_error) native_error->reset();
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        const DWORD failure = GetLastError();
        if (native_error) *native_error = failure;
        return std::nullopt;
    }
    if (size == 0) return std::nullopt;
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(),
                                              static_cast<int>(size), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        const DWORD failure = GetLastError();
        if (native_error) *native_error = failure;
        return std::nullopt;
    }
    std::string utf8(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(), static_cast<int>(size), utf8.data(),
                             required, nullptr, nullptr) != required) {
        const DWORD failure = GetLastError();
        if (native_error) *native_error = failure;
        return std::nullopt;
    }
    return utf8;
}

std::optional<std::uint32_t> toolhelp_parent_pid(std::uint32_t pid) {
    UniqueHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snapshot.get() == INVALID_HANDLE_VALUE) return std::nullopt;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) return std::nullopt;
    do {
        if (entry.th32ProcessID == pid) return static_cast<std::uint32_t>(entry.th32ParentProcessID);
    } while (Process32NextW(snapshot.get(), &entry));
    return std::nullopt;
}

const char* stage_name(ProcessTerminationStage stage) {
    switch (stage) {
        case ProcessTerminationStage::preflight: return "preflight";
        case ProcessTerminationStage::boot: return "boot";
        case ProcessTerminationStage::open: return "open";
        case ProcessTerminationStage::identity: return "identity";
        case ProcessTerminationStage::image: return "image";
        case ProcessTerminationStage::critical: return "critical";
        case ProcessTerminationStage::protection: return "protection";
        case ProcessTerminationStage::liveness: return "liveness";
        case ProcessTerminationStage::initiate: return "initiate";
        case ProcessTerminationStage::completion: return "completion";
    }
    return "unknown";
}

}  // namespace

std::optional<ProcessObservation> reobserve_process(const ProcessTarget& target, std::string& error_message) {
    error_message.clear();
    if (!target.boot_id) {
        error_message = "boot-bound process target required; legacy process action refused";
        return std::nullopt;
    }
    const auto current_boot = core::query_native_boot_id(error_message);
    if (!current_boot || *current_boot != *target.boot_id) {
        error_message = "process target boot does not match verified current native boot";
        return std::nullopt;
    }
    if (target.pid == 0U || target.start_time_ticks == 0U) {
        error_message = "process target is invalid";
        return std::nullopt;
    }
    UniqueHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.pid)};
    if (process.get() == nullptr) {
        error_message = "process no longer exists or cannot be opened for query";
        return std::nullopt;
    }
    FILETIME creation{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    if (!GetProcessTimes(process.get(), &creation, &exit_time, &kernel_time, &user_time)) {
        error_message = "cannot read process creation time for re-observation";
        return std::nullopt;
    }
    const std::uint64_t observed_creation_ticks = filetime_to_ticks(creation);
    if (observed_creation_ticks != target.start_time_ticks) {
        // This is the PID-reuse defense: the PID number matches but the
        // process behind it today is provably not the one the command
        // named.
        error_message = "process identity no longer matches (PID has been reused)";
        return std::nullopt;
    }

    ProcessObservation observation;
    observation.pid = target.pid;
    observation.creation_time_ticks = observed_creation_ticks;
    observation.parent_pid = toolhelp_parent_pid(target.pid);
    observation.executable_path = query_full_image_path(process.get());
    if (observation.executable_path) {
        observation.image_base_name = lowered_base_name(*observation.executable_path);
    }
    return observation;
}

telemetry::RawProcessEvent to_raw_process_event(const ProcessObservation& observation) {
    telemetry::RawProcessEvent raw;
    raw.source.kind = telemetry::TelemetrySourceKind::etw;
    raw.source.provider = "Officer-Response-Reobservation";
    raw.pid = observation.pid;
    raw.parent_pid = observation.parent_pid;
    raw.executable = observation.executable_path;
    raw.start_time_ticks = observation.creation_time_ticks;
    const auto utc = ticks_to_utc(observation.creation_time_ticks);
    raw.process_start_time = utc.value_or(telemetry::UtcTimestamp{});
    return raw;
}

ProcessTerminationResult terminate_process(const ProcessTarget& target) {
    using State = ProcessTerminationState;
    using Stage = ProcessTerminationStage;
    const auto stop = [](State state, Stage stage, std::string summary,
                         std::optional<std::uint32_t> native_error = std::nullopt) {
        return ProcessTerminationResult{state, stage, false, false, native_error, std::move(summary)};
    };
    if (!target.pid || !target.start_time_ticks || target.pid == GetCurrentProcessId() || is_protected_process(target.pid, "")) {
        return stop(State::refused, Stage::preflight, "target is invalid, protected, or the endpoint process itself");
    }
    if (!target.boot_id) {
        return stop(State::refused, Stage::boot, "boot-bound process target required; legacy process action refused");
    }
    std::string error_message;
    const auto current_boot = core::query_native_boot_id(error_message);
    if (!current_boot) return stop(State::failed, Stage::boot, "native boot verification unavailable: " + error_message);
    if (*current_boot != *target.boot_id)
        return stop(State::refused, Stage::boot, "process target boot does not match verified current native boot");
    // A held handle names the kernel object, not whichever process later owns
    // this PID. Every identity/protection check and the action uses this handle.
    UniqueHandle process{OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, target.pid)};
    if (process.get() == nullptr) {
        const DWORD failure = GetLastError();
        return stop(State::failed, Stage::open, "cannot open process for termination", failure);
    }
    FILETIME creation{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    if (!GetProcessTimes(process.get(), &creation, &exit_time, &kernel_time, &user_time)) {
        const DWORD failure = GetLastError();
        return stop(State::failed, Stage::identity, "cannot read held process creation token", failure);
    }
    if (filetime_to_ticks(creation) != target.start_time_ticks)
        return stop(State::refused, Stage::identity, "held process creation token does not match requested instance");
    std::optional<std::uint32_t> image_error;
    const auto image = query_full_image_path(process.get(), &image_error);
    if (!image || image->empty()) {
        return stop(State::failed, Stage::image, "target image could not be verified; termination refused", image_error);
    }
    if (is_protected_process(target.pid, lowered_base_name(*image))) {
        return stop(State::refused, Stage::image, "target image is protected");
    }
    using CriticalQuery = BOOL(WINAPI*)(HANDLE, PBOOL);
    const auto query = reinterpret_cast<CriticalQuery>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
    BOOL critical = FALSE;
    if (!query) return stop(State::failed, Stage::critical, "critical-process API unavailable; termination refused", ERROR_PROC_NOT_FOUND);
    if (!query(process.get(), &critical)) {
        const DWORD failure = GetLastError();
        return stop(State::failed, Stage::critical, "critical-process status could not be verified; termination refused", failure);
    }
    if (critical) {
        return stop(State::refused, Stage::critical, "Windows reports a critical process; termination refused");
    }
    using ProtectionQuery = BOOL(WINAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
    const auto protection_query = reinterpret_cast<ProtectionQuery>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessInformation"));
    PROCESS_PROTECTION_LEVEL_INFORMATION protection{};
    if (!protection_query)
        return stop(State::failed, Stage::protection, "process protection API unavailable; termination refused", ERROR_PROC_NOT_FOUND);
    if (!protection_query(process.get(), ProcessProtectionLevelInfo, &protection, sizeof(protection))) {
        const DWORD failure = GetLastError();
        return stop(State::failed, Stage::protection, "process protection level could not be verified; termination refused", failure);
    }
    if (protection.ProtectionLevel != PROTECTION_LEVEL_NONE) {
        return stop(State::refused, Stage::protection, "Windows reports a protected or unknown protection level; termination refused");
    }
    const auto before = WaitForSingleObject(process.get(), 0);
    if (before != WAIT_TIMEOUT) {
        if (before == WAIT_OBJECT_0)
            return stop(State::refused, Stage::liveness, "target already exited; no termination performed");
        const auto native_error = before == WAIT_FAILED ? std::optional<std::uint32_t>{GetLastError()} : std::nullopt;
        return stop(State::failed, Stage::liveness, "target lifetime state could not be verified", native_error);
    }
    if (!TerminateProcess(process.get(), /*exit_code=*/1)) {
        const DWORD failure = GetLastError();
        return stop(State::failed, Stage::initiate, "TerminateProcess failed", failure);
    }
    const auto completed = WaitForSingleObject(process.get(), 5000);
    const auto native_error = completed == WAIT_FAILED ? std::optional<std::uint32_t>{GetLastError()} : std::nullopt;
    return detail::termination_completion(completed, native_error);
}

ProcessTerminationResult detail::termination_completion(std::uint32_t wait_status,
                                                        std::optional<std::uint32_t> native_error) {
    if (wait_status == WAIT_OBJECT_0)
        return {ProcessTerminationState::succeeded, ProcessTerminationStage::completion, true, true,
            std::nullopt, "termination initiated and held process exit observed"};
    const char* summary = wait_status == WAIT_TIMEOUT ? "termination initiated; bounded wait expired without observing exit"
        : wait_status == WAIT_FAILED ? "termination initiated; exit observation failed"
        : "termination initiated; unexpected exit observation status";
    return {ProcessTerminationState::indeterminate, ProcessTerminationStage::completion, true, false,
        wait_status == WAIT_FAILED ? native_error : std::nullopt, summary};
}

CommandReceipt termination_receipt(const ProcessTerminationResult& result,
                                   const std::string& command_id, const std::string& correlation_id) {
    ReceiptCode code = ReceiptCode::execution_failed;
    switch (result.state) {
        case ProcessTerminationState::refused: code = ReceiptCode::target_mismatch; break;
        case ProcessTerminationState::failed: code = ReceiptCode::execution_failed; break;
        case ProcessTerminationState::succeeded: code = ReceiptCode::succeeded; break;
        case ProcessTerminationState::indeterminate: code = ReceiptCode::indeterminate; break;
    }
    const auto declared_code = code;
    // Do not let an inconsistent result claim success or definite failure after
    // initiation without observed completion. Unknown completion stays uncertain.
    if ((result.action_initiated && !result.completion_observed) ||
        (code == ReceiptCode::succeeded && (!result.action_initiated || !result.completion_observed)))
        code = ReceiptCode::indeterminate;
    std::string summary = std::string{"kill_process stage="} + stage_name(result.stage) +
        " action_initiated=" + (result.action_initiated ? "true" : "false") +
        " completion_observed=" + (result.completion_observed ? "true" : "false");
    if (result.native_error) summary += " windows_error=" + std::to_string(*result.native_error);
    CommandReceipt receipt{command_id, correlation_id, code, summary + ": " + result.summary};
    // Inconsistent internal facts cannot supply conclusive structured evidence.
    // Preserve uncertainty in outcome/detail while omitting this representation.
    const bool consistent = result.completion_observed
        ? result.action_initiated && code == ReceiptCode::succeeded && !result.native_error
        : result.action_initiated ? code == ReceiptCode::indeterminate : code != ReceiptCode::indeterminate;
    if (consistent && code == declared_code &&
        (!result.native_error || code == ReceiptCode::execution_failed || code == ReceiptCode::indeterminate) &&
        (result.action_initiated == (result.stage == ProcessTerminationStage::completion)) &&
        std::string_view{stage_name(result.stage)} != "unknown")
        receipt.execution = ProcessExecutionEvidence{stage_name(result.stage), result.action_initiated,
            result.completion_observed, result.native_error};
    return receipt;
}

}  // namespace panopticon::officer::response
