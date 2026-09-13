#include "panopticon/officer/response/process_actions.hpp"

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

std::optional<std::string> query_full_image_path(HANDLE process) {
    std::vector<wchar_t> buffer(4096);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size) || size == 0) return std::nullopt;
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(),
                                              static_cast<int>(size), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return std::nullopt;
    std::string utf8(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(), static_cast<int>(size), utf8.data(),
                             required, nullptr, nullptr) != required) {
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

}  // namespace

std::optional<ProcessObservation> reobserve_process(const ProcessTarget& target, std::string& error_message) {
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
    const auto utc = ticks_to_utc(observation.creation_time_ticks);
    raw.process_start_time = utc.value_or(telemetry::UtcTimestamp{});
    return raw;
}

std::optional<bool> terminate_process(const ProcessTarget& target, std::string& error_message) {
    auto observation = reobserve_process(target, error_message);
    if (!observation) return std::nullopt;
    if (is_protected_process(observation->pid, observation->image_base_name)) {
        error_message = "target is a protected process";
        return std::nullopt;
    }
    // KILL_PROCESS specifically needs PROCESS_TERMINATE, which
    // reobserve_process deliberately does not request (query-only handles
    // are used for every other action so this file's read paths stay least-
    // privilege); re-open with the elevated access right only here, after
    // every safety check above has already passed against the query-only
    // handle.
    UniqueHandle process{OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.pid)};
    if (process.get() == nullptr) {
        error_message = "cannot open process for termination";
        return std::nullopt;
    }
    // TOCTOU note: a PID could theoretically be reused again between the
    // GetProcessTimes() check above and this OpenProcess() call. There is
    // no atomic "terminate iff creation time == X" Win32 primitive; a final
    // best-effort re-check of the creation time on the freshly reopened
    // handle narrows (does not eliminate) this window before terminating.
    FILETIME creation{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    if (!GetProcessTimes(process.get(), &creation, &exit_time, &kernel_time, &user_time) ||
        filetime_to_ticks(creation) != target.start_time_ticks) {
        error_message = "process identity changed between re-observation and termination";
        return std::nullopt;
    }
    if (!TerminateProcess(process.get(), /*exit_code=*/1)) {
        error_message = "TerminateProcess failed";
        return std::nullopt;
    }
    return true;
}

}  // namespace panopticon::officer::response
