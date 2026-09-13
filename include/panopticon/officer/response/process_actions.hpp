#pragma once

#include "panopticon/officer/response/command.hpp"
#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::response {

// A fresh, live re-observation of a single process by PID -- never trusted
// from the command, always re-queried from the OS at handler-execution
// time. This is the PID-reuse defense: a command that named PID 4242 with
// start_time_ticks X must be refused if PID 4242 is now a *different*
// process (a different creation time) even though the PID number matches.
struct ProcessObservation {
    std::uint32_t pid = 0;
    std::uint64_t creation_time_ticks = 0;  // FILETIME 100ns ticks since 1601-01-01, from GetProcessTimes.
    std::optional<std::uint32_t> parent_pid;
    std::optional<std::string> executable_path;  // Full path from QueryFullProcessImageNameW, if obtainable.
    std::string image_base_name;                 // Lowercased file-name component of executable_path, or empty.
};

// Re-observes exactly the requested pid via Toolhelp32 (for parent pid and a
// fallback image name) plus OpenProcess+GetProcessTimes+
// QueryFullProcessImageNameW (for the authoritative creation time and full
// path). Returns std::nullopt (with error_message set) if the process does
// not exist, cannot be opened even for query-limited access, or its
// creation time does not match target.start_time_ticks -- the last case is
// the actual PID-reuse defense and must never be bypassed.
[[nodiscard]] std::optional<ProcessObservation> reobserve_process(const ProcessTarget& target,
                                                                   std::string& error_message);

// Builds a Schema 0.2/0.3-shaped RawProcessEvent from a fresh observation,
// for COLLECT_PROCESS_INFO to hand to the existing normalizer/serializer
// pipeline (panopticon::officer::pipeline) rather than inventing a second
// wire format.
[[nodiscard]] telemetry::RawProcessEvent to_raw_process_event(const ProcessObservation& observation);

// KILL_PROCESS: re-observes the PID/creation-time tuple (defeats PID
// reuse), refuses PID 0/4 and the hardcoded critical-process image list
// (see command.hpp's is_protected_process), and only then calls
// TerminateProcess. Returns true on success, std::nullopt (with
// error_message) on any refusal or Win32 failure.
[[nodiscard]] std::optional<bool> terminate_process(const ProcessTarget& target, std::string& error_message);

}  // namespace panopticon::officer::response
