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

// KILL_PROCESS: one held query/terminate/synchronize handle binds creation-token,
// required image and native critical/protection checks to the same kernel object.
// Refuses protected/self targets and unknown safety facts. Succeeded means observed
// exit, not merely TerminateProcess acceptance. A five-second wait timeout is
// indeterminate and does not prove the process survived. Current native boot
// must match the explicit target boot; missing boot refuses both process actions.
enum class ProcessTerminationState { refused, failed, succeeded, indeterminate };
enum class ProcessTerminationStage { preflight, boot, open, identity, image, critical, protection, liveness, initiate, completion };
struct ProcessTerminationResult {
    ProcessTerminationState state = ProcessTerminationState::refused;
    ProcessTerminationStage stage = ProcessTerminationStage::preflight;
    bool action_initiated = false;
    bool completion_observed = false;
    std::optional<std::uint32_t> native_error;
    std::string summary;
};
[[nodiscard]] ProcessTerminationResult terminate_process(const ProcessTarget& target);
[[nodiscard]] CommandReceipt termination_receipt(const ProcessTerminationResult& result,
    const std::string& command_id, const std::string& correlation_id);

namespace detail {
// Classifies only the completion wait AFTER a successful TerminateProcess call.
// Kept separate to exercise timeout/error paths without harming real targets.
[[nodiscard]] ProcessTerminationResult termination_completion(std::uint32_t wait_status,
    std::optional<std::uint32_t> native_error = std::nullopt);
}

}  // namespace panopticon::officer::response
