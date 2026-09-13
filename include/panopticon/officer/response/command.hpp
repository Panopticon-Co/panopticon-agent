#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::officer::response {

// The same closed, 7-action vocabulary as response_engine.contract.ACTIONS
// (Manager/Python) and panopticon-linux-agent's action_type. Do not add an
// 8th action or a generic/arbitrary-exec action -- see
// docs/RESPONSE_ENGINE_STATE.md in panopticon-manager for why this is
// closed by design.
enum class ActionType : std::uint8_t {
    kill_process,
    collect_process_info,
    collect_network_connections,
    collect_file,
    quarantine_file,
    isolate_host,
    release_host_isolation,
};

// Windows equivalent of the Linux agent's process_identity: pid plus a
// tamper-resistant "start time" tuple that defends against PID reuse. On
// Windows this is the process creation time as a Win32 FILETIME, expressed
// as the 64-bit tick count (100ns intervals since 1601-01-01), which is
// exactly what GetProcessTimes() returns -- no unit conversion needed at the
// handler call site.
struct ProcessTarget {
    std::string host_id;
    std::uint32_t pid = 0;
    std::uint64_t start_time_ticks = 0;

    [[nodiscard]] bool operator==(const ProcessTarget&) const = default;
};

struct Command {
    std::string command_id;
    std::string agent_id;
    std::string host_id;
    std::string schema_version;
    std::string correlation_id;
    ActionType action{};
    std::int64_t expires_at_epoch_seconds = 0;
    ProcessTarget process_target;
    // Populated only for collect_file / quarantine_file; empty otherwise.
    std::string file_target_path;
};

enum class ReceiptCode : std::uint8_t {
    succeeded,
    invalid_command,
    expired,
    replay_detected,
    target_mismatch,
    target_protected,
    unsupported_action,
    execution_failed,
};

struct CommandReceipt {
    std::string command_id;
    std::string correlation_id;
    ReceiptCode code = ReceiptCode::invalid_command;
    std::string summary;
};

// Decodes only the Manager's closed schema-1 command envelope: an exact,
// known top-level key set (command_id, agent_id, host_id, schema_version,
// action, expires_at, created_at, correlation_id, target); a `target` whose
// shape is fully determined by `action` (process actions: exactly {pid,
// start_time_ticks}, both positive integers; file actions: exactly {path},
// a non-empty bounded string; every other action: an empty object); UTC-only
// RFC 3339 timestamps (a 'Z' or '+00:00' suffix -- any other offset, or a
// naive local time, is rejected); and created_at strictly before expires_at.
// Unknown actions, unknown top-level fields, or a target shape that doesn't
// match the action are all rejected rather than tolerated.
[[nodiscard]] std::optional<Command> parse_command_json(std::string_view payload, std::string& error_message);

// Decodes the `{"commands": [...]}` poll response, bounded to
// maximum_commands entries.
[[nodiscard]] std::optional<std::vector<Command>> parse_command_poll_response(
    std::string_view payload, std::size_t maximum_commands, std::string& error_message);

[[nodiscard]] std::optional<std::string> serialize_command_result(
    const CommandReceipt& receipt, std::size_t maximum_bytes, std::string& error_message);

// Enforces idempotency/replay/expiry/target-protection exactly once per
// command, backed by an optional durable ReplayLedger so a restart cannot
// re-execute a command a prior process crash interrupted mid-handler.
class CommandGate {
public:
    CommandGate(std::string agent_id, std::string host_id, std::function<std::int64_t()> clock_epoch_seconds,
                class ReplayLedger* durable_ledger = nullptr);

    [[nodiscard]] CommandReceipt validate_and_mark(const Command& command);

private:
    std::string agent_id_;
    std::string host_id_;
    std::function<std::int64_t()> clock_epoch_seconds_;
    ReplayLedger* durable_ledger_;
    std::mutex mutex_;
    std::set<std::string> seen_;
};

// True for PID 0/4 and for any process whose current image name (re-checked
// live, never trusted from the command) matches a hardcoded critical-system
// list: System, csrss.exe, wininit.exe, services.exe, lsass.exe, smss.exe.
// image_name may be empty (e.g. access denied) -- in that case only the PID
// check applies, so a protected image is never accidentally treated as safe
// just because it couldn't be re-observed; callers must separately fail
// closed when the image name can't be obtained at all for KILL_PROCESS (see
// process_actions.cpp).
[[nodiscard]] bool is_protected_process(std::uint32_t pid, std::string_view image_name) noexcept;

}  // namespace panopticon::officer::response
