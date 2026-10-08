#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/collectors/windows_event_log.hpp"
#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/uploader.hpp"
#include "panopticon/officer/health/coverage.hpp"
#include "panopticon/officer/health/state_freshness.hpp"
#include "panopticon/officer/state/security_center.hpp"
#include "panopticon/officer/state/defender_status.hpp"
#include "panopticon/officer/state/device_guard.hpp"
#include "panopticon/officer/state/persistence_inventory.hpp"
#include "panopticon/officer/state/identity_inventory.hpp"
#include "panopticon/officer/state/software_inventory.hpp"
#include "panopticon/officer/runtime/service_host.hpp"
#include "panopticon/officer/health/source_supervisor.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include "panopticon/officer/pipeline/serializer.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/state/host_inventory.hpp"
#include "panopticon/officer/telemetry/panopticon_event.hpp"
#include "panopticon/officer/response/command.hpp"
#include "panopticon/officer/response/config.hpp"
#include "panopticon/officer/response/file_evidence.hpp"
#include "panopticon/officer/response/identity.hpp"
#include "panopticon/officer/response/isolation.hpp"
#include "panopticon/officer/response/network_evidence.hpp"
#include "panopticon/officer/response/process_actions.hpp"
#include "panopticon/officer/response/replay_ledger.hpp"
#include "panopticon/officer/response/transport.hpp"
#include "panopticon/officer/response/result_outbox.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/pipeline/raw_handoff.hpp"
#include "panopticon/officer/pipeline/diagnostic_output.hpp"
#include "panopticon/officer/state/process_inventory.hpp"
#include "panopticon/officer/state/thread_inventory.hpp"
#include "panopticon/officer/state/memory_inventory.hpp"
#include "panopticon/officer/collectors/usn_journal.hpp"
#include "panopticon/officer/state/service_inventory.hpp"
#include "panopticon/officer/state/driver_inventory.hpp"
#include "panopticon/officer/state/socket_inventory.hpp"
#include "panopticon/officer/state/route_inventory.hpp"
#include "panopticon/officer/state/ip_interface_inventory.hpp"
#include "panopticon/officer/state/firewall_profiles.hpp"
#include "panopticon/officer/state/firewall_rules.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <array>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace {

namespace collectors = panopticon::officer::collectors;
namespace delivery = panopticon::officer::delivery;
namespace enrichment = panopticon::officer::enrichment;
namespace pipeline = panopticon::officer::pipeline;
namespace response = panopticon::officer::response;
namespace telemetry = panopticon::officer::telemetry;

enum class SourceSelection { all, etw, sysmon };

// Durable journal acceptance precedes best-effort diagnostic display.
// --manager-url adds delivery; stdout is not an acceptance receipt.
//
// Response (command polling/execution) is a second, independent opt-in on
// top of that: --enable-response requires --manager-url and does nothing at
// all unless explicitly passed, so every existing telemetry-only deployment
// is unaffected.
struct CliOptions {
    SourceSelection source = SourceSelection::all;
    std::optional<std::string> manager_url;
    std::string spool_directory = "spool";
    bool insecure_tls = false;
    bool enable_response = false;
    std::string identity_path = "officer-identity.txt";
    std::string keypair_path = "officer-identity.key";
    std::string bootstrap_token_path;
    std::string replay_ledger_path = "officer-response-ledger.txt";
    std::string file_collection_root;
    std::string quarantine_root;
    std::string manager_exception_host;
    unsigned manager_exception_port = 0;
    unsigned response_poll_interval_ms = 15000;
};

std::atomic<HANDLE> shutdown_event{nullptr};

BOOL WINAPI console_control_handler(DWORD control_type) {
    if (control_type == CTRL_C_EVENT || control_type == CTRL_BREAK_EVENT ||
        control_type == CTRL_CLOSE_EVENT || control_type == CTRL_SHUTDOWN_EVENT) {
        if (const HANDLE event = shutdown_event.load(); event != nullptr) {
            SetEvent(event);
        }
        return TRUE;
    }
    return FALSE;
}

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueHandle() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_;
};

std::optional<std::string> utf16_to_utf8(std::wstring_view text, std::string& error_message) {
    if (text.empty()) {
        return std::string{};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        error_message = "A Windows identity value is too large to convert.";
        return std::nullopt;
    }
    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        text.data(),
        static_cast<int>(text.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        error_message = "Could not convert Windows runtime metadata to UTF-8.";
        return std::nullopt;
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            required,
            nullptr,
            nullptr) != required) {
        error_message = "Could not convert Windows runtime metadata to UTF-8.";
        return std::nullopt;
    }
    return result;
}

std::optional<std::wstring> registry_string(
    const wchar_t* key,
    const wchar_t* value_name,
    std::string& error_message) {
    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE, key, value_name, RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS || bytes < sizeof(wchar_t)) {
        error_message = "Could not read required Windows registry metadata.";
        return std::nullopt;
    }
    std::vector<wchar_t> buffer(
        (static_cast<std::size_t>(bytes) + sizeof(wchar_t) - 1) / sizeof(wchar_t));
    status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        key,
        value_name,
        RRF_RT_REG_SZ,
        nullptr,
        buffer.data(),
        &bytes);
    if (status != ERROR_SUCCESS) {
        error_message = "Could not read required Windows registry metadata.";
        return std::nullopt;
    }
    std::size_t length = buffer.size();
    while (length != 0 && buffer[length - 1] == L'\0') {
        --length;
    }
    return std::wstring{buffer.data(), length};
}

std::optional<std::wstring> computer_name(std::string& error_message) {
    DWORD characters = 0;
    GetComputerNameExW(ComputerNameDnsHostname, nullptr, &characters);
    if (GetLastError() != ERROR_MORE_DATA || characters == 0) {
        error_message = "Could not determine the Windows hostname.";
        return std::nullopt;
    }
    std::vector<wchar_t> buffer(characters);
    if (!GetComputerNameExW(ComputerNameDnsHostname, buffer.data(), &characters)) {
        error_message = "Could not determine the Windows hostname.";
        return std::nullopt;
    }
    return std::wstring{buffer.data(), characters};
}

std::optional<pipeline::NormalizationContext> runtime_context(std::string& error_message) {
    constexpr wchar_t machine_key[] = L"SOFTWARE\\Microsoft\\Cryptography";
    constexpr wchar_t windows_key[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    const auto machine_guid = registry_string(machine_key, L"MachineGuid", error_message);
    const auto hostname = computer_name(error_message);
    const auto product_name = registry_string(windows_key, L"ProductName", error_message);
    const auto build = registry_string(windows_key, L"CurrentBuildNumber", error_message);
    if (!machine_guid || !hostname || !product_name || !build) {
        return std::nullopt;
    }

    const auto machine_guid_utf8 = utf16_to_utf8(*machine_guid, error_message);
    const auto hostname_utf8 = utf16_to_utf8(*hostname, error_message);
    const auto product_name_utf8 = utf16_to_utf8(*product_name, error_message);
    const auto build_utf8 = utf16_to_utf8(*build, error_message);
    if (!machine_guid_utf8 || !hostname_utf8 || !product_name_utf8 || !build_utf8) {
        return std::nullopt;
    }

    pipeline::NormalizationContext context;
    context.agent = {"officer-" + *machine_guid_utf8, telemetry::kAgentVersion};
    context.host = {
        *machine_guid_utf8,
        *hostname_utf8,
        {*product_name_utf8, *build_utf8},
    };
    return context;
}

bool process_is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    UniqueHandle token_handle{token};
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    return GetTokenInformation(
               token,
               TokenElevation,
               &elevation,
               sizeof(elevation),
               &returned) != FALSE &&
           elevation.TokenIsElevated != 0;
}

std::optional<CliOptions> parse_arguments(int argc, char* argv[]) {
    CliOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            std::cout << "Usage: " << argv[0]
                      << " [--service] [--source all|etw|sysmon] [--manager-url <https-url>] [--insecure-tls]\n"
                         "       [--enable-response] [--identity-path <path>] [--bootstrap-token-path <path>]\n"
                         "       [--file-collection-root <dir>] [--quarantine-root <dir>]\n"
                         "       [--manager-exception-host <ip>] [--manager-exception-port <port>]\n"
                      << "  --source                  Select live collectors (default: all).\n"
                      << "  --manager-url             Also deliver events to a Panopticon manager over HTTPS.\n"
                      << "                            Stdout output is unaffected either way.\n"
                      << "  --insecure-tls            Skip TLS certificate validation for telemetry delivery\n"
                      << "                            only (bring-up only). Never applies to the response\n"
                      << "                            (command polling/execution) path, which always verifies.\n"
                      << "  --enable-response         Opt in to polling the Manager for commands and executing\n"
                      << "                            them (requires --manager-url). Off by default.\n"
                      << "  --identity-path           Where to load/store this agent's enrolled identity.\n"
                      << "  --spool-directory         Protected durable record directory, including offline capture.\n"
                      << "  --bootstrap-token-path    One-shot enrollment token file, read only if\n"
                      << "                            --identity-path does not yet exist.\n"
                      << "  --file-collection-root    Allow-listed root for COLLECT_FILE/QUARANTINE_FILE.\n"
                      << "  --quarantine-root         Destination root for QUARANTINE_FILE.\n"
                      << "  --manager-exception-host  Manager address kept reachable while host-isolated.\n"
                      << "  --manager-exception-port  Manager port kept reachable while host-isolated.\n"
                      << "Run elevated and press Ctrl+C to stop cleanly.\n";
            return std::nullopt;
        }
        if (argument == "--insecure-tls") {
            options.insecure_tls = true;
            continue;
        }
        if (argument == "--enable-response") {
            options.enable_response = true;
            continue;
        }
        if (argument == "--manager-url") {
            if (index + 1 >= argc) {
                std::cerr << "--manager-url requires a value. Use --help for usage.\n";
                return std::nullopt;
            }
            options.manager_url = std::string{argv[++index]};
            continue;
        }
        if (argument == "--identity-path" || argument == "--keypair-path" ||
            argument == "--spool-directory" ||
            argument == "--bootstrap-token-path" || argument == "--file-collection-root" ||
            argument == "--quarantine-root" || argument == "--manager-exception-host") {
            if (index + 1 >= argc) {
                std::cerr << argument << " requires a value. Use --help for usage.\n";
                return std::nullopt;
            }
            const std::string value{argv[++index]};
            if (argument == "--identity-path") options.identity_path = value;
            else if (argument == "--spool-directory") options.spool_directory = value;
            else if (argument == "--keypair-path") options.keypair_path = value;
            else if (argument == "--bootstrap-token-path") options.bootstrap_token_path = value;
            else if (argument == "--file-collection-root") options.file_collection_root = value;
            else if (argument == "--quarantine-root") options.quarantine_root = value;
            else options.manager_exception_host = value;
            continue;
        }
        if (argument == "--manager-exception-port") {
            if (index + 1 >= argc) {
                std::cerr << "--manager-exception-port requires a value. Use --help for usage.\n";
                return std::nullopt;
            }
            try {
                options.manager_exception_port = static_cast<unsigned>(std::stoul(std::string{argv[++index]}));
            } catch (const std::exception&) {
                std::cerr << "Invalid --manager-exception-port value.\n";
                return std::nullopt;
            }
            continue;
        }
        if (argument != "--source" || index + 1 >= argc) {
            std::cerr << "Invalid argument. Use --help for usage.\n";
            return std::nullopt;
        }
        const std::string_view value = argv[++index];
        if (value == "all") {
            options.source = SourceSelection::all;
        } else if (value == "etw") {
            options.source = SourceSelection::etw;
        } else if (value == "sysmon") {
            options.source = SourceSelection::sysmon;
        } else {
            std::cerr << "Invalid --source value: " << value << '\n';
            return std::nullopt;
        }
    }
    return options;
}

std::optional<std::string> file_name(const std::optional<std::string>& path) {
    if (!path || path->empty()) {
        return std::nullopt;
    }
    const std::size_t separator = path->find_last_of("\\/");
    return separator == std::string::npos ? *path : path->substr(separator + 1);
}

void populate_user(const std::optional<std::string>& account, enrichment::ResolvedUser& user) {
    if (!account || account->empty()) {
        return;
    }
    const std::size_t separator = account->find('\\');
    if (separator == std::string::npos) {
        user.name = *account;
        return;
    }
    if (separator != 0) {
        user.domain = account->substr(0, separator);
    }
    if (separator + 1 < account->size()) {
        user.name = account->substr(separator + 1);
    }
}

// Holds everything one response (command poll/execute/result) cycle needs.
// Constructed once in main() after enrollment succeeds; the background
// thread reuses it across polls. The encrypted inbox owns new durable replay
// state; the old flat ledger is a read-only migration guard. The exclusive
// native handle prevents a second live worker from owning this response scope.
struct ResponseRuntime {
    std::function<void(const std::string&)> diagnostic_sink;
    void diagnostic(const std::string& message) const {
        if (diagnostic_sink) diagnostic_sink(message);
        else std::cerr << message << '\n';
    }
    response::ResponseTransportClient client;
    response::EnrolledIdentity identity;
    response::ReplayLedger ledger;
    response::CommandGate gate;
    response::ResponseConfig config;
    std::string manager_url;
    pipeline::NormalizationContext context;
    std::function<void(const std::string&)> emit_line;
    response::ResultOutbox outcomes;
    delivery::DurableJournal inbox;
    std::string inbox_scope;
    UniqueHandle inbox_owner;
    std::optional<std::string> pending_result;
    std::string pending_command_key;
    std::atomic_uint64_t result_commit_failures{0};
    std::atomic_uint64_t pending_results{0};
    std::atomic_uint64_t poll_failures{0}, parse_failures{0};
    std::atomic_uint64_t last_poll_success_uptime{0}, last_poll_failure_uptime{0};
    std::atomic_uint8_t poll_state{0};

    // CommandGate holds a std::mutex, so it (and therefore ResponseRuntime)
    // is neither copyable nor movable -- this constructor builds `gate` in
    // place from the already-constructed `identity`/`ledger` members
    // (declaration order above guarantees they exist first) instead of
    // building a temporary ResponseRuntime and moving/copying it, which
    // would not compile.
    ResponseRuntime(response::EnrolledIdentity identity_in, response::ReplayLedger ledger_in,
                     response::ResponseConfig config_in, std::string manager_url_in,
                     pipeline::NormalizationContext context_in, std::function<void(const std::string&)> emit_line_in,
                     std::filesystem::path outbox_directory)
        : identity(std::move(identity_in)),
          ledger(std::move(ledger_in)),
          gate(identity.agent_id, identity.host_id,
               [] {
                   return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                          std::chrono::system_clock::now().time_since_epoch())
                                                          .count());
               },
               nullptr),
          config(std::move(config_in)),
          manager_url(std::move(manager_url_in)),
          context(std::move(context_in)),
          emit_line(std::move(emit_line_in)),
          outcomes(delivery::JournalConfig{outbox_directory}, identity.agent_id, identity.host_id),
          inbox(delivery::JournalConfig{outbox_directory / "inbox"}),
          inbox_scope(outbox_directory.filename().string()),
          inbox_owner(CreateFileW((outbox_directory / "response-owner.lock").c_str(), GENERIC_READ | GENERIC_WRITE,
              0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)) {
        if (!inbox_owner.get() || inbox_owner.get() == INVALID_HANDLE_VALUE)
            throw std::runtime_error("response identity scope already owned or ownership lock unavailable");
        pending_results.store(outcomes.pending());
    }
};

std::string action_name(response::ActionType action) {
    switch (action) {
        case response::ActionType::kill_process: return "KILL_PROCESS";
        case response::ActionType::collect_process_info: return "COLLECT_PROCESS_INFO";
        case response::ActionType::collect_network_connections: return "COLLECT_NETWORK_CONNECTIONS";
        case response::ActionType::collect_file: return "COLLECT_FILE";
        case response::ActionType::quarantine_file: return "QUARANTINE_FILE";
        case response::ActionType::isolate_host: return "ISOLATE_HOST";
        case response::ActionType::release_host_isolation: return "RELEASE_HOST_ISOLATION";
    }
    return "UNKNOWN";
}

// Executes exactly one already-gated command and returns the final receipt.
// Mirrors panopticon-linux-agent's main.cpp per-branch dispatch: every
// branch that can fail rewrites receipt.code to execution_failed or
// target_mismatch with a specific summary rather than silently succeeding.
response::CommandReceipt execute_command(ResponseRuntime& runtime, const response::Command& received,
                                          response::CommandReceipt receipt) {
    using response::ActionType;
    using response::ReceiptCode;
    if (receipt.code != ReceiptCode::succeeded) return receipt;
    // The best-effort acceptance request can consume the remaining command
    // lifetime. Recheck at dispatch instead of executing on an earlier gate result.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now >= received.expires_at_epoch_seconds) {
        receipt.code = ReceiptCode::expired;
        receipt.summary = "command expired before OS action dispatch";
        return receipt;
    }

    switch (received.action) {
        case ActionType::kill_process: {
            receipt = response::termination_receipt(response::terminate_process(received.process_target),
                received.command_id, received.correlation_id);
            break;
        }
        case ActionType::collect_process_info: {
            std::string error;
            const auto observation = response::reobserve_process(received.process_target, error);
            if (!observation) {
                receipt.code = ReceiptCode::target_mismatch;
                receipt.summary = "process identity could not be re-observed: " + error;
                break;
            }
            const auto raw = response::to_raw_process_event(*observation);
            enrichment::EnrichedProcessEvent enriched;
            enriched.raw = raw;
            enriched.process_name = raw.executable;
            std::string normalization_error;
            const auto normalized = pipeline::normalize_process_event(enriched, runtime.context, normalization_error);
            if (!normalized) {
                receipt.code = ReceiptCode::execution_failed;
                receipt.summary = "process observation could not be normalized: " + normalization_error;
                break;
            }
            runtime.emit_line(pipeline::serialize_event(*normalized));
            break;
        }
        case ActionType::collect_network_connections: {
            std::string error;
            const auto evidence = response::collect_network_evidence(runtime.config.maximum_connections_per_table,
                                                                       runtime.config.maximum_event_bytes, error);
            if (!evidence) {
                receipt.code = ReceiptCode::execution_failed;
                receipt.summary = "network evidence collection failed: " + error;
                break;
            }
            runtime.emit_line(*evidence);
            break;
        }
        case ActionType::collect_file: {
            std::string error;
            const auto evidence =
                response::collect_file_evidence(runtime.config.file_collection_root, received.file_target_path,
                                                 runtime.config.maximum_event_bytes, error);
            if (!evidence) {
                receipt.code = ReceiptCode::target_mismatch;
                receipt.summary = "requested file could not be safely collected: " + error;
                break;
            }
            runtime.emit_line(*evidence);
            break;
        }
        case ActionType::quarantine_file: {
            std::string error;
            const auto result = response::quarantine_file_and_serialize(
                runtime.config.file_collection_root, received.file_target_path, runtime.config.quarantine_root,
                runtime.config.maximum_event_bytes, error);
            if (!result) {
                receipt.code = ReceiptCode::target_mismatch;
                receipt.summary = "requested file could not be safely quarantined: " + error;
                break;
            }
            runtime.emit_line(*result);
            break;
        }
        case ActionType::isolate_host:
        case ActionType::release_host_isolation: {
            response::IsolationExceptionEndpoint exception{runtime.config.manager_exception_host,
                                                            static_cast<std::uint16_t>(runtime.config.manager_exception_port)};
            const auto plan = response::build_isolation_plan(exception);
            std::string error;
            const auto applied = received.action == ActionType::isolate_host
                                      ? response::apply_isolation(plan, error)
                                      : response::release_isolation(plan, error);
            if (!applied.value_or(false)) {
                receipt.code = ReceiptCode::execution_failed;
                receipt.summary = (received.action == ActionType::isolate_host ? "isolate_host failed: "
                                                                                : "release_host_isolation failed: ") +
                                   error;
            }
            break;
        }
    }
    return receipt;
}

// One poll -> gate -> accept -> execute -> result cycle, called repeatedly
// by the response thread below. Never touches stdout telemetry output
// directly except through runtime.emit_line, so a poll/parse failure here
// can never interrupt the existing ETW/Sysmon collection loop.
void process_durable_commands(ResponseRuntime& runtime) {
    for (const auto& stored : runtime.inbox.pending_commands(runtime.inbox_scope, 32)) {
        if (stored.state == "result_ready") {
            runtime.outcomes.save(stored.result);
            runtime.inbox.mark_command_outboxed(runtime.inbox_scope, stored.key);
            continue;
        }
        std::string error;
        const auto received = response::parse_command_json(stored.body, error);
        if (!received) throw std::runtime_error("retained command cannot be decoded: " + error);
        response::CommandReceipt receipt{received->command_id, received->correlation_id,
            response::ReceiptCode::indeterminate, "prior execution intent recovered; completion cannot be proven; action not repeated"};
        if (stored.state == "received") {
            if (!runtime.inbox.begin_command(runtime.inbox_scope, stored.key)) continue;
            receipt = runtime.gate.validate_and_mark(*received);
            if (receipt.code == response::ReceiptCode::succeeded && runtime.ledger.contains(received->command_id)) {
                receipt.code = response::ReceiptCode::indeterminate;
                receipt.summary = "legacy acceptance retained; prior execution cannot be proven; action not repeated";
            }
            if (receipt.code == response::ReceiptCode::succeeded)
                (void)runtime.client.accept_command(runtime.manager_url, runtime.identity, received->command_id);
            receipt = execute_command(runtime, *received, receipt);
        }
        const auto result = response::serialize_command_result(receipt, runtime.config.maximum_event_bytes, error);
        if (!result) throw std::runtime_error("retained command result cannot serialize: " + error);
        runtime.pending_command_key = stored.key;
        runtime.pending_result = *result;
        runtime.inbox.finish_command(runtime.inbox_scope, stored.key, *result);
        runtime.pending_result.reset();
        runtime.outcomes.save(*result);
        runtime.inbox.mark_command_outboxed(runtime.inbox_scope, stored.key);
    }
}

void run_response_cycle(ResponseRuntime& runtime) {
    try {
        if (runtime.pending_result) {
            runtime.inbox.finish_command(runtime.inbox_scope, runtime.pending_command_key, *runtime.pending_result);
            runtime.pending_result.reset();
        }
        process_durable_commands(runtime);
        runtime.outcomes.flush([&](const std::string& result) {
            return runtime.client.submit_command_result(runtime.manager_url, runtime.identity, result);
        });
        runtime.pending_results.store(runtime.outcomes.pending());
    } catch (const std::exception& error) {
        ++runtime.result_commit_failures;
        runtime.diagnostic("[response] outcome durability/receipt failure: " + std::string{error.what()});
        return;
    }
    std::string poll_error;
    const auto poll = runtime.client.poll_commands(runtime.manager_url, runtime.identity, poll_error);
    if (!poll) {
        ++runtime.poll_failures;
        runtime.last_poll_failure_uptime.store(GetTickCount64());
        runtime.poll_state.store(2);
        runtime.diagnostic("[response] command poll failed: " + poll_error);
        return;
    }
    std::string parse_error;
    const auto commands = response::parse_command_poll_response(*poll, 32, parse_error);
    if (!commands) {
        ++runtime.parse_failures;
        runtime.last_poll_failure_uptime.store(GetTickCount64());
        runtime.poll_state.store(2);
        runtime.diagnostic("[response] command poll response rejected: " + parse_error);
        return;
    }
    runtime.last_poll_success_uptime.store(GetTickCount64());
    runtime.poll_state.store(1);
    try {
        for (const auto& received : *commands) {
            std::string key_error;
            const auto key = panopticon::officer::core::sha256_hex(runtime.inbox_scope + ":" + received.command_id, key_error);
            if (!key) throw std::runtime_error(key_error);
            runtime.inbox.receive_command(runtime.inbox_scope, *key, received.canonical_wire_json);
        }
        process_durable_commands(runtime);
        runtime.pending_results.store(runtime.outcomes.pending());
    } catch (const std::exception& error) {
        ++runtime.result_commit_failures;
        runtime.diagnostic("[response] inbox/intent/outcome failure: " + std::string{error.what()});
    }
}

}  // namespace

int run_endpoint(int argc, char* argv[], HANDLE service_stop = nullptr,
    const std::function<void()>& progress = {}, const std::function<void()>& ready = {},
    const std::function<void()>& stopping = {}) {
    bool help_requested = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        help_requested = help_requested || argument == "--help" || argument == "-h";
    }
    const auto options = parse_arguments(argc, argv);
    if (!options) {
        return help_requested ? 0 : 2;
    }
    if (service_stop) {
        const auto absolute = [](const std::string& path) { return !path.empty() && std::filesystem::path(path).is_absolute(); };
        if (!absolute(options->spool_directory) || !absolute(options->identity_path) ||
            (options->manager_url && !absolute(options->keypair_path)) ||
            (options->enable_response && !absolute(options->replay_ledger_path)) ||
            (!options->bootstrap_token_path.empty() && !absolute(options->bootstrap_token_path)) ||
            (!options->file_collection_root.empty() && !absolute(options->file_collection_root)) ||
            (!options->quarantine_root.empty() && !absolute(options->quarantine_root))) {
            std::cerr << "Service mode requires absolute spool/identity and enabled delivery/response credential/ledger paths.\n";
            return 2;
        }
    }

    std::string error;
    auto context = runtime_context(error);
    if (!context) {
        std::cerr << "Officer startup failed: " << error << '\n';
        return 3;
    }
    const auto device_id = context->host.id;
    std::string startup_identity_error;
    const auto enrolled_identity = response::load_enrolled_identity(options->identity_path, startup_identity_error);
    if (enrolled_identity) {
        context->agent.id = enrolled_identity->agent_id;
        context->host.id = enrolled_identity->host_id;
    }
    if (!process_is_elevated()) {
        std::cerr << "Warning: Officer is not elevated. ETW or Sysmon subscription may be denied.\n";
    }

    HANDLE endpoint_stop = nullptr;
    if (service_stop) {
        if (!DuplicateHandle(GetCurrentProcess(), service_stop, GetCurrentProcess(), &endpoint_stop, 0, FALSE, DUPLICATE_SAME_ACCESS)) return 3;
    } else endpoint_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    UniqueHandle stop_event{endpoint_stop};
    if (stop_event.get() == nullptr) {
        std::cerr << "Officer could not create its shutdown event.\n";
        return 3;
    }
    shutdown_event.store(stop_event.get());
    if (!service_stop && !SetConsoleCtrlHandler(&console_control_handler, TRUE)) {
        shutdown_event.store(nullptr);
        std::cerr << "Officer could not install its Ctrl+C handler.\n";
        return 3;
    }

    // --manager-url is additive: stdout output (below) is unconditional,
    // exactly as it is with no flags at all. Constructing Uploader here
    // starts its network thread. enqueue() commits to the journal synchronously;
    // collector isolation is tracked in the capability matrix.
    std::unique_ptr<delivery::Uploader> uploader;
    std::unique_ptr<delivery::DurableJournal> offline_journal;
    if (options->manager_url) {
        delivery::DeliveryConfig delivery_config;
        delivery_config.manager_url = *options->manager_url;
        delivery_config.verify_tls = !options->insecure_tls;
        delivery_config.spool_directory = options->spool_directory;
        if (enrolled_identity) delivery_config.bearer_token = enrolled_identity->bearer_token;
        try {
            uploader = std::make_unique<delivery::Uploader>(delivery_config, context->agent.id);
        } catch (const std::exception& journal_error) {
            panopticon::officer::health::CoverageRegistry failed;
            failed.set("AG.durability", panopticon::officer::health::CapabilityState::unavailable,
                journal_error.what(), "journal initialization failed; collection has not started", true);
            std::cerr << failed.snapshot(context->agent.id, context->host.id).dump() << '\n';
            SetConsoleCtrlHandler(&console_control_handler, FALSE);
            shutdown_event.store(nullptr);
            return 5;
        }
        std::cerr << "Delivering events to " << delivery_config.manager_url
                   << (delivery_config.verify_tls ? "" : " (TLS verification disabled)") << '\n';
    }

    std::string installation_id;
    std::uint64_t collector_generation = 0;
    try {
        if (uploader) {
            installation_id = uploader->installation_id();
            collector_generation = uploader->next_collector_generation();
        }
        else {
            offline_journal = std::make_unique<delivery::DurableJournal>(delivery::JournalConfig{options->spool_directory});
            installation_id = offline_journal->persistent_identifier("installation");
            collector_generation = offline_journal->next_collector_generation();
        }
    } catch (const std::exception& journal_error) {
        std::cerr << "Officer durable capture initialization failed: " << journal_error.what() << '\n';
        SetConsoleCtrlHandler(&console_control_handler, FALSE);
        shutdown_event.store(nullptr);
        return 5;
    }
    std::string boot_error;
    const auto boot_id = panopticon::officer::core::query_native_boot_id(boot_error);
    pipeline::EndpointRecordFactory record_factory{*context, device_id, installation_id, boot_id, collector_generation};
    if (progress) progress(); // Runtime identity and durable writer are initialized.
    if (uploader) uploader->set_capture_scope(record_factory.capture_scope());
    pipeline::DiagnosticOutput diagnostic_stdout{GetStdHandle(STD_OUTPUT_HANDLE), 1024, 8 * 1024 * 1024};
    pipeline::DiagnosticOutput diagnostic_stderr{GetStdHandle(STD_ERROR_HANDLE), 256, 4 * 1024 * 1024};
    const auto persist_record = [&](const std::string& line) {
        if (uploader) return uploader->enqueue(line);
        try { offline_journal->append(line); return true; }
        catch (const std::exception& append_error) {
            (void)diagnostic_stderr.try_submit("[journal] offline observation was not accepted: " + std::string{append_error.what()});
            return false;
        }
    };
    panopticon::officer::health::CoverageRegistry coverage;
    if (service_stop) coverage.set("AJ.update", panopticon::officer::health::CapabilityState::degraded,
        "SCM dispatch path active; service installation/update/security qualification incomplete",
        "own-process service lifecycle only; RUNNING does not prove sensor coverage");
    using CapabilityState = panopticon::officer::health::CapabilityState;
    UniqueHandle health_changed{CreateEventW(nullptr, FALSE, FALSE, nullptr)};
    if (!health_changed.get()) {
        { std::ostringstream diagnostic; diagnostic << "Officer could not create its coverage notification event.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
        SetConsoleCtrlHandler(&console_control_handler, FALSE);
        shutdown_event.store(nullptr);
        return 3;
    }
    coverage.set("AG.durability", CapabilityState::degraded,
        "journal active including offline capture; physical disk bound, emergency reserve and collector isolation pending",
        "per-observation FULL/WAL journal, encrypted payloads, retained rejections");
    coverage.set("AH.transport", uploader ? CapabilityState::unavailable : CapabilityState::disabled,
        "no validated delivery receipt yet", "HTTPS, canonical protocol 2 and legacy protocol 1");
    coverage.set("identity.boot", boot_id ? CapabilityState::degraded : CapabilityState::unavailable,
        boot_id ? "native boot query active; OS compatibility qualification pending" : boot_error, "native NT boot environment identifier");
    coverage.set("A.host", CapabilityState::degraded,
        "separate device/install/enrollment/native boot identities active; hardware inventory and identity lifecycle pending",
        "identity, hostname and OS metadata; native boot may be unavailable");
    coverage.set("AN.detection_context", CapabilityState::degraded, "canonical context available to fleet Detection; local prevention and full domain coverage pending", "exact/source-scoped/unresolved process references");
    std::mutex output_mutex;
    std::atomic_uint64_t normalization_failures{0};
    std::atomic_uint64_t failure_evidence_committed{0};
    std::atomic_uint64_t observation_admission_failures{0};
    const auto emit_normalized =
        [&](const std::optional<telemetry::PanopticonEvent>& normalized,
            const std::string& normalization_error, const telemetry::RawEvent& raw) {
            std::scoped_lock lock{output_mutex};
            std::string line;
            std::string failure = normalization_error;
            bool failure_record = !normalized;
            if (normalized) {
                try { line = record_factory.observation(raw, *normalized).dump(); }
                catch (const std::exception& exception) {
                    failure = "Canonical serialization failed: " + std::string{exception.what()};
                    failure_record = true;
                }
            }
            if (failure_record) {
                ++normalization_failures;
                coverage.set("pipeline.normalization", CapabilityState::degraded, failure,
                    "decoded source facts retained in failure evidence when journal accepts", true);
                SetEvent(health_changed.get());
                (void)diagnostic_stderr.try_submit("[pipeline] " + failure);
                line = record_factory.normalization_failure(raw, failure).dump();
            }
            if (!persist_record(line)) {
                ++observation_admission_failures;
                coverage.set("AG.durability", CapabilityState::degraded, "observation/failure evidence commit refused",
                    "observation not durably accepted; source sink failure counted", true);
                SetEvent(health_changed.get());
                // Let the source account for this failed sink acceptance as an
                // event failure. Do not disguise refusal as successful capture.
                throw std::runtime_error("observation was not durably accepted");
            }
            if (failure_record) ++failure_evidence_committed;
            (void)diagnostic_stdout.try_submit(line);
        };
    const collectors::RawEventSink process_raw_event = [&](telemetry::RawEvent raw_event) {
        if (const auto* stopped = std::get_if<telemetry::RawProcessEvent>(&raw_event); stopped && stopped->terminated) {
            std::scoped_lock lock{output_mutex};
            nlohmann::json record;
            try { record = record_factory.process_stop(*stopped); }
            catch (const std::exception& error) {
                // emit_normalized owns the same output lock; release before
                // re-entering it is not possible here, so retain explicit failure.
                ++normalization_failures;
                record = record_factory.normalization_failure(raw_event, error.what());
            }
            if (!persist_record(record.dump())) {
                ++observation_admission_failures; SetEvent(health_changed.get());
                throw std::runtime_error("process stop was not durably accepted");
            }
            if (record["category"] == "process_stop") record_factory.accepted_process_stop(*stopped);
            else ++failure_evidence_committed;
            (void)diagnostic_stdout.try_submit(record.dump());
            return;
        }
        const auto source_record = raw_event;
        std::string normalization_error;
        std::optional<telemetry::PanopticonEvent> normalized;
        try {
            normalized = std::visit(
            [&](auto&& raw) -> std::optional<telemetry::PanopticonEvent> {
                using Event = std::decay_t<decltype(raw)>;
                if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>) {
                    enrichment::EnrichedProcessEvent enriched;
                    enriched.raw = std::move(raw);
                    enriched.process_name = file_name(enriched.raw.executable);
                    enriched.parent_name = file_name(enriched.raw.parent_executable);
                    enriched.sha256 = enriched.raw.sha256;
                    populate_user(enriched.raw.user_name, enriched.user);
                    return pipeline::normalize_process_event(enriched, *context, normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawNetworkEvent>) {
                    return pipeline::normalize_network_event(raw, *context, normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawFileEvent>) {
                    return pipeline::normalize_file_event(raw, *context, normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawRegistryEvent>) {
                    return pipeline::normalize_registry_event(raw, *context, normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawImageLoadEvent>) {
                    return pipeline::normalize_image_load_event(raw, *context, normalization_error);
                }
            },
            std::move(raw_event));
        } catch (const std::exception& exception) {
            normalization_error = "Normalization exception: " + std::string{exception.what()};
        }
        emit_normalized(normalized, normalization_error, source_record);
    };
    const collectors::CollectorErrorSink error_sink =
        [&](std::string_view collector, std::string message) {
            coverage.set("sensor." + std::string{collector}, CapabilityState::degraded,
                message, "collector reported an error; continuity not verified", true);
            SetEvent(health_changed.get());
        };

    pipeline::RawHandoff raw_handoff{8192, 64u * 1024 * 1024, process_raw_event};
    coverage.set("pipeline.raw_handoff", CapabilityState::degraded,
        "bounded RAM ownership separates decoded-event callbacks from journal/output I/O; crash-safe admission and native decode isolation pending",
        "8192 owned events including in-flight; 64 MiB variant/string capacity charge, not allocator RSS; volatile admission is not durable acceptance");
    const collectors::RawEventSink event_sink = [&](telemetry::RawEvent raw_event) {
        if (!raw_handoff.try_submit(std::move(raw_event))) {
            SetEvent(health_changed.get());
            throw std::runtime_error("volatile raw handoff admission refused; observation not durably accepted");
        }
    };

    std::vector<std::unique_ptr<collectors::TelemetryCollector>> all_collectors;
    if (options->source == SourceSelection::all || options->source == SourceSelection::etw) {
        all_collectors.push_back(std::make_unique<collectors::EtwProcessCollector>());
    }
    if (options->source == SourceSelection::all || options->source == SourceSelection::sysmon) {
        all_collectors.push_back(std::make_unique<collectors::SysmonEventCollector>());
    }

    coverage.set("sensor.etw", CapabilityState::disabled, "source not selected", "kernel process-start adapter");
    coverage.set("sensor.sysmon", CapabilityState::disabled, "source not selected", "configured Sysmon event subset");
    std::size_t started = 0;
    struct SupervisedSource {
        collectors::TelemetryCollector* collector;
        panopticon::officer::health::SourceGapBuffer history;
        std::string pending_record;
    };
    std::vector<SupervisedSource> supervised_sources;
    for (auto& collector : all_collectors) {
        error.clear();
        if (collector->start(event_sink, error_sink, error)) {
            ++started;
            supervised_sources.push_back({collector.get(), {}, {}});
            coverage.set("sensor." + std::string{collector->name()}, CapabilityState::degraded,
                "subscription active; supervisor starting; replay/bookmarks and provider configuration qualification pending", "current adapter subset");
            coverage.set("B.process", CapabilityState::degraded,
                "process-start sensor active; full instance identity, stops, tokens and state pending", "ETW/Sysmon process starts");
            if (collector->name() == "sysmon") {
                for (const auto* id : {"H.filesystem", "I.registry", "N.network"})
                    coverage.set(id, CapabilityState::degraded, "Sysmon subset active; native coverage and host state pending", "selected Sysmon records; provider configuration dependent");
            }
            { std::ostringstream diagnostic; diagnostic << "Started " << collector->name() << " collector.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
        } else {
            coverage.set("sensor." + std::string{collector->name()}, CapabilityState::unavailable,
                error, "collector could not subscribe", true);
            { std::ostringstream diagnostic; diagnostic << "Could not start " << collector->name() << " collector: "
                      << error << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
        }
    }
    if (started == 0) {
        coverage.set("B.process", CapabilityState::blind, "no process event source subscribed", "host inventory and health continue");
        { std::ostringstream diagnostic; diagnostic << "No event collector subscribed; continuing host inventory and health with event coverage blind.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
    }

    std::mutex inventory_mutex;
    auto inventory_health = nlohmann::json{{"state", "unavailable"}, {"last_committed_uptime_ms", nullptr},
        {"committed_snapshots", "0"}, {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread inventory_worker{[&](std::stop_token stop) {
        std::string pending_record;
        std::string pending_record_id;
        auto pending_field_status = nlohmann::json::object();
        std::uint64_t committed = 0, commit_failures = 0;
        ULONGLONG next_capture = 0;
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending_record.empty() && GetTickCount64() >= next_capture) {
                    {
                        std::scoped_lock lock{inventory_mutex};
                        inventory_health["state"] = "degraded";
                        inventory_health["collection_in_progress"] = true;
                        inventory_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64());
                    }
                    const auto snapshot = panopticon::officer::state::collect_host_inventory();
                    pending_field_status = nlohmann::json::object();
                    for (const auto& [field, fact] : snapshot.at("fields").items()) {
                        pending_field_status[field] = {{"state", fact.at("state")}, {"source", fact.at("source")},
                            {"reason", fact.at("reason")}, {"error_code", fact.at("error_code")}};
                        for (const auto* key : {"error_domain", "query_status_code", "enumeration_error_code",
                            "query_failures", "query_failures_scope", "bound_exceeded", "enumerated_subcategory_count", "scope"})
                            if (fact.contains(key)) pending_field_status[field][key] = fact.at(key);
                    }
                    const auto record = record_factory.state("host_inventory", snapshot);
                    pending_record_id = record.at("record_id").get<std::string>();
                    pending_record = record.dump();
                }
                if (!pending_record.empty()) {
                    bool accepted = false;
                    {
                        std::scoped_lock lock{output_mutex};
                        accepted = persist_record(pending_record);
                        if (accepted) { (void)diagnostic_stdout.try_submit(pending_record); }
                    }
                    std::scoped_lock inventory_status_lock{inventory_mutex};
                    if (accepted) {
                        pending_record.clear();
                        next_capture = GetTickCount64() + 300000;
                        ++committed;
                        coverage.set("A.host", CapabilityState::degraded,
                            "native host snapshot committed; full TPM/Entra/disk state, virtualization, deltas and qualification pending",
                            "version/architecture/memory/firmware/BIOS/join/adapters/TPM/default Entra/volumes with per-query availability");
                        const auto field_state = [&](const char* name) {
                            const auto value = pending_field_status.at(name).at("state").get<std::string>();
                            return value == "healthy" ? CapabilityState::healthy : value == "degraded" ? CapabilityState::degraded
                                : value == "unavailable" ? CapabilityState::unavailable : value == "unsupported" ? CapabilityState::unsupported
                                : value == "disabled" ? CapabilityState::disabled : CapabilityState::blind;
                        };
                        coverage.set("state.tpm_device", field_state("tpm"),
                            pending_field_status.at("tpm").at("reason").get<std::string>(),
                            "last committed TPM compatible-device/version query; readiness and attestation not queried");
                        coverage.set("state.entra_default_join", field_state("entra_join"),
                            pending_field_status.at("entra_join").at("reason").get<std::string>(),
                            "last committed device/default collector-user work-account query; not all users or tenants");
                        coverage.set("state.storage_volumes", field_state("storage"),
                            pending_field_status.at("storage").at("reason").get<std::string>(),
                            "last committed local volume query; disk topology, encryption, removable devices and continuity incomplete");
                        coverage.set("state.system_audit_policy", field_state("system_audit_policy"),
                            pending_field_status.at("system_audit_policy").at("reason").get<std::string>(),
                            "last committed system advanced audit policy query; per-user/token policy, options and Security log delivery not verified");
                        const auto posture_available = field_state("tpm") == CapabilityState::healthy || field_state("tpm") == CapabilityState::degraded ||
                            field_state("secure_boot_registry_report") == CapabilityState::healthy ||
                            field_state("system_audit_policy") == CapabilityState::healthy || field_state("system_audit_policy") == CapabilityState::degraded;
                        coverage.set("Y.posture", posture_available ? CapabilityState::degraded : CapabilityState::unavailable,
                            "TPM/Secure Boot and system audit policy queried with per-field availability; attestation, VBS/HVCI/WDAC, effective per-user audit and deltas pending",
                            "per-field query status in committed host state; no enforcement or attestation claim");
                        const auto entra_available = field_state("entra_join") == CapabilityState::healthy || field_state("entra_join") == CapabilityState::degraded;
                        coverage.set("W.enterprise_identity", entra_available ? CapabilityState::degraded : CapabilityState::unavailable,
                            "default native Entra query sampled; complete identity, tenant/user inventory, policy and changes pending",
                            "per-field Entra query status in committed host state");
                    } else {
                        ++commit_failures;
                        coverage.set("A.host", CapabilityState::degraded, "host snapshot pending durable acceptance", "retained bounded pending snapshot", true);
                    }
                    {
                        inventory_health["state"] = accepted ? "degraded" : "unavailable";
                        inventory_health["collection_in_progress"] = false;
                        inventory_health["committed_snapshots"] = std::to_string(committed);
                        inventory_health["commit_failures"] = std::to_string(commit_failures);
                        inventory_health["pending_durable_acceptance"] = !pending_record.empty();
                        if (accepted) {
                            inventory_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                            inventory_health["last_committed_capture_started_uptime_ms"] = inventory_health["collection_started_uptime_ms"];
                            inventory_health["last_committed_record_id"] = pending_record_id;
                            inventory_health["field_query_status"] = pending_field_status;
                            inventory_health["field_query_status_scope"] = "last committed host snapshot; not live continuity";
                        }
                    }
                    SetEvent(health_changed.get());
                }
            } catch (const std::exception& exception) {
                coverage.set("A.host", CapabilityState::unavailable, exception.what(), "inventory collection or serialization failed", true);
                { std::scoped_lock lock{inventory_mutex}; inventory_health["state"] = "unavailable";
                  inventory_health["collection_in_progress"] = false; }
                next_capture = GetTickCount64() + 30000;
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto process_inventory_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread process_inventory_worker{[&](std::stop_token stop) {
        std::string pending_record, pending_id;
        auto pending_status = nlohmann::json::object();
        std::uint64_t committed = 0, failures = 0; ULONGLONG next_capture = 0;
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending_record.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex};
                      process_inventory_health["collection_in_progress"] = true;
                      process_inventory_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto page_ids = nlohmann::json::array();
                    auto begin = record_factory.state("process_inventory_begin", {{"format", "paged_process_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex};
                              process_inventory_health["capture_id"] = capture_id;
                              process_inventory_health["committed_pages"] = std::to_string(page_ids.size());
                              process_inventory_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) { ++failures; process_inventory_health["commit_failures"] = std::to_string(failures); } }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_process_inventory_pages(context->host.id, boot_id,
                        [&](nlohmann::json page) {
                            page["capture_id"] = capture_id;
                            const auto record = record_factory.state("process_inventory_page", std::move(page));
                            if (!retain(record)) return false;
                            page_ids.push_back(record.at("record_id"));
                            { std::scoped_lock lock{inventory_mutex}; process_inventory_health["committed_pages"] = std::to_string(page_ids.size()); }
                            SetEvent(health_changed.get()); return true;
                        });
                    data["format"] = "paged_process_inventory_v1";
                    data["capture_id"] = capture_id;
                    data["page_record_ids"] = std::move(page_ids);
                    pending_status = {{"state", data.at("state")}};
                    for (const auto* key : {"enumeration_complete", "bound_exceeded", "query_failure_count", "native_exact_query_references", "security_query_summary", "source", "error_domain", "error_code", "enumeration_error_code"})
                        if (data.contains(key)) pending_status[key] = data.at(key);
                    const auto record = record_factory.state("process_inventory", data);
                    pending_id = record.at("record_id").get<std::string>(); pending_record = record.dump();
                }
                if (!pending_record.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending_record);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending_record); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending_record.clear(); next_capture = GetTickCount64() + 300000; ++committed;
                        process_inventory_health["last_committed_record_id"] = pending_id;
                        process_inventory_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        process_inventory_health["last_committed_capture_started_uptime_ms"] = process_inventory_health["collection_started_uptime_ms"];
                        process_inventory_health["last_committed_query_status"] = pending_status;
                        coverage.set("state.process_inventory", pending_status.at("state") == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                            "last committed Toolhelp snapshot and later held-object queries; descriptor association and lifecycle unverified",
                            "parent PID is not a parent instance; no event continuity or full process graph claim");
                    } else { ++failures; coverage.set("state.process_inventory", CapabilityState::degraded, "process snapshot pending durable acceptance", "one stable pending snapshot; not crash-durable until commit", true); }
                    process_inventory_health["state"] = accepted ? pending_status.at("state") : nlohmann::json("unavailable");
                    process_inventory_health["committed_snapshots"] = std::to_string(committed);
                    process_inventory_health["commit_failures"] = std::to_string(failures);
                    process_inventory_health["pending_durable_acceptance"] = !pending_record.empty();
                    process_inventory_health["collection_in_progress"] = false;
                    SetEvent(health_changed.get());
                }
            } catch (const std::exception& exception) {
                std::scoped_lock lock{inventory_mutex};
                process_inventory_health["state"] = "unavailable"; process_inventory_health["last_error"] = exception.what();
                process_inventory_health["collection_in_progress"] = false;
                if (pending_record.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.process_inventory", CapabilityState::unavailable, exception.what(), "process inventory collection/serialization unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto service_inventory_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread service_inventory_worker{[&](std::stop_token stop) {
        coverage.set("state.service_security_descriptor", CapabilityState::unavailable, "no committed service security query", "selected caller-visible owner/group/DACL only");
        constexpr const char* optional_names[]{"description", "failure_actions", "delayed_auto_start",
            "failure_actions_on_non_crash", "service_sid_type", "required_privileges", "preshutdown_timeout", "launch_protection", "triggers"};
        for (const auto* name : optional_names) coverage.set(std::string("state.service_configuration.") + name,
            CapabilityState::unavailable, "no committed service configuration query", "caller-visible SCM configuration only");
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending_record, pending_id; auto pending_status = nlohmann::json::object();
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending_record.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; service_inventory_health["collection_in_progress"] = true;
                      service_inventory_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto page_ids = nlohmann::json::array();
                    const auto begin = record_factory.state("service_inventory_begin", {{"format", "paged_service_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex};
                              service_inventory_health["capture_id"] = capture_id;
                              service_inventory_health["committed_pages"] = std::to_string(page_ids.size());
                              service_inventory_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) { ++failures; service_inventory_health["commit_failures"] = std::to_string(failures); } }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_service_inventory_pages([&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state("service_inventory_page", std::move(page));
                        if (!retain(record)) return false;
                        page_ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; service_inventory_health["committed_pages"] = std::to_string(page_ids.size()); }
                        SetEvent(health_changed.get()); return true;
                    });
                    data["format"] = "paged_service_inventory_v1"; data["capture_id"] = capture_id;
                    data["page_record_ids"] = std::move(page_ids);
                    pending_status = {{"state", data.at("state")}};
                    for (const auto* key : {"enumeration_complete", "bound_exceeded", "consumer_refused", "entries_delivered", "query_failure_count",
                        "query_failure_scope", "optional_configuration_query_summary", "optional_configuration_summary_scope", "security_query_summary",
                        "enumeration_failure", "native_enumeration_calls", "scope", "source", "error_domain", "error_code"})
                        if (data.contains(key)) pending_status[key] = data.at(key);
                    const auto record = record_factory.state("service_inventory", std::move(data));
                    pending_id = record.at("record_id").get<std::string>(); pending_record = record.dump();
                }
                if (!pending_record.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending_record);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending_record); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending_record.clear(); next_capture = GetTickCount64() + 300000; ++committed;
                        service_inventory_health["last_committed_record_id"] = pending_id;
                        service_inventory_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        service_inventory_health["last_committed_capture_started_uptime_ms"] = service_inventory_health["collection_started_uptime_ms"];
                        service_inventory_health["last_committed_query_status"] = pending_status;
                        const auto state = pending_status.at("state") == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.service_inventory", state, "committed caller-visible SCM descriptors and later configuration queries",
                            "silently omitted services unknown; service/process instances and lifecycle unverified");
                        coverage.set("K.service_driver", state, "SCM service/driver state sampled; full configuration, driver modules/signers and changes pending",
                            "caller-visible win32/driver records; not a complete service or loaded-driver census");
                        coverage.set("state.service_security_descriptor",
                            pending_status.contains("security_query_summary") && pending_status["security_query_summary"]["state"] == "degraded"
                                ? CapabilityState::degraded : CapabilityState::unavailable,
                            "selected service security query status in manifest " + pending_id,
                            "later separate READ_CONTROL object; owner/group/DACL binary evidence; effective access/SACL/instance association unqualified");
                        for (const auto* name : optional_names) {
                            auto query_state = CapabilityState::unavailable;
                            if (pending_status.contains("optional_configuration_query_summary")) {
                                const auto& query = pending_status["optional_configuration_query_summary"][name];
                                if (query["state"] == "healthy") query_state = CapabilityState::healthy;
                                else if (query["state"] == "degraded") query_state = CapabilityState::degraded;
                            }
                            coverage.set(std::string("state.service_configuration.") + name, query_state,
                                "selected query status in committed service manifest " + pending_id,
                                "caller-visible later opened service objects; not full census, running configuration or instance association");
                        }
                    } else { ++failures; coverage.set("state.service_inventory", CapabilityState::degraded,
                        "service capture pending durable acceptance", "stable pending record; not crash-durable until commit", true); }
                    service_inventory_health["state"] = accepted ? pending_status.at("state") : nlohmann::json("unavailable");
                    service_inventory_health["committed_snapshots"] = std::to_string(committed);
                    service_inventory_health["commit_failures"] = std::to_string(failures);
                    service_inventory_health["pending_durable_acceptance"] = !pending_record.empty();
                    service_inventory_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; service_inventory_health["state"] = "unavailable";
                service_inventory_health["last_error"] = error.what(); service_inventory_health["collection_in_progress"] = false;
                if (pending_record.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.service_inventory", CapabilityState::unavailable, error.what(), "service collection/serialization unavailable", true);
                coverage.set("state.service_security_descriptor", CapabilityState::unavailable, error.what(), "service security collection/serialization unavailable", true);
                for (const auto* name : optional_names) coverage.set(std::string("state.service_configuration.") + name,
                    CapabilityState::unavailable, error.what(), "service configuration collection/serialization unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto loaded_driver_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread loaded_driver_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.loaded_driver_inventory", CapabilityState::unavailable, "no committed loaded-driver capture", "independent native driver address snapshot");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; loaded_driver_health["collection_in_progress"] = true;
                      loaded_driver_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto ids = nlohmann::json::array();
                    const auto begin = record_factory.state("loaded_driver_inventory_begin", {{"format", "paged_loaded_driver_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex}; loaded_driver_health["capture_id"] = capture_id;
                              loaded_driver_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) loaded_driver_health["commit_failures"] = std::to_string(++failures); }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_loaded_driver_pages([&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state("loaded_driver_inventory_page", std::move(page));
                        if (!retain(record)) return false; ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; loaded_driver_health["committed_pages"] = std::to_string(ids.size()); }
                        SetEvent(health_changed.get()); return true;
                    });
                    data["capture_id"] = capture_id; data["page_record_ids"] = std::move(ids);
                    data["inventory_complete"] = false; data["format"] = "paged_loaded_driver_inventory_v1";
                    status = data; status.erase("page_record_ids"); status.erase("capture_id");
                    const auto record = record_factory.state("loaded_driver_inventory", std::move(data));
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        loaded_driver_health["committed_snapshots"] = std::to_string(++committed);
                        loaded_driver_health["last_committed_record_id"] = pending_id;
                        loaded_driver_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        loaded_driver_health["last_committed_capture_started_uptime_ms"] = loaded_driver_health["collection_started_uptime_ms"];
                        loaded_driver_health["last_committed_query_status"] = status;
                        const auto query_state = status["state"] == "blind" ? CapabilityState::blind
                            : status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.loaded_driver_inventory", query_state, "loaded-driver status in manifest " + pending_id,
                            "native address snapshot and later names; not SCM registration, module identity, file/signature or continuous loaded-module census");
                    } else loaded_driver_health["commit_failures"] = std::to_string(++failures);
                    loaded_driver_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    loaded_driver_health["pending_durable_acceptance"] = !pending.empty();
                    loaded_driver_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; loaded_driver_health["state"] = "unavailable";
                loaded_driver_health["last_error"] = error.what(); loaded_driver_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.loaded_driver_inventory", CapabilityState::unavailable, error.what(), "loaded-driver collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto socket_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread socket_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.socket_inventory", CapabilityState::unavailable, "no committed socket table capture", "independent native TCP/UDP owner-PID table snapshot");
        for (const auto* table : {"tcp4", "tcp6", "udp4", "udp6"})
            coverage.set(std::string("state.socket_table.") + table, CapabilityState::unavailable,
                "no committed socket capture", "one native available-to-caller table");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; socket_health["collection_in_progress"] = true;
                      socket_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto ids = nlohmann::json::array();
                    const auto begin = record_factory.state("socket_inventory_begin", {{"format", "paged_socket_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex}; socket_health["capture_id"] = capture_id;
                              socket_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) socket_health["commit_failures"] = std::to_string(++failures); }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_socket_inventory_pages([&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state("socket_inventory_page", std::move(page));
                        if (!retain(record)) return false; ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; socket_health["committed_pages"] = std::to_string(ids.size()); }
                        SetEvent(health_changed.get()); return true;
                    });
                    data["capture_id"] = capture_id; data["page_record_ids"] = std::move(ids);
                    data["inventory_complete"] = false; data["format"] = "paged_socket_inventory_v1";
                    status = data; status.erase("page_record_ids"); status.erase("capture_id");
                    const auto record = record_factory.state("socket_inventory", std::move(data));
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        socket_health["committed_snapshots"] = std::to_string(++committed);
                        socket_health["last_committed_record_id"] = pending_id;
                        socket_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        socket_health["last_committed_capture_started_uptime_ms"] = socket_health["collection_started_uptime_ms"];
                        socket_health["last_committed_query_status"] = status;
                        const auto query_state = status["state"] == "blind" ? CapabilityState::blind
                            : status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.socket_inventory", query_state, "socket table status in manifest " + pending_id,
                            "separate native TCP/UDP IPv4/IPv6 queries; not verified process/socket identity or continuous network activity");
                        for (auto it = status.at("tables").begin(); it != status.at("tables").end(); ++it) {
                            const auto raw = it.value().at("state").get<std::string>();
                            const auto table_state = raw == "healthy" ? CapabilityState::healthy
                                : raw == "unsupported" ? CapabilityState::unsupported
                                : raw == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                            coverage.set("state.socket_table." + it.key(), table_state,
                                "native query and page admission status in manifest " + pending_id,
                                "one available-to-caller table; no verified owner instance, socket lifecycle or continuous activity");
                        }
                    } else socket_health["commit_failures"] = std::to_string(++failures);
                    socket_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    socket_health["pending_durable_acceptance"] = !pending.empty();
                    socket_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; socket_health["state"] = "unavailable";
                socket_health["last_error"] = error.what(); socket_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.socket_inventory", CapabilityState::unavailable, error.what(), "socket table collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto route_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread route_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.route_inventory", CapabilityState::unavailable, "no committed route table capture", "independent native IPv4/IPv6 route table snapshot");
        coverage.set("state.route_ip_interface", CapabilityState::unavailable,
            "no committed later IP interface query", "route-associated caller-context family lookups");
        for (const auto* table : {"ipv4", "ipv6"})
            coverage.set(std::string("state.route_table.") + table, CapabilityState::unavailable,
                "no committed route capture", "one native available-to-caller table");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; route_health["collection_in_progress"] = true;
                      route_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto ids = nlohmann::json::array();
                    const auto begin = record_factory.state("route_inventory_begin", {{"format", "paged_route_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex}; route_health["capture_id"] = capture_id;
                              route_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) route_health["commit_failures"] = std::to_string(++failures); }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_route_inventory_pages([&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state("route_inventory_page", std::move(page));
                        if (!retain(record)) return false; ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; route_health["committed_pages"] = std::to_string(ids.size()); }
                        SetEvent(health_changed.get()); return true;
                    });
                    data["capture_id"] = capture_id; data["page_record_ids"] = std::move(ids);
                    data["inventory_complete"] = false; data["format"] = "paged_route_inventory_v1";
                    status = data; status.erase("page_record_ids"); status.erase("capture_id");
                    const auto record = record_factory.state("route_inventory", std::move(data));
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        route_health["committed_snapshots"] = std::to_string(++committed);
                        route_health["last_committed_record_id"] = pending_id;
                        route_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        route_health["last_committed_capture_started_uptime_ms"] = route_health["collection_started_uptime_ms"];
                        route_health["last_committed_query_status"] = status;
                        const auto interface_state = status.at("ip_interface_query_summary").at("state").get<std::string>();
                        coverage.set("state.route_ip_interface", interface_state == "healthy" ? CapabilityState::healthy
                            : interface_state == "degraded" ? CapabilityState::degraded : CapabilityState::unavailable,
                            "later IP interface query summary in manifest " + pending_id,
                            "bounded unique route-associated family/lookup keys; later relationship unverified, not full interface census or effective path");
                        const auto query_state = status["state"] == "blind" ? CapabilityState::blind
                            : status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.route_inventory", query_state, "route table status in manifest " + pending_id,
                            "separate native IPv4/IPv6 route queries; no persistent interface/route identity or continuous changes");
                        for (auto it = status.at("tables").begin(); it != status.at("tables").end(); ++it) {
                            const auto raw = it.value().at("state").get<std::string>();
                            const auto table_state = raw == "healthy" ? CapabilityState::healthy
                                : raw == "unsupported" ? CapabilityState::unsupported
                                : raw == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                            coverage.set("state.route_table." + it.key(), table_state,
                                "native query and page admission status in manifest " + pending_id,
                                "one caller-context route table; no effective route, persistent interface or continuous change coverage");
                        }
                    } else route_health["commit_failures"] = std::to_string(++failures);
                    route_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    route_health["pending_durable_acceptance"] = !pending.empty();
                    route_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; route_health["state"] = "unavailable";
                route_health["last_error"] = error.what(); route_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.route_inventory", CapabilityState::unavailable, error.what(), "route table collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto ip_interface_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread ip_interface_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.ip_interface_inventory", CapabilityState::unavailable, "no committed ip_interface table capture", "independent native IPv4/IPv6 IP interface table snapshot");
        for (const auto* table : {"ipv4", "ipv6"})
            coverage.set(std::string("state.ip_interface_table.") + table, CapabilityState::unavailable,
                "no committed ip_interface capture", "one native available-to-caller table");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; ip_interface_health["collection_in_progress"] = true;
                      ip_interface_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto ids = nlohmann::json::array();
                    const auto begin = record_factory.state("ip_interface_inventory_begin", {{"format", "paged_ip_interface_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex}; ip_interface_health["capture_id"] = capture_id;
                              ip_interface_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) ip_interface_health["commit_failures"] = std::to_string(++failures); }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_ip_interface_inventory_pages([&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state("ip_interface_inventory_page", std::move(page));
                        if (!retain(record)) return false; ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; ip_interface_health["committed_pages"] = std::to_string(ids.size()); }
                        SetEvent(health_changed.get()); return true;
                    });
                    data["capture_id"] = capture_id; data["page_record_ids"] = std::move(ids);
                    data["inventory_complete"] = false; data["format"] = "paged_ip_interface_inventory_v1";
                    status = data; status.erase("page_record_ids"); status.erase("capture_id");
                    const auto record = record_factory.state("ip_interface_inventory", std::move(data));
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        ip_interface_health["committed_snapshots"] = std::to_string(++committed);
                        ip_interface_health["last_committed_record_id"] = pending_id;
                        ip_interface_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        ip_interface_health["last_committed_capture_started_uptime_ms"] = ip_interface_health["collection_started_uptime_ms"];
                        ip_interface_health["last_committed_query_status"] = status;
                        const auto query_state = status["state"] == "blind" ? CapabilityState::blind
                            : status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.ip_interface_inventory", query_state, "ip_interface table status in manifest " + pending_id,
                            "separate native IPv4/IPv6 ip_interface queries; no persistent interface identity or continuous changes");
                        for (auto it = status.at("tables").begin(); it != status.at("tables").end(); ++it) {
                            const auto raw = it.value().at("state").get<std::string>();
                            const auto table_state = raw == "healthy" ? CapabilityState::healthy
                                : raw == "unsupported" ? CapabilityState::unsupported
                                : raw == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                            coverage.set("state.ip_interface_table." + it.key(), table_state,
                                "native query and page admission status in manifest " + pending_id,
                                "one caller-context IP interface table; no persistent lifetime or continuous changes");
                        }
                    } else ip_interface_health["commit_failures"] = std::to_string(++failures);
                    ip_interface_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    ip_interface_health["pending_durable_acceptance"] = !pending.empty();
                    ip_interface_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; ip_interface_health["state"] = "unavailable";
                ip_interface_health["last_error"] = error.what(); ip_interface_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.ip_interface_inventory", CapabilityState::unavailable, error.what(), "ip_interface table collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto firewall_rule_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread firewall_rule_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.firewall_rule_inventory", CapabilityState::unavailable, "no committed firewall_rule table capture", "sequential caller-visible INetFwRules snapshot");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; firewall_rule_health["collection_in_progress"] = true;
                      firewall_rule_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    auto ids = nlohmann::json::array();
                    const auto begin = record_factory.state("firewall_rule_inventory_begin", {{"format", "paged_firewall_rule_inventory_begin_v1"}, {"inventory_complete", false}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        for (;;) {
                            bool accepted;
                            { std::scoped_lock lock{output_mutex}; accepted = persist_record(line);
                              if (accepted) { (void)diagnostic_stdout.try_submit(line); } }
                            { std::scoped_lock lock{inventory_mutex}; firewall_rule_health["capture_id"] = capture_id;
                              firewall_rule_health["pending_durable_acceptance"] = !accepted;
                              if (!accepted) firewall_rule_health["commit_failures"] = std::to_string(++failures); }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            if (stop.stop_requested() || WaitForSingleObject(stop_event.get(), 1000) == WAIT_OBJECT_0) return false;
                        }
                    };
                    if (!retain(begin)) break;
                    auto data = panopticon::officer::state::collect_firewall_rule_pages([&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state("firewall_rule_inventory_page", std::move(page));
                        if (!retain(record)) return false; ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; firewall_rule_health["committed_pages"] = std::to_string(ids.size()); }
                        SetEvent(health_changed.get()); return true;
                    });
                    data["capture_id"] = capture_id; data["page_record_ids"] = std::move(ids);
                    data["inventory_complete"] = false; data["format"] = "paged_firewall_rule_inventory_v1";
                    status = data; status.erase("page_record_ids"); status.erase("capture_id");
                    const auto record = record_factory.state("firewall_rule_inventory", std::move(data));
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) { (void)diagnostic_stdout.try_submit(pending); } }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        firewall_rule_health["committed_snapshots"] = std::to_string(++committed);
                        firewall_rule_health["last_committed_record_id"] = pending_id;
                        firewall_rule_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        firewall_rule_health["last_committed_capture_started_uptime_ms"] = firewall_rule_health["collection_started_uptime_ms"];
                        firewall_rule_health["last_committed_query_status"] = status;
                        const auto query_state = status["state"] == "blind" ? CapabilityState::blind
                            : status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.firewall_rule_inventory", query_state, "firewall_rule table status in manifest " + pending_id,
                            "base and available INetFwRule2/3 getter queries; no verified rule lifetime, effective filters or continuous changes");

                    } else firewall_rule_health["commit_failures"] = std::to_string(++failures);
                    firewall_rule_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    firewall_rule_health["pending_durable_acceptance"] = !pending.empty();
                    firewall_rule_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; firewall_rule_health["state"] = "unavailable";
                firewall_rule_health["last_error"] = error.what(); firewall_rule_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.firewall_rule_inventory", CapabilityState::unavailable, error.what(), "firewall_rule table collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto firewall_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread firewall_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.firewall_profiles", CapabilityState::unavailable, "no committed firewall profile state", "selected read-only local COM policy getters");
        for (const auto* name : {"domain", "private", "public"})
            coverage.set(std::string("state.firewall_exclusions.") + name, CapabilityState::unavailable,
                "no committed exclusion query", "selected caller-visible profile exclusion getter");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; firewall_health["collection_in_progress"] = true;
                      firewall_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    status = panopticon::officer::state::collect_firewall_profile_state();
                    const auto record = record_factory.state("firewall_profile_state", status);
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) (void)diagnostic_stdout.try_submit(pending); }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        firewall_health["committed_snapshots"] = std::to_string(++committed);
                        firewall_health["last_committed_record_id"] = pending_id;
                        firewall_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        firewall_health["last_committed_capture_started_uptime_ms"] = firewall_health["collection_started_uptime_ms"];
                        firewall_health["last_committed_query_status"] = status;
                        const auto value = status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.firewall_profiles", value, "getter status in record " + pending_id,
                            "domain/private/public selected policy and bounded exclusion outputs; rules/effective packet policy and changes missing");
                        coverage.set("P.firewall", value, "selected profile state in record " + pending_id,
                            "partial caller-visible local policy; complete firewall state and enforcement unverified");
                        for (const auto* name : {"domain", "private", "public"})
                            coverage.set(std::string("state.firewall_exclusions.") + name, CapabilityState::unavailable,
                                "no interpreted exclusion output in record " + pending_id, "selected caller-visible exclusion getter");
                        for (const auto& profile : status.at("profiles")) {
                            const auto& fact = profile.at("fields").at("excluded_interfaces");
                            const auto raw = fact.at("state").get<std::string>();
                            coverage.set("state.firewall_exclusions." + profile.at("profile_name").get<std::string>(),
                                raw == "healthy" ? CapabilityState::healthy : raw == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                                "bounded exclusion query status in record " + pending_id,
                                "returned list only; no verified interface lifetime or effective packet enforcement");
                        }
                    } else firewall_health["commit_failures"] = std::to_string(++failures);
                    firewall_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    firewall_health["pending_durable_acceptance"] = !pending.empty();
                    firewall_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; firewall_health["state"] = "unavailable";
                firewall_health["last_error"] = error.what(); firewall_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.firewall_profiles", CapabilityState::unavailable, error.what(), "firewall profile collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto security_center_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread security_center_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.security_center", CapabilityState::unavailable,
            "no committed WSC category capture", "selected client WSC reports; protection unverified");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; security_center_health["collection_in_progress"] = true;
                      security_center_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    status = panopticon::officer::state::collect_security_center_state();
                    const auto record = record_factory.state("security_center_state", status);
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) (void)diagnostic_stdout.try_submit(pending); }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        security_center_health["committed_snapshots"] = std::to_string(++committed);
                        security_center_health["last_committed_record_id"] = pending_id;
                        security_center_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        security_center_health["last_committed_capture_started_uptime_ms"] = security_center_health["collection_started_uptime_ms"];
                        security_center_health["last_committed_query_status"] = status;
                        const auto value = status["state"] == "unsupported" ? CapabilityState::unsupported :
                            status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.security_center", value, "WSC query status in record " + pending_id,
                            "selected category reports; product inventory and verified protection absent");
                        coverage.set("Q.security_product", value == CapabilityState::unsupported ? CapabilityState::unavailable : value,
                            "selected WSC reports in record " + pending_id,
                            "partial security product posture; Defender/ASR/SmartScreen/tamper/exclusions unverified");
                        for (auto it = status["fields"].begin(); it != status["fields"].end(); ++it) {
                            const auto raw = it.value().at("state").get<std::string>();
                            coverage.set("state.security_center." + it.key(), raw == "unsupported" ? CapabilityState::unsupported :
                                raw == "healthy" ? CapabilityState::healthy :
                                raw == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                                "WSC category getter quality in record " + pending_id,
                                "quality of category report; reported good/poor/snooze is separate from verified protection");
                        }
                    } else security_center_health["commit_failures"] = std::to_string(++failures);
                    security_center_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    security_center_health["pending_durable_acceptance"] = !pending.empty();
                    security_center_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; security_center_health["state"] = "unavailable";
                security_center_health["last_error"] = error.what(); security_center_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.security_center", CapabilityState::unavailable, error.what(), "WSC collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto defender_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread defender_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.defender_status", CapabilityState::unavailable,
            "no committed Defender WMI status capture", "caller-visible Defender WMI reports; protection unverified");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; defender_health["collection_in_progress"] = true;
                      defender_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    status = panopticon::officer::state::collect_defender_status();
                    const auto record = record_factory.state("defender_status", status);
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) (void)diagnostic_stdout.try_submit(pending); }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        defender_health["committed_snapshots"] = std::to_string(++committed);
                        defender_health["last_committed_record_id"] = pending_id;
                        defender_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        defender_health["last_committed_capture_started_uptime_ms"] = defender_health["collection_started_uptime_ms"];
                        defender_health["last_committed_query_status"] = status;
                        const auto value = status["state"] == "unsupported" ? CapabilityState::unsupported :
                            status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.defender_status", value, "Defender WMI query status in record " + pending_id,
                            "selected category reports; product inventory and verified protection absent");
                        for (auto it = status["modern_property_quality"].begin(); it != status["modern_property_quality"].end(); ++it) {
                            const auto raw = it.value().at("state").get<std::string>();
                            coverage.set("state.defender_status." + it.key(), raw == "healthy" ? CapabilityState::healthy :
                                raw == "degraded" ? CapabilityState::degraded : CapabilityState::unavailable,
                                "captured property quality in record " + pending_id,
                                "retained-row getter and interpretation quality; reported mode/tamper distinct from verified enforcement");
                        }
                    } else defender_health["commit_failures"] = std::to_string(++failures);
                    defender_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    defender_health["pending_durable_acceptance"] = !pending.empty();
                    defender_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; defender_health["state"] = "unavailable";
                defender_health["last_error"] = error.what(); defender_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.defender_status", CapabilityState::unavailable, error.what(), "Defender WMI collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    auto device_guard_health = nlohmann::json{{"state", "unavailable"}, {"committed_snapshots", "0"},
        {"commit_failures", "0"}, {"pending_durable_acceptance", false}};
    std::jthread device_guard_worker{[&](std::stop_token stop) {
        std::uint64_t committed = 0, failures = 0, next_capture = 0;
        std::string pending, pending_id; auto status = nlohmann::json::object();
        coverage.set("state.device_guard_state", CapabilityState::unavailable,
            "no committed Device Guard WMI status capture", "caller-visible Device Guard WMI reports; protection unverified");
        while (!stop.stop_requested() && WaitForSingleObject(stop_event.get(), 0) != WAIT_OBJECT_0) {
            try {
                if (pending.empty() && GetTickCount64() >= next_capture) {
                    { std::scoped_lock lock{inventory_mutex}; device_guard_health["collection_in_progress"] = true;
                      device_guard_health["collection_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                    status = panopticon::officer::state::collect_device_guard_state();
                    const auto record = record_factory.state("device_guard_state", status);
                    pending_id = record.at("record_id").get<std::string>(); pending = record.dump();
                }
                if (!pending.empty()) {
                    bool accepted;
                    { std::scoped_lock lock{output_mutex}; accepted = persist_record(pending);
                      if (accepted) (void)diagnostic_stdout.try_submit(pending); }
                    std::scoped_lock lock{inventory_mutex};
                    if (accepted) {
                        pending.clear(); next_capture = GetTickCount64() + 300000;
                        device_guard_health["committed_snapshots"] = std::to_string(++committed);
                        device_guard_health["last_committed_record_id"] = pending_id;
                        device_guard_health["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                        device_guard_health["last_committed_capture_started_uptime_ms"] = device_guard_health["collection_started_uptime_ms"];
                        device_guard_health["last_committed_query_status"] = status;
                        const auto value = status["state"] == "unsupported" ? CapabilityState::unsupported :
                            status["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded;
                        coverage.set("state.device_guard_state", value, "Device Guard WMI query status in record " + pending_id,
                            "selected Device Guard/VBS reports; effective protection and policy authority unverified");
                    } else device_guard_health["commit_failures"] = std::to_string(++failures);
                    device_guard_health["state"] = accepted ? status["state"] : nlohmann::json("unavailable");
                    device_guard_health["pending_durable_acceptance"] = !pending.empty();
                    device_guard_health["collection_in_progress"] = false; SetEvent(health_changed.get());
                }
            } catch (const std::exception& error) {
                std::scoped_lock lock{inventory_mutex}; device_guard_health["state"] = "unavailable";
                device_guard_health["last_error"] = error.what(); device_guard_health["collection_in_progress"] = false;
                if (pending.empty()) next_capture = GetTickCount64() + 30000;
                coverage.set("state.device_guard_state", CapabilityState::unavailable, error.what(), "Device Guard WMI collection unavailable", true);
                SetEvent(health_changed.get());
            }
            WaitForSingleObject(stop_event.get(), 1000);
        }
    }};

    constexpr std::array persistence_sources{
        panopticon::officer::state::PersistenceSource::scheduled_tasks,
        panopticon::officer::state::PersistenceSource::wmi_subscriptions,
        panopticon::officer::state::PersistenceSource::startup};
    constexpr std::array identity_sources{
        panopticon::officer::state::IdentitySource::accounts,
        panopticon::officer::state::IdentitySource::groups,
        panopticon::officer::state::IdentitySource::logons,
        panopticon::officer::state::IdentitySource::terminal_sessions};
    constexpr std::array software_sources{
        panopticon::officer::state::SoftwareSource::msi,
        panopticon::officer::state::SoftwareSource::uninstall_registry};
    const auto native_category = [&](std::size_t index) {
        if (index < persistence_sources.size()) return panopticon::officer::state::persistence_source_name(persistence_sources[index]);
        index -= persistence_sources.size();
        if (index < identity_sources.size()) return panopticon::officer::state::identity_source_name(identity_sources[index]);
        index -= identity_sources.size();
        if (index < software_sources.size()) return panopticon::officer::state::software_source_name(software_sources[index]);
        return index == 0 ? "thread_inventory" : "memory_region_inventory";
    };
    std::array<nlohmann::json, 11> persistence_health;
    std::array<std::jthread, 11> persistence_workers;
    for (std::size_t index = 0; index < persistence_workers.size(); ++index)
        persistence_health[index] = {{"state", "unavailable"}, {"committed_snapshots", "0"}, {"commit_failures", "0"},
            {"pending_durable_acceptance", false}, {"collection_in_progress", false}};
    for (std::size_t index = 0; index < persistence_workers.size(); ++index) {
        persistence_workers[index] = std::jthread{[&, index](std::stop_token stop) {
            const std::string category = native_category(index);
            const auto capability = "state." + category;
            coverage.set(capability, CapabilityState::unavailable, "no committed native state capture", "local caller-visible native state only");
            std::uint64_t failures = 0, committed = 0, next_capture = 0;
            std::uint32_t memory_after_pid = 0;
            const auto cancelled = [&] { return stop.stop_requested() || WaitForSingleObject(stop_event.get(), 0) == WAIT_OBJECT_0; };
            while (!cancelled()) {
                if (GetTickCount64() < next_capture) { WaitForSingleObject(stop_event.get(), 1000); continue; }
                try {
                    const auto capture_started = GetTickCount64();
                    { std::scoped_lock lock{inventory_mutex}; auto& status = persistence_health[index];
                      status["collection_in_progress"] = true; status["collection_started_uptime_ms"] = std::to_string(capture_started); }
                    auto page_ids = nlohmann::json::array();
                    const auto begin = record_factory.state(category + "_begin", {{"format", "paged_" + category + "_begin_v1"},
                        {"inventory_complete", false}, {"collection_started_uptime_ms", std::to_string(capture_started)}});
                    const auto capture_id = begin.at("record_id").get<std::string>();
                    const auto retain = [&](const nlohmann::json& record) {
                        const auto line = record.dump();
                        while (!cancelled()) {
                            // Each caller retains immutable canonical bytes until
                            // journal acceptance; no cross-source output lock.
                            const auto accepted = persist_record(line);
                            if (accepted) (void)diagnostic_stdout.try_submit(line);
                            { std::scoped_lock lock{inventory_mutex}; auto& status = persistence_health[index];
                              status["capture_id"] = capture_id; status["committed_pages"] = std::to_string(page_ids.size());
                              status["pending_durable_acceptance"] = !accepted;
                              if (!accepted) status["commit_failures"] = std::to_string(++failures); }
                            SetEvent(health_changed.get());
                            if (accepted) return true;
                            WaitForSingleObject(stop_event.get(), 1000);
                        }
                        return false;
                    };
                    if (!retain(begin)) break;
                    const auto consume = [&](nlohmann::json page) {
                        page["capture_id"] = capture_id;
                        const auto record = record_factory.state(category + "_page", std::move(page));
                        if (!retain(record)) return false;
                        page_ids.push_back(record.at("record_id"));
                        { std::scoped_lock lock{inventory_mutex}; persistence_health[index]["committed_pages"] = std::to_string(page_ids.size()); }
                        return true;
                    };
                    nlohmann::json manifest;
                    if (index < persistence_sources.size())
                        manifest = panopticon::officer::state::collect_persistence_inventory_pages(persistence_sources[index], consume, {}, cancelled);
                    else if (index < persistence_sources.size() + identity_sources.size())
                        manifest = panopticon::officer::state::collect_identity_inventory_pages(identity_sources[index - persistence_sources.size()], consume, {}, cancelled);
                    else if (index < persistence_sources.size() + identity_sources.size() + software_sources.size())
                        manifest = panopticon::officer::state::collect_software_inventory_pages(software_sources[index - persistence_sources.size() - identity_sources.size()], consume, {}, cancelled);
                    else if (category == "thread_inventory") manifest = panopticon::officer::state::collect_thread_inventory_pages(context->host.id, boot_id, consume, {}, cancelled);
                    else {
                        panopticon::officer::state::MemoryInventoryLimits bounds; bounds.after_pid = memory_after_pid;
                        manifest = panopticon::officer::state::collect_memory_inventory_pages(context->host.id, boot_id, consume, bounds, cancelled);
                    }
                    manifest["format"] = "paged_" + category + "_v1";
                    manifest["capture_id"] = capture_id; manifest["page_record_ids"] = page_ids;
                    const auto record = record_factory.state(category, manifest);
                    if (!retain(record)) break;
                    if (category == "memory_region_inventory") memory_after_pid = manifest.at("next_after_pid").get<std::uint32_t>();
                    { std::scoped_lock lock{inventory_mutex}; auto& status = persistence_health[index];
                      status["state"] = manifest["state"]; status["committed_snapshots"] = std::to_string(++committed);
                      status["last_committed_record_id"] = record["record_id"];
                      status["last_committed_uptime_ms"] = std::to_string(GetTickCount64());
                      status["last_committed_capture_started_uptime_ms"] = std::to_string(capture_started);
                      status["last_committed_query_status"] = nlohmann::json::object();
                      for (const auto* key : {"state", "source", "scope", "enumeration_complete", "query_failure_count", "copy_refusal_count",
                          "entries_delivered", "pages_produced", "bound_exceeded", "consumer_refused", "cancelled", "soft_budget_exceeded"})
                          status["last_committed_query_status"][key] = manifest.at(key);
                      status["collection_in_progress"] = false;
                      coverage.set(capability, manifest["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                          "native query status in committed manifest " + record["record_id"].get<std::string>(), manifest["scope"].get<std::string>()); }
                    if (category == "thread_inventory") coverage.set("C.thread_handle",
                        manifest["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                        "durable sampled thread descriptors and held-thread queries", "owner process instances, handles, interactions and continuous thread lifecycle unverified");
                    if (category == "memory_region_inventory") coverage.set("R.memory_injection",
                        manifest["state"] == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                        "durable bounded held-process virtual-memory metadata", "no content reads, injected-thread/handle/ETW correlation, verdict or complete process/memory coverage");
                    next_capture = GetTickCount64() + 300000; SetEvent(health_changed.get());
                } catch (const std::exception& error) {
                    { std::scoped_lock lock{inventory_mutex}; auto& status = persistence_health[index];
                      status["state"] = "unavailable"; status["last_error"] = error.what(); status["collection_in_progress"] = false; }
                    coverage.set(capability, CapabilityState::unavailable, error.what(), "incomplete begin/pages retained; fresh capture retries after 30 seconds", true);
                    if (category == "thread_inventory") coverage.set("C.thread_handle", CapabilityState::unavailable,
                        error.what(), "thread collection unavailable; handles and interactions not implemented", true);
                    if (category == "memory_region_inventory") coverage.set("R.memory_injection", CapabilityState::unavailable,
                        error.what(), "memory region collection unavailable; no injection verdict or target mutation", true);
                    next_capture = GetTickCount64() + 30000; SetEvent(health_changed.get());
                }
            }
            { std::scoped_lock lock{inventory_mutex}; auto& status = persistence_health[index];
              status["last_source_state"] = status["state"]; status["state"] = "disabled";
              status["reason"] = "endpoint_shutdown"; status["worker_stopped"] = true; status["collection_in_progress"] = false; }
            coverage.set(capability, CapabilityState::disabled, "endpoint_shutdown", "last committed state remains historical evidence");
            if (category == "thread_inventory") coverage.set("C.thread_handle", CapabilityState::disabled,
                "endpoint_shutdown", "thread worker stopped; last committed evidence historical");
            if (category == "memory_region_inventory") coverage.set("R.memory_injection", CapabilityState::disabled,
                "endpoint_shutdown", "memory worker stopped; last committed evidence historical");
        }};
    }

    std::unique_ptr<collectors::UsnJournal> usn_journal;
    std::string usn_init_error;
    try {
        collectors::UsnCallbacks callbacks;
        callbacks.load = [&](const std::string& source) {
            return uploader ? uploader->source_checkpoint(source) : offline_journal->source_checkpoint(source);
        };
        callbacks.make_record = [&](const std::string& volume, nlohmann::json body, bool gap) {
            return record_factory.usn_journal(volume, std::move(body), gap).dump();
        };
        callbacks.commit = [&](const std::string& line, const std::string& source, const std::string& cursor, std::uint64_t revision) {
            bool accepted = false;
            if (uploader) accepted = uploader->enqueue_checkpointed(line, source, cursor, revision);
            else { try { offline_journal->append_checkpointed(line, source, cursor, revision); accepted = true; } catch (const std::exception&) {} }
            if (accepted) (void)diagnostic_stdout.try_submit(line);
            return accepted;
        };
        callbacks.changed = [&] { SetEvent(health_changed.get()); };
        usn_journal = std::make_unique<collectors::UsnJournal>(std::move(callbacks));
    } catch (const std::exception& error) { usn_init_error = error.what(); }

    std::unique_ptr<collectors::WindowsEventLog> windows_logs;
    std::string windows_log_init_error;
    try {
        collectors::WindowsLogCallbacks callbacks;
        callbacks.load = [&](const std::string& source) {
            return uploader ? uploader->source_checkpoint(source) : offline_journal->source_checkpoint(source);
        };
        callbacks.make_record = [&](const std::string& channel, const collectors::DecodedWindowsEvent& event, bool gap) {
            return (gap ? record_factory.gap("winevt:" + channel, event.data) :
                record_factory.windows_event_log(channel, event.data, event.event_time)).dump();
        };
        callbacks.commit = [&](const std::string& line, const std::string& source, const std::string& bookmark, std::uint64_t revision) {
            bool accepted = false;
            if (bookmark.empty()) accepted = persist_record(line);
            else if (uploader) accepted = uploader->enqueue_checkpointed(line, source, bookmark, revision);
            else {
                try { offline_journal->append_checkpointed(line, source, bookmark, revision); accepted = true; }
                catch (const std::exception&) { accepted = false; }
            }
            if (accepted) (void)diagnostic_stdout.try_submit(line);
            return accepted;
        };
        callbacks.changed = [&] { SetEvent(health_changed.get()); };
        windows_logs = std::make_unique<collectors::WindowsEventLog>(std::move(callbacks));
    } catch (const std::exception& error) { windows_log_init_error = error.what(); }

    // Response is a second, independent opt-in: it never starts unless
    // --enable-response was explicitly passed, and any bootstrap/config
    // failure here is reported and disables only the response path --
    // telemetry collection above is already running and continues either
    // way.
    std::unique_ptr<ResponseRuntime> response_runtime;
    std::string response_outcome_init_failure;
    std::thread response_thread;
    std::atomic<bool> stop_response{false};
    if (options->enable_response) {
        if (!options->manager_url) {
            { std::ostringstream diagnostic; diagnostic << "[response] --enable-response requires --manager-url; response is disabled.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
        } else {
            std::string identity_error;
            auto identity = response::load_enrolled_identity(options->identity_path, identity_error);
            if (!identity) {
                if (options->bootstrap_token_path.empty()) {
                    { std::ostringstream diagnostic; diagnostic << "[response] no enrolled identity and no --bootstrap-token-path; response is disabled: "
                              << identity_error << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                } else {
                    std::ifstream token_file{options->bootstrap_token_path};
                    std::string bootstrap_token;
                    if (!token_file || !std::getline(token_file, bootstrap_token) || bootstrap_token.empty()) {
                        { std::ostringstream diagnostic; diagnostic << "[response] cannot read bootstrap token; response is disabled.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                    } else {
                        // Phase 13: enrollment now proves possession of a
                        // locally-generated ECDSA P-256 keypair. Reuse a
                        // previously generated key if one already exists
                        // (e.g. a prior enrollment attempt failed after key
                        // generation but before the server accepted it) --
                        // never silently regenerate over an existing key
                        // file, since that would be indistinguishable from
                        // discarding an already-registered identity.
                        std::string keypair_error;
                        auto keypair = response::load_ec_keypair(options->keypair_path, keypair_error);
                        if (!keypair) {
                            keypair = response::generate_ec_p256_keypair(keypair_error);
                            if (keypair) {
                                std::string keypair_store_error;
                                if (!response::store_ec_keypair(options->keypair_path, *keypair, keypair_store_error)) {
                                    { std::ostringstream diagnostic; diagnostic << "[response] could not persist enrollment key pair: "
                                              << keypair_store_error << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                                    keypair.reset();
                                }
                            }
                        }
                        response::ResponseTransportClient client;
                        std::optional<response::EnrolledIdentity> enrolled;
                        std::string enroll_error;
                        if (!keypair) {
                            enroll_error = "cannot obtain an enrollment key pair: " + keypair_error;
                        } else if (auto nonce = client.request_enrollment_challenge(*options->manager_url, enroll_error)) {
                            enrolled = client.enroll(*options->manager_url, context->agent.id, context->host.id,
                                                      bootstrap_token, *keypair, *nonce, enroll_error);
                        }
                        if (!enrolled) {
                            { std::ostringstream diagnostic; diagnostic << "[response] enrollment failed; response is disabled: " << enroll_error << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                        } else {
                            std::string store_error;
                            if (!response::store_enrolled_identity(options->identity_path, *enrolled, store_error)) {
                                { std::ostringstream diagnostic; diagnostic << "[response] could not persist enrolled identity: " << store_error << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                            }
                            identity = enrolled;
                        }
                    }
                }
            }
            if (identity) {
                if (uploader) uploader->set_bearer_token(identity->agent_id, identity->bearer_token);
                response::ReplayLedger ledger{std::filesystem::path{options->replay_ledger_path}, 4096};
                std::string ledger_error;
                if (!ledger.load(ledger_error)) {
                    { std::ostringstream diagnostic; diagnostic << "[response] replay ledger is unreadable; response is disabled: " << ledger_error
                              << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                } else {
                    response::ResponseConfig response_config;
                    response_config.enabled = true;
                    response_config.file_collection_root = options->file_collection_root;
                    response_config.quarantine_root = options->quarantine_root;
                    response_config.manager_exception_host = options->manager_exception_host;
                    response_config.manager_exception_port =
                        static_cast<std::uint16_t>(options->manager_exception_port);

                    try {
                    std::string scope_error;
                    const auto scope = panopticon::officer::core::sha256_hex(
                        std::to_string(identity->agent_id.size()) + ":" + identity->agent_id +
                        std::to_string(identity->host_id.size()) + ":" + identity->host_id, scope_error);
                    if (!scope) throw std::runtime_error(scope_error);
                    response_runtime = std::make_unique<ResponseRuntime>(
                        *identity, std::move(ledger), response_config, *options->manager_url, *context,
                        [&](const std::string& line) {
                            std::scoped_lock lock{output_mutex};
                            if (persist_record(line)) (void)diagnostic_stdout.try_submit(line);
                            else (void)diagnostic_stderr.try_submit("[response] evidence was not durably accepted");
                        }, std::filesystem::path{options->spool_directory} / "response-results" / *scope);
                    { std::ostringstream diagnostic; diagnostic << "[response] enabled; polling " << *options->manager_url << " every "
                              << options->response_poll_interval_ms << "ms.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                    response_runtime->diagnostic_sink = [&](const std::string& message) { (void)diagnostic_stderr.try_submit(message); };
                    response_thread = std::thread([&] {
                        while (!stop_response.load()) {
                            run_response_cycle(*response_runtime);
                            WaitForSingleObject(stop_event.get(), options->response_poll_interval_ms);
                        }
                    });
                    } catch (const std::exception& error) {
                        response_outcome_init_failure = error.what();
                        response_runtime.reset();
                        { std::ostringstream diagnostic; diagnostic << "[response] durable outcome initialization failed; response disabled: " << error.what() << '\n'; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
                    }
                }
            }
        }
    }

    { std::ostringstream diagnostic; diagnostic << "Officer agent " << telemetry::kAgentVersion
              << " is collecting canonical endpoint records 1.0. Press Ctrl+C to stop.\n"; (void)diagnostic_stderr.try_submit(diagnostic.str()); }
    if (response_runtime) {
        coverage.set("response.process_target", boot_id ? CapabilityState::degraded : CapabilityState::unavailable,
            boot_id ? "schema-2 boot-bound verification active; leases, outcomes and compatibility qualification pending"
                    : "native boot identity unavailable; process actions refuse execution",
            "Windows schema-2 host/boot/PID/full creation ticks; unscoped legacy process actions refused");
        coverage.set("AC.response", CapabilityState::degraded, "typed actions configured; command leases, durable results and full qualification pending", "existing enrolled response runtime");
        coverage.set("AD.isolation", CapabilityState::degraded, "IPv6, persistent recovery and transactional failure handling pending", "configured IPv4 WFP actions");
    } else {
        coverage.set("response.process_target", CapabilityState::disabled,
            "response runtime is not configured", "boot-bound process command verification");
    }
    if (!response_outcome_init_failure.empty()) {
        coverage.set("AC.response", CapabilityState::unavailable, response_outcome_init_failure,
            "durable outcome initialization failed; response has not started", true);
        coverage.set("response.process_target", CapabilityState::unavailable, response_outcome_init_failure,
            "response disabled because result durability could not initialize", true);
    }
    auto source_health = nlohmann::json::object();
    const auto supervise_sources = [&] {
        bool changed = false;
        for (auto& source : supervised_sources) {
            const auto current = source.collector->status();
            const auto name = std::string{source.collector->name()};
            source_health[name] = panopticon::officer::health::source_status_json(current);
            const auto sample_uptime = GetTickCount64();
            source_health[name]["sample_uptime_ms"] = std::to_string(sample_uptime);
            changed |= source.history.observe(current, sample_uptime);
            const bool blind = !current.running || (name == "sysmon" && current.continuity_fault);
            coverage.set("sensor." + name, blind ? CapabilityState::blind : CapabilityState::degraded,
                blind ? "consumer stopped or subscription history missing; reconciliation required" :
                current.continuity_fault ? "source reports discarded events or buffers; continuity unverified" :
                "consumer active; complete provider coverage and source continuity unverified",
                "sampled collector supervision; source counters when available");
            if (source.pending_record.empty() && !source.history.empty()) {
                auto gap = source.history.front();
                gap["source"] = name;
                source.pending_record = record_factory.gap(name, std::move(gap)).dump();
            }
            if (!source.pending_record.empty()) {
                // Retry identical canonical bytes while subsequent observations
                // remain in bounded history. No callback performs gap journal I/O.
                std::scoped_lock lock{output_mutex};
                if (persist_record(source.pending_record)) {
                    (void)diagnostic_stdout.try_submit(source.pending_record);
                    source.history.acknowledge_front();
                    source.pending_record.clear();
                }
            }
            source_health[name]["gap_pending_durable_acceptance"] = !source.pending_record.empty() || source.history.pending();
            source_health[name]["supervisor_history"] = source.history.snapshot();
        }
        // Domain visibility reflects its required sensors, even if a different
        // collector remains active. Keep all partial domains degraded otherwise.
        bool process_visible = false;
        bool sysmon_visible = false;
        for (const auto& source : supervised_sources) {
            const auto name = std::string{source.collector->name()};
            const auto& status = source_health[name];
            const bool visible = status["running"].get<bool>() &&
                !(name == "sysmon" && status["continuity_fault"].get<bool>());
            process_visible |= visible;
            if (name == "sysmon") sysmon_visible = visible;
        }
        coverage.set("state.process_stop", process_visible ? CapabilityState::degraded : CapabilityState::blind,
            process_visible ? "ETW ID 2/Sysmon ID 5 decode path enabled; source configuration and live lifecycle unqualified" : "no eligible process source; stop visibility blind",
            "exact native creation token or source-scoped GUID only; no PID-only tombstone, full lifecycle or ancestry assertion");
        if (!process_visible)
            coverage.set("B.process", CapabilityState::blind, "no subscribed process source has verified consumer availability", "process-start adapters");
        if (!sysmon_visible && options->source != SourceSelection::etw) {
            for (const auto* id : {"H.filesystem", "I.registry", "N.network"})
                coverage.set(id, CapabilityState::blind, "Sysmon consumer unavailable or subscription history missing", "no native fallback implemented for this subset");
        }
        return changed;
    };
    std::string pending_handoff_gap;
    panopticon::officer::health::StateCaptureGapBuffer state_capture_history;
    std::string pending_state_capture_gap;
    std::uint64_t state_capture_gap_commit_failures = 0;
    std::uint64_t committed_handoff_refusals = 0, committed_handoff_failures = 0;
    std::uint64_t pending_handoff_refusals = 0, pending_handoff_failures = 0;
    const auto emit_health = [&](bool display = true) {
        const auto log_health = windows_logs ? windows_logs->snapshot() : nlohmann::json{{"state", "unavailable"}, {"reason", windows_log_init_error}};
        if (windows_logs) for (const auto& channel : log_health.at("channels")) {
            const auto state = channel.at("state").get<std::string>();
            coverage.set("log." + channel.at("channel").get<std::string>(), state == "disabled" ? CapabilityState::disabled :
                state == "blind" ? CapabilityState::blind : state == "unavailable" ? CapabilityState::unavailable : CapabilityState::degraded,
                channel.at("reason").get<std::string>(), "native retained channel records and atomic encrypted bookmark; policy and continuity unverified");
        }
        else coverage.set("AA.windows_event_log", CapabilityState::unavailable, windows_log_init_error, "native log workers unavailable");
        const auto stdout_health = diagnostic_stdout.snapshot();
        const auto stderr_health = diagnostic_stderr.snapshot();
        for (const auto& entry : {std::pair{"pipeline.diagnostic_stdout", stdout_health}, std::pair{"pipeline.diagnostic_stderr", stderr_health}})
            coverage.set(entry.first, entry.second["state"] == "unavailable" ? CapabilityState::unavailable :
                entry.second["state"] == "disabled" ? CapabilityState::disabled : CapabilityState::degraded,
                "best-effort display; independent of durable telemetry acceptance", "bounded volatile queue and native write counters");
        auto health = coverage.snapshot(context->agent.id, context->host.id);
        health["service_host"] = {{"mode", service_stop ? "scm" : "console"},
            {"running_semantics", "runtime initialized and source startup attempted; independent coverage applies"},
            {"shutdown_deadline", "native joins may block; SCM checkpoints advance only on actual progress"},
            {"service_qualification", "incomplete"}};

        health["sources"] = source_health;
        health["windows_event_log"] = log_health;
        health["usn_journal"] = usn_journal ? usn_journal->snapshot() : nlohmann::json{{"state", "unavailable"}, {"reason", usn_init_error}};
        const auto usn_state = health["usn_journal"]["state"].get<std::string>();
        coverage.set("filesystem.usn_journal", usn_state == "degraded" ? CapabilityState::degraded :
            usn_state == "blind" ? CapabilityState::blind : usn_state == "disabled" ? CapabilityState::disabled : CapabilityState::unavailable,
            "per-volume native USN query/read and durable cursor status", "source-native file IDs/names/reasons; full paths, actors, baseline and complete filesystem coverage unverified");
        { std::scoped_lock lock{inventory_mutex};
          health["host_inventory"] = inventory_health;
          health["process_inventory"] = process_inventory_health;
          health["service_inventory"] = service_inventory_health;
          health["loaded_driver_inventory"] = loaded_driver_health;
          health["socket_inventory"] = socket_health;
          health["route_inventory"] = route_health;
          health["ip_interface_inventory"] = ip_interface_health;
          health["firewall_profile_state"] = firewall_health;
          health["firewall_rule_inventory"] = firewall_rule_health;
          health["security_center_state"] = security_center_health;
          health["defender_status"] = defender_health;
          health["device_guard_state"] = device_guard_health;
          for (std::size_t index = 0; index < persistence_workers.size(); ++index)
              health[native_category(index)] = persistence_health[index];
          health["capabilities"] = coverage.snapshot(context->agent.id, context->host.id).at("capabilities"); }
        health["process_state_admission_failures"] = record_factory.process_state_admission_failures();
        if (response_runtime) health["response_results"] = {
            {"state", "degraded"}, {"pending_durable_results", std::to_string(response_runtime->pending_results.load())},
            {"durability_or_receipt_failures", std::to_string(response_runtime->result_commit_failures.load())},
            {"limitations", "lease fencing, interrupted-action reconciliation and full qualification pending"}};
        if (response_runtime) {
            const auto success = response_runtime->last_poll_success_uptime.load();
            const bool failed = response_runtime->poll_state.load() == 2;
            coverage.set("response.command_channel", !success ? CapabilityState::unavailable : failed ? CapabilityState::blind : CapabilityState::degraded,
                !success ? "no valid authenticated poll observed" : failed ? "latest poll or decoding failed" : "durable-mode polls observed; leases and freshness qualification pending",
                "authenticated command poll and bounded strict decoder");
            try {
                const auto stats = response_runtime->inbox.stats();
                health["response_inbox"] = {{"state", stats.commands_unknown_state ? "blind" : "degraded"},
                    {"received", std::to_string(stats.commands_received)}, {"executing", std::to_string(stats.commands_executing)},
                    {"result_ready", std::to_string(stats.command_results_ready)}, {"outboxed", std::to_string(stats.commands_outboxed)},
                    {"unknown_state", std::to_string(stats.commands_unknown_state)}, {"retained_plaintext_bytes", std::to_string(stats.retained_bytes)},
                    {"poll_failures", std::to_string(response_runtime->poll_failures.load())}, {"parse_failures", std::to_string(response_runtime->parse_failures.load())},
                    {"last_valid_poll_uptime_ms", success ? nlohmann::json(std::to_string(success)) : nlohmann::json(nullptr)}};
            } catch (const std::exception& error) {
                health["response_inbox"] = {{"state", "unavailable"}, {"reason", error.what()}};
            }
            { std::scoped_lock lock{inventory_mutex};
              health["host_inventory"] = inventory_health;
              health["process_inventory"] = process_inventory_health;
              health["service_inventory"] = service_inventory_health;
              health["loaded_driver_inventory"] = loaded_driver_health;
          health["socket_inventory"] = socket_health;
          health["route_inventory"] = route_health;
          health["ip_interface_inventory"] = ip_interface_health;
          health["firewall_profile_state"] = firewall_health;
          health["firewall_rule_inventory"] = firewall_rule_health;
          health["security_center_state"] = security_center_health;
          health["defender_status"] = defender_health;
          health["device_guard_state"] = device_guard_health;
          for (std::size_t index = 0; index < persistence_workers.size(); ++index)
              health[native_category(index)] = persistence_health[index];
              health["capabilities"] = coverage.snapshot(context->agent.id, context->host.id).at("capabilities"); }
        }
        health["pipeline"] = {{"normalization_or_serialization_failures", std::to_string(normalization_failures.load())},
            {"failure_evidence_committed", std::to_string(failure_evidence_committed.load())},
            {"observation_admission_failures", std::to_string(observation_admission_failures.load())}};
        const auto handoff = raw_handoff.stats();
        health["pipeline"]["diagnostic_stdout"] = stdout_health;
        health["pipeline"]["diagnostic_stderr"] = stderr_health;
        health["pipeline"]["raw_handoff"] = {{"state", "degraded"},
            {"scope", "owned decoded events in RAM; callback return is not durable acceptance; counters reset on restart"},
            {"admitted_volatile", std::to_string(handoff.admitted)}, {"completed_durable", std::to_string(handoff.completed)},
            {"failed", std::to_string(handoff.failed)}, {"refused", std::to_string(handoff.refused)},
            {"contention_refused", std::to_string(handoff.contention_refused)}, {"exception_refused", std::to_string(handoff.exception_refused)},
            {"owned_events", std::to_string(handoff.owned_events)}, {"charged_bytes", std::to_string(handoff.charged_bytes)},
            {"event_limit", std::to_string(handoff.event_limit)}, {"byte_limit", std::to_string(handoff.byte_limit)},
            {"fixed_ring_bytes", std::to_string(handoff.fixed_ring_bytes)},
            {"contention_refused_scope", "retired try-lock refusal policy; current preallocated ring waits for its short mutex section"},
            {"byte_scope", "variant objects and owned string capacities including in-flight item; allocator/worker RSS excluded"},
            {"accepting", handoff.accepting}};
        if (uploader) {
            const auto delivery_health = uploader->health();
            health["delivery"] = {{"durability_state", delivery_health.durability_state}, {"transport_state", delivery_health.transport_state},
                {"commit_failures", delivery_health.commit_failures}, {"transport_failures", delivery_health.transport_failures},
                {"invalid_receipts", delivery_health.invalid_receipts},
                {"capture_age_state", delivery_health.capture_age_state},
                {"freshness_challenge_failures", delivery_health.freshness_challenge_failures},
                {"last_error", delivery_health.last_error}};
        }
        if (uploader || offline_journal) {
            try {
                const auto stats = uploader ? uploader->journal_stats() : offline_journal->stats();
                health["journal"] = {{"pending_events", stats.pending_events}, {"dead_letter_events", stats.dead_letter_events},
                    {"acknowledged_events", stats.acknowledged_events}, {"retained_bytes", stats.retained_bytes},
                    {"process_history", {{"state", "degraded"}, {"records", std::to_string(stats.process_history_records)},
                        {"retained_bytes", std::to_string(stats.process_history_bytes)}, {"delivery_independent", true},
                        {"scope", "exact canonical births/stops archived with acceptance; prior retired evidence, source continuity and durable ancestry reconstruction unverified"}}},
                    {"process_graph", {{"state", "degraded"}, {"indexed_records", std::to_string(stats.process_graph_indexed)},
                        {"unresolved_or_refused_records", std::to_string(stats.process_graph_unresolved)},
                        {"archive_backlog", std::to_string(stats.process_history_records - stats.process_graph_indexed)},
                        {"scope", "exact identity index over retained lifecycle originals; PID-only ancestry, creator relationships, source continuity and alias promotion unverified"}}},
                    {"disk_bytes", stats.disk_bytes}, {"legacy_gaps", stats.legacy_gaps},
                    {"storage_admission", {{"state", "degraded"}, {"scope", "sampled DB/WAL/SHM logical file sizes and caller-available volume bytes; no reservation or aggregate budget"},
                        {"physical_admission_limit", std::to_string(stats.physical_admission_limit)},
                        {"minimum_free_bytes", std::to_string(stats.minimum_free_bytes)},
                        {"caller_available_bytes", std::to_string(stats.caller_available_bytes)},
                        {"refusals", std::to_string(stats.storage_admission_refusals)},
                        {"refusals_scope", "current journal object lifetime; not durable loss accounting"}}}};
                if (stats.process_graph_indexed < stats.process_history_records) {
                    try {
                        const auto rebuilt = uploader ? uploader->rebuild_process_graph(32, 2u * 1024 * 1024) :
                            offline_journal->rebuild_process_graph(32, 2u * 1024 * 1024);
                        health["journal"]["process_graph"]["backfilled_this_pass"] = std::to_string(rebuilt);
                        health["journal"]["process_graph"]["backlog_sample_scope"] = "before this bounded rebuild pass";
                    } catch (const std::exception& graph_error) {
                        health["journal"]["process_graph"]["state"] = "unavailable";
                        health["journal"]["process_graph"]["last_error"] = graph_error.what();
                    }
                }
            } catch (const std::exception& journal_error) {
                health["journal"] = {{"storage_admission", {{"state", "unavailable"}, {"reason", journal_error.what()}}}};
                health["delivery"]["durability_state"] = "degraded";
                health["delivery"]["last_error"] = journal_error.what();
            }
        }
        std::scoped_lock lock{output_mutex};
        if (pending_handoff_gap.empty() && (handoff.refused > committed_handoff_refusals || handoff.failed > committed_handoff_failures)) {
            pending_handoff_refusals = handoff.refused; pending_handoff_failures = handoff.failed;
            pending_handoff_gap = record_factory.gap("raw_handoff", {
                {"scope", "all selected decoded-event sources in this collector epoch; counters reset on restart"},
                {"refused_observations", std::to_string(handoff.refused - committed_handoff_refusals)},
                {"failed_worker_completions", std::to_string(handoff.failed - committed_handoff_failures)},
                {"failed_completion_scope", "worker exceptions; durable record may already exist; not a proven lost-native-event count"},
                {"refused_total", std::to_string(handoff.refused)}, {"failed_total", std::to_string(handoff.failed)},
                {"abrupt_exit_loss", "unknown; volatile ownership is not a durable acceptance receipt"}}).dump();
        }
        if (!pending_handoff_gap.empty() && persist_record(pending_handoff_gap)) {
            pending_handoff_gap.clear(); committed_handoff_refusals = pending_handoff_refusals;
            committed_handoff_failures = pending_handoff_failures;
        }
        health["pipeline"]["raw_handoff"]["loss_gap_pending_durable_acceptance"] = !pending_handoff_gap.empty();
        const auto freshness_uptime = GetTickCount64();
        panopticon::officer::health::apply_state_capture_freshness(health, freshness_uptime);
        state_capture_history.observe(health, freshness_uptime);
        if (pending_state_capture_gap.empty() && !state_capture_history.empty())
            pending_state_capture_gap = record_factory.gap("state.capture_freshness", state_capture_history.front()).dump();
        if (!pending_state_capture_gap.empty()) {
            if (persist_record(pending_state_capture_gap)) {
                (void)diagnostic_stdout.try_submit(pending_state_capture_gap);
                state_capture_history.acknowledge_front(); pending_state_capture_gap.clear();
            } else ++state_capture_gap_commit_failures;
        }
        health["state_capture_history"] = state_capture_history.snapshot();
        health["state_capture_history"]["commit_failures"] = std::to_string(state_capture_gap_commit_failures);
        health["state_capture_history"]["gap_pending_durable_acceptance"] = state_capture_history.pending();
        if (persist_record(record_factory.health(health).dump())) {
            if (display) (void)diagnostic_stderr.try_submit(health.dump());
        }
        else coverage.set("AG.durability", CapabilityState::degraded, "health record commit failed", "durable health capture", true);
    };
    const HANDLE wait_handles[]{stop_event.get(), health_changed.get()};
    if (ready) ready(); // Workers/source startup attempted; coverage may be degraded.
    auto next_health = GetTickCount64();
    bool health_notification = true;
    for (;;) {
        if (supervise_sources()) health_notification = true;
        const auto now = GetTickCount64();
        if (health_notification || now >= next_health) {
            emit_health();
            next_health = now + 30000;
        }
        const auto wait = WaitForMultipleObjects(2, wait_handles, FALSE, 1000);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
        health_notification = wait == WAIT_OBJECT_0 + 1;
    }
    (void)diagnostic_stderr.try_submit("Stopping Officer collectors...");
    if (stopping) stopping();
    inventory_worker.request_stop();
    process_inventory_worker.request_stop();
    service_inventory_worker.request_stop();
    loaded_driver_worker.request_stop();
    socket_worker.request_stop();
    route_worker.request_stop();
    ip_interface_worker.request_stop();
    firewall_worker.request_stop();
    firewall_rule_worker.request_stop();
    security_center_worker.request_stop();
    defender_worker.request_stop();
    device_guard_worker.request_stop();
    for (auto& worker : persistence_workers) worker.request_stop();
    if (windows_logs) windows_logs->stop();
    if (usn_journal) usn_journal->stop();
    inventory_worker.join();
    process_inventory_worker.join();
    service_inventory_worker.join();
    loaded_driver_worker.join();
    socket_worker.join();
    route_worker.join();
    ip_interface_worker.join();
    firewall_worker.join();
    firewall_rule_worker.join();
    security_center_worker.join();
    defender_worker.join();
    device_guard_worker.join();
    for (auto& worker : persistence_workers) worker.join();
    if (progress) progress(); // Native inventory workers have joined.

    for (auto iterator = all_collectors.rbegin(); iterator != all_collectors.rend(); ++iterator) {
        (*iterator)->stop();
    }
    raw_handoff.close();
    if (progress) progress(); // Source consumers and raw handoff have drained.
    supervise_sources();
    emit_health();
    stop_response.store(true);
    if (response_thread.joinable()) {
        response_thread.join();
    }
    diagnostic_stdout.close();
    diagnostic_stderr.close();
    emit_health(false);  // Final writer accounting is retained even when display is closed.
    if (uploader) {
        uploader->stop();  // accepted observations are already durably committed
    }
    if (progress) progress(); // Delivery worker closed; journal ownership retained until return.
    SetConsoleCtrlHandler(&console_control_handler, FALSE);
    shutdown_event.store(nullptr);
    // Final durable health carries shutdown evidence; no synchronous display on exit.
    return 0;
}

int main(int argc, char* argv[]) {
    bool service = false, help = false;
    std::vector<char*> arguments{argv[0]};
    for (int index = 1; index < argc; ++index) {
        if (std::string_view(argv[index]) == "--service") service = true;
        else arguments.push_back(argv[index]);
        help |= std::string_view(argv[index]) == "--help" || std::string_view(argv[index]) == "-h";
    }
    arguments.push_back(nullptr);
    const int count = static_cast<int>(arguments.size() - 1);
    if (service && !help) return panopticon::officer::runtime::run_service(
        [&](HANDLE stop, const std::function<void()>& progress, const std::function<void()>& ready,
            const std::function<void()>& stopping) { return run_endpoint(count, arguments.data(), stop, progress, ready, stopping); });
    try { return run_endpoint(count, arguments.data()); }
    catch (const std::exception& error) { std::cerr << "Officer fatal runtime error: " << error.what() << '\n'; return 6; }
}
