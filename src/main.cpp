#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/uploader.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include "panopticon/officer/pipeline/serializer.hpp"
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

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
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

// Phase 1 tracer bullet: --manager-url is additive, never a replacement for
// stdout. Omitting it reproduces exactly today's behavior (there is no
// --stdout flag to omit -- stdout output is unconditional, see main()).
//
// Response (command polling/execution) is a second, independent opt-in on
// top of that: --enable-response requires --manager-url and does nothing at
// all unless explicitly passed, so every existing telemetry-only deployment
// is unaffected.
struct CliOptions {
    SourceSelection source = SourceSelection::all;
    std::optional<std::string> manager_url;
    bool insecure_tls = false;
    bool enable_response = false;
    std::string identity_path = "officer-identity.txt";
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
                      << " [--source all|etw|sysmon] [--manager-url <https-url>] [--insecure-tls]\n"
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
        if (argument == "--identity-path" || argument == "--bootstrap-token-path" ||
            argument == "--file-collection-root" || argument == "--quarantine-root" ||
            argument == "--manager-exception-host") {
            if (index + 1 >= argc) {
                std::cerr << argument << " requires a value. Use --help for usage.\n";
                return std::nullopt;
            }
            const std::string value{argv[++index]};
            if (argument == "--identity-path") options.identity_path = value;
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
// thread below reuses it across every poll interval so the in-memory half
// of CommandGate's replay defense (command_gate::seen_) persists for the
// life of the process, on top of the durable ledger surviving a restart.
struct ResponseRuntime {
    response::ResponseTransportClient client;
    response::EnrolledIdentity identity;
    response::ReplayLedger ledger;
    response::CommandGate gate;
    response::ResponseConfig config;
    std::string manager_url;
    pipeline::NormalizationContext context;
    std::function<void(const std::string&)> emit_line;

    // CommandGate holds a std::mutex, so it (and therefore ResponseRuntime)
    // is neither copyable nor movable -- this constructor builds `gate` in
    // place from the already-constructed `identity`/`ledger` members
    // (declaration order above guarantees they exist first) instead of
    // building a temporary ResponseRuntime and moving/copying it, which
    // would not compile.
    ResponseRuntime(response::EnrolledIdentity identity_in, response::ReplayLedger ledger_in,
                     response::ResponseConfig config_in, std::string manager_url_in,
                     pipeline::NormalizationContext context_in, std::function<void(const std::string&)> emit_line_in)
        : identity(std::move(identity_in)),
          ledger(std::move(ledger_in)),
          gate(identity.agent_id, identity.host_id,
               [] {
                   return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                          std::chrono::system_clock::now().time_since_epoch())
                                                          .count());
               },
               &ledger),
          config(std::move(config_in)),
          manager_url(std::move(manager_url_in)),
          context(std::move(context_in)),
          emit_line(std::move(emit_line_in)) {}
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

    switch (received.action) {
        case ActionType::kill_process: {
            std::string error;
            if (!response::terminate_process(received.process_target, error).value_or(false)) {
                receipt.code = ReceiptCode::execution_failed;
                receipt.summary = "kill_process failed: " + error;
            }
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
void run_response_cycle(ResponseRuntime& runtime) {
    std::string poll_error;
    const auto poll = runtime.client.poll_commands(runtime.manager_url, runtime.identity, poll_error);
    if (!poll) {
        std::cerr << "[response] command poll failed: " << poll_error << '\n';
        return;
    }
    std::string parse_error;
    const auto commands = response::parse_command_poll_response(*poll, 32, parse_error);
    if (!commands) {
        std::cerr << "[response] command poll response rejected: " << parse_error << '\n';
        return;
    }
    for (const auto& received : *commands) {
        auto receipt = runtime.gate.validate_and_mark(received);
        if (receipt.code == response::ReceiptCode::succeeded) {
            // Best-effort DISPATCHED -> ACCEPTED acknowledgement; outcome
            // intentionally ignored (see transport.hpp).
            (void)runtime.client.accept_command(runtime.manager_url, runtime.identity, received.command_id);
        }
        receipt = execute_command(runtime, received, receipt);
        std::string serialize_error;
        const auto result =
            response::serialize_command_result(receipt, runtime.config.maximum_event_bytes, serialize_error);
        if (!result) {
            std::cerr << "[response] cannot serialize result for " << action_name(received.action) << ": "
                      << serialize_error << '\n';
            continue;
        }
        (void)runtime.client.submit_command_result(runtime.manager_url, runtime.identity, *result);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    bool help_requested = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        help_requested = help_requested || argument == "--help" || argument == "-h";
    }
    const auto options = parse_arguments(argc, argv);
    if (!options) {
        return help_requested ? 0 : 2;
    }

    std::string error;
    const auto context = runtime_context(error);
    if (!context) {
        std::cerr << "Officer startup failed: " << error << '\n';
        return 3;
    }
    if (!process_is_elevated()) {
        std::cerr << "Warning: Officer is not elevated. ETW or Sysmon subscription may be denied.\n";
    }

    UniqueHandle stop_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (stop_event.get() == nullptr) {
        std::cerr << "Officer could not create its shutdown event.\n";
        return 3;
    }
    shutdown_event.store(stop_event.get());
    if (!SetConsoleCtrlHandler(&console_control_handler, TRUE)) {
        shutdown_event.store(nullptr);
        std::cerr << "Officer could not install its Ctrl+C handler.\n";
        return 3;
    }

    // --manager-url is additive: stdout output (below) is unconditional,
    // exactly as it is with no flags at all. Constructing Uploader here
    // starts its background thread; enqueue() from collector callbacks is
    // just a mutex-protected push, so no network call ever happens on an
    // ETW/Sysmon callback thread.
    std::unique_ptr<delivery::Uploader> uploader;
    if (options->manager_url) {
        delivery::DeliveryConfig delivery_config;
        delivery_config.manager_url = *options->manager_url;
        delivery_config.verify_tls = !options->insecure_tls;
        uploader = std::make_unique<delivery::Uploader>(delivery_config, context->agent.id);
        std::cerr << "Delivering events to " << delivery_config.manager_url
                   << (delivery_config.verify_tls ? "" : " (TLS verification disabled)") << '\n';
    }

    std::mutex output_mutex;
    const auto emit_normalized =
        [&](const std::optional<telemetry::PanopticonEvent>& normalized,
            const std::string& normalization_error) {
            std::scoped_lock lock{output_mutex};
            if (!normalized) {
                std::cerr << "[pipeline] " << normalization_error << '\n';
                return;
            }
            const std::string line = pipeline::serialize_event(*normalized);
            std::cout << line << '\n';
            std::cout.flush();
            if (uploader) {
                uploader->enqueue(line);
            }
        };
    const collectors::RawEventSink event_sink = [&](telemetry::RawEvent raw_event) {
        std::visit(
            [&](auto&& raw) {
                using Event = std::decay_t<decltype(raw)>;
                std::string normalization_error;
                if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>) {
                    enrichment::EnrichedProcessEvent enriched;
                    enriched.raw = std::move(raw);
                    enriched.process_name = file_name(enriched.raw.executable);
                    enriched.parent_name = file_name(enriched.raw.parent_executable);
                    enriched.sha256 = enriched.raw.sha256;
                    populate_user(enriched.raw.user_name, enriched.user);
                    emit_normalized(
                        pipeline::normalize_process_event(enriched, *context, normalization_error),
                        normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawNetworkEvent>) {
                    emit_normalized(
                        pipeline::normalize_network_event(raw, *context, normalization_error),
                        normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawFileEvent>) {
                    emit_normalized(
                        pipeline::normalize_file_event(raw, *context, normalization_error),
                        normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawRegistryEvent>) {
                    emit_normalized(
                        pipeline::normalize_registry_event(raw, *context, normalization_error),
                        normalization_error);
                } else if constexpr (std::is_same_v<Event, telemetry::RawImageLoadEvent>) {
                    emit_normalized(
                        pipeline::normalize_image_load_event(raw, *context, normalization_error),
                        normalization_error);
                }
            },
            std::move(raw_event));
    };
    const collectors::CollectorErrorSink error_sink =
        [&](std::string_view collector, std::string message) {
            std::scoped_lock lock{output_mutex};
            std::cerr << '[' << collector << "] " << message << '\n';
        };

    std::vector<std::unique_ptr<collectors::TelemetryCollector>> all_collectors;
    if (options->source == SourceSelection::all || options->source == SourceSelection::etw) {
        all_collectors.push_back(std::make_unique<collectors::EtwProcessCollector>());
    }
    if (options->source == SourceSelection::all || options->source == SourceSelection::sysmon) {
        all_collectors.push_back(std::make_unique<collectors::SysmonEventCollector>());
    }

    std::size_t started = 0;
    for (auto& collector : all_collectors) {
        error.clear();
        if (collector->start(event_sink, error_sink, error)) {
            ++started;
            std::cerr << "Started " << collector->name() << " collector.\n";
        } else {
            std::cerr << "Could not start " << collector->name() << " collector: "
                      << error << '\n';
        }
    }
    if (started == 0) {
        SetConsoleCtrlHandler(&console_control_handler, FALSE);
        shutdown_event.store(nullptr);
        std::cerr << "Officer could not start any telemetry collectors.\n";
        return 4;
    }

    // Response is a second, independent opt-in: it never starts unless
    // --enable-response was explicitly passed, and any bootstrap/config
    // failure here is reported and disables only the response path --
    // telemetry collection above is already running and continues either
    // way.
    std::unique_ptr<ResponseRuntime> response_runtime;
    std::thread response_thread;
    std::atomic<bool> stop_response{false};
    if (options->enable_response) {
        if (!options->manager_url) {
            std::cerr << "[response] --enable-response requires --manager-url; response is disabled.\n";
        } else {
            std::string identity_error;
            auto identity = response::load_enrolled_identity(options->identity_path, identity_error);
            if (!identity) {
                if (options->bootstrap_token_path.empty()) {
                    std::cerr << "[response] no enrolled identity and no --bootstrap-token-path; response is disabled: "
                              << identity_error << '\n';
                } else {
                    std::ifstream token_file{options->bootstrap_token_path};
                    std::string bootstrap_token;
                    if (!token_file || !std::getline(token_file, bootstrap_token) || bootstrap_token.empty()) {
                        std::cerr << "[response] cannot read bootstrap token; response is disabled.\n";
                    } else {
                        response::ResponseTransportClient client;
                        std::string enroll_error;
                        auto enrolled = client.enroll(*options->manager_url, context->agent.id, context->host.id,
                                                       bootstrap_token, enroll_error);
                        if (!enrolled) {
                            std::cerr << "[response] enrollment failed; response is disabled: " << enroll_error << '\n';
                        } else {
                            std::string store_error;
                            if (!response::store_enrolled_identity(options->identity_path, *enrolled, store_error)) {
                                std::cerr << "[response] could not persist enrolled identity: " << store_error << '\n';
                            }
                            identity = enrolled;
                        }
                    }
                }
            }
            if (identity) {
                response::ReplayLedger ledger{std::filesystem::path{options->replay_ledger_path}, 4096};
                std::string ledger_error;
                if (!ledger.load(ledger_error)) {
                    std::cerr << "[response] replay ledger is unreadable; response is disabled: " << ledger_error
                              << '\n';
                } else {
                    response::ResponseConfig response_config;
                    response_config.enabled = true;
                    response_config.file_collection_root = options->file_collection_root;
                    response_config.quarantine_root = options->quarantine_root;
                    response_config.manager_exception_host = options->manager_exception_host;
                    response_config.manager_exception_port =
                        static_cast<std::uint16_t>(options->manager_exception_port);

                    response_runtime = std::make_unique<ResponseRuntime>(
                        *identity, std::move(ledger), response_config, *options->manager_url, *context,
                        [&](const std::string& line) {
                            std::scoped_lock lock{output_mutex};
                            std::cout << line << '\n';
                            std::cout.flush();
                            if (uploader) uploader->enqueue(line);
                        });
                    std::cerr << "[response] enabled; polling " << *options->manager_url << " every "
                              << options->response_poll_interval_ms << "ms.\n";
                    response_thread = std::thread([&] {
                        while (!stop_response.load()) {
                            run_response_cycle(*response_runtime);
                            WaitForSingleObject(stop_event.get(), options->response_poll_interval_ms);
                        }
                    });
                }
            }
        }
    }

    std::cerr << "Officer agent " << telemetry::kAgentVersion
              << " is collecting Panopticon schema " << telemetry::kSchemaVersion
              << " events. Press Ctrl+C to stop.\n";
    WaitForSingleObject(stop_event.get(), INFINITE);
    std::cerr << "Stopping Officer collectors...\n";

    for (auto iterator = all_collectors.rbegin(); iterator != all_collectors.rend(); ++iterator) {
        (*iterator)->stop();
    }
    stop_response.store(true);
    if (response_thread.joinable()) {
        response_thread.join();
    }
    if (uploader) {
        uploader->stop();  // flushes whatever is still pending, best-effort
    }
    SetConsoleCtrlHandler(&console_control_handler, FALSE);
    shutdown_event.store(nullptr);
    std::cerr << "Officer stopped cleanly.\n";
    return 0;
}
