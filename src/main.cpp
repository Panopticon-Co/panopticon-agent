#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/uploader.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include "panopticon/officer/pipeline/serializer.hpp"
#include "panopticon/officer/telemetry/panopticon_event.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace {

namespace collectors = panopticon::officer::collectors;
namespace delivery = panopticon::officer::delivery;
namespace enrichment = panopticon::officer::enrichment;
namespace pipeline = panopticon::officer::pipeline;
namespace telemetry = panopticon::officer::telemetry;

enum class SourceSelection { all, etw, sysmon };

// Phase 1 tracer bullet: --manager-url is additive, never a replacement for
// stdout. Omitting it reproduces exactly today's behavior (there is no
// --stdout flag to omit -- stdout output is unconditional, see main()).
struct CliOptions {
    SourceSelection source = SourceSelection::all;
    std::optional<std::string> manager_url;
    bool insecure_tls = false;
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
                      << "  --source        Select live collectors (default: all).\n"
                      << "  --manager-url   Also deliver events to a Panopticon manager over HTTPS.\n"
                      << "                  Stdout output is unaffected either way.\n"
                      << "  --insecure-tls  Skip TLS certificate validation (bring-up only).\n"
                      << "Run elevated and press Ctrl+C to stop cleanly.\n";
            return std::nullopt;
        }
        if (argument == "--insecure-tls") {
            options.insecure_tls = true;
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

    std::cerr << "Officer agent " << telemetry::kAgentVersion
              << " is collecting Panopticon schema " << telemetry::kSchemaVersion
              << " events. Press Ctrl+C to stop.\n";
    WaitForSingleObject(stop_event.get(), INFINITE);
    std::cerr << "Stopping Officer collectors...\n";

    for (auto iterator = all_collectors.rbegin(); iterator != all_collectors.rend(); ++iterator) {
        (*iterator)->stop();
    }
    if (uploader) {
        uploader->stop();  // flushes whatever is still pending, best-effort
    }
    SetConsoleCtrlHandler(&console_control_handler, FALSE);
    shutdown_event.store(nullptr);
    std::cerr << "Officer stopped cleanly.\n";
    return 0;
}
