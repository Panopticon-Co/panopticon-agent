#include "panopticon/officer/collectors/apihook_collector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define PANOPTICON_APIHOOK_USER
#include <windows.h>
#include <sddl.h>

#include "panopticon/officer/apihook/apihook_protocol.hpp"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace panopticon::officer::collectors {
namespace {

using apihook::DecodedApiHookEvent;

// SYSTEM and Administrators full control; no access for anyone else. The hook
// runs in a monitored process, so this limits which tokens may impersonate it.
constexpr wchar_t kPipeSddl[] = L"D:(A;;GA;;;SY)(A;;GA;;;BA)";

telemetry::FileOperation to_file_operation(PanopticonApiHookOperation op) {
    switch (op) {
        case PanopticonApiHookOpCreate: return telemetry::FileOperation::create;
        case PanopticonApiHookOpOpen: return telemetry::FileOperation::open;
        case PanopticonApiHookOpWrite: return telemetry::FileOperation::write;
        case PanopticonApiHookOpSetInformation: return telemetry::FileOperation::set_information;
        case PanopticonApiHookOpOverwrite: return telemetry::FileOperation::overwrite;
        case PanopticonApiHookOpRename: return telemetry::FileOperation::rename;
        case PanopticonApiHookOpDelete: return telemetry::FileOperation::remove;
    }
    return telemetry::FileOperation::set_information;
}

telemetry::UtcTimestamp from_filetime_ticks(std::uint64_t ticks) {
    constexpr std::uint64_t kTicksToUnixEpoch = 116444736000000000ull;
    const std::int64_t unix_100ns = static_cast<std::int64_t>(ticks) - static_cast<std::int64_t>(kTicksToUnixEpoch);
    return telemetry::UtcTimestamp{std::chrono::nanoseconds{unix_100ns * 100}};
}

// The OS-reported creation time of a PID as FILETIME ticks, nullopt if it cannot
// be read. Used to bind a connection to a specific process instance.
std::optional<std::uint64_t> process_create_ticks(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return std::nullopt;
    FILETIME create{}, exit{}, kernel{}, user{};
    const BOOL ok = GetProcessTimes(process, &create, &exit, &kernel, &user);
    CloseHandle(process);
    if (!ok) return std::nullopt;
    ULARGE_INTEGER value;
    value.LowPart = create.dwLowDateTime;
    value.HighPart = create.dwHighDateTime;
    return value.QuadPart;
}

telemetry::RawFileEvent to_raw_event(const DecodedApiHookEvent& decoded, DWORD verified_pid,
                                     std::optional<std::uint64_t> verified_create) {
    telemetry::RawFileEvent file;
    // The concrete API name is carried as the provenance channel for the record.
    file.source = {telemetry::TelemetrySourceKind::api_hook, "Officer-Hook",
        decoded.api_name.empty() ? std::optional<std::string>{} : std::optional<std::string>{decoded.api_name},
        decoded.sequence};
    file.timestamp = from_filetime_ticks(decoded.event_time);
    file.process.pid = verified_pid;
    // Prefer the OS creation token; fall back to the hook's claim only if the OS
    // did not supply one (it already passed verify_claimed_actor).
    if (verified_create) file.process.start_time_ticks = *verified_create;
    else if (decoded.claimed_create) file.process.start_time_ticks = *decoded.claimed_create;
    file.operation = to_file_operation(decoded.operation);
    file.path = decoded.path;
    if (decoded.previous_path) file.previous_path = decoded.previous_path;
    file.phase = decoded.post ? telemetry::OperationPhase::completed : telemetry::OperationPhase::attempted;
    if (decoded.post) file.status = telemetry::NativeStatus{telemetry::NativeStatus::Kind::win32_error, decoded.win32_error};
    return file;
}

}  // namespace

struct ApiHookCollector::Impl {
    std::thread worker;
    std::atomic<bool> stopping{false};
    std::atomic<bool> active{false};
    std::atomic<bool> continuity_fault{false};
    std::atomic<std::uint64_t> decode_failures{0};
    std::atomic<std::uint64_t> sink_failures{0};
    std::atomic<std::uint64_t> subscription_errors{0};
    std::atomic<std::uint64_t> identity_rejections{0};
    std::atomic<std::uint64_t> dropped{0};

    std::mutex sequence_mutex;
    bool have_last_sequence = false;
    std::uint64_t last_sequence = 0;
    // The current connection handle, so stop() can cancel a blocking read.
    std::atomic<HANDLE> pipe{INVALID_HANDLE_VALUE};

    void note_sequence(const DecodedApiHookEvent& decoded) {
        std::lock_guard<std::mutex> guard(sequence_mutex);
        dropped.store(decoded.dropped_before, std::memory_order_relaxed);
        if (decoded.dropped_before != 0) continuity_fault.store(true, std::memory_order_relaxed);
        if (have_last_sequence && decoded.sequence != last_sequence + 1)
            continuity_fault.store(true, std::memory_order_relaxed);
        last_sequence = decoded.sequence;
        have_last_sequence = true;
    }

    // Serve one connection: verify the peer, then read records until it closes.
    void serve(HANDLE connection, const RawEventSink& event_sink, const CollectorErrorSink& error_sink) {
        DWORD peer_pid = 0;
        if (!GetNamedPipeClientProcessId(connection, &peer_pid) || peer_pid == 0) {
            subscription_errors.fetch_add(1, std::memory_order_relaxed);
            if (error_sink) error_sink("api_hook", "could not resolve pipe client PID; refusing connection");
            return;
        }
        const auto peer_create = process_create_ticks(peer_pid);

        for (;;) {
            if (stopping.load(std::memory_order_relaxed)) break;
            PanopticonApiHookEvent record{};
            DWORD read = 0;
            const BOOL ok = ReadFile(connection, &record, sizeof(record), &read, nullptr);
            if (!ok || read == 0) break;  // peer closed or error
            if (read != sizeof(record)) { decode_failures.fetch_add(1, std::memory_order_relaxed); continue; }

            std::string error;
            const auto decoded = apihook::decode_apihook_event(
                reinterpret_cast<const unsigned char*>(&record), sizeof(record), error);
            if (!decoded) {
                decode_failures.fetch_add(1, std::memory_order_relaxed);
                if (error_sink) error_sink("api_hook", "record rejected: " + error);
                continue;
            }
            std::string reason;
            if (!apihook::verify_claimed_actor(*decoded, peer_pid, peer_create, reason)) {
                identity_rejections.fetch_add(1, std::memory_order_relaxed);
                if (error_sink) error_sink("api_hook", "actor identity rejected: " + reason);
                continue;  // never emit an unverified actor
            }
            note_sequence(*decoded);
            try {
                event_sink(telemetry::RawEvent{to_raw_event(*decoded, peer_pid, peer_create)});
            } catch (const std::exception&) {
                sink_failures.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void run(RawEventSink event_sink, CollectorErrorSink error_sink) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        PSECURITY_DESCRIPTOR sd = nullptr;
        const bool have_sd = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kPipeSddl, SDDL_REVISION_1, &sd, nullptr) != FALSE;
        sa.lpSecurityDescriptor = have_sd ? sd : nullptr;

        while (!stopping.load(std::memory_order_relaxed)) {
            HANDLE connection = CreateNamedPipeW(
                PANOPTICON_APIHOOK_PIPE_NAME,
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                0, sizeof(PanopticonApiHookEvent) * 8,
                0, have_sd ? &sa : nullptr);
            if (connection == INVALID_HANDLE_VALUE) {
                subscription_errors.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            pipe.store(connection, std::memory_order_relaxed);
            const BOOL connected = ConnectNamedPipe(connection, nullptr) ? TRUE :
                (GetLastError() == ERROR_PIPE_CONNECTED);
            if (stopping.load(std::memory_order_relaxed)) {
                pipe.store(INVALID_HANDLE_VALUE, std::memory_order_relaxed);
                CloseHandle(connection);
                break;
            }
            if (connected) serve(connection, event_sink, error_sink);
            DisconnectNamedPipe(connection);
            pipe.store(INVALID_HANDLE_VALUE, std::memory_order_relaxed);
            CloseHandle(connection);
        }
        if (have_sd && sd) LocalFree(sd);
    }
};

ApiHookCollector::ApiHookCollector() : impl_(std::make_unique<Impl>()) {}

ApiHookCollector::~ApiHookCollector() { stop(); }

std::string_view ApiHookCollector::name() const noexcept { return "api_hook"; }

bool ApiHookCollector::start(RawEventSink event_sink, CollectorErrorSink error_sink, std::string& error_message) {
    if (impl_->active.load(std::memory_order_relaxed)) { error_message = "already running"; return false; }
    impl_->stopping.store(false, std::memory_order_relaxed);
    impl_->active.store(true, std::memory_order_relaxed);
    impl_->worker = std::thread([this, event_sink = std::move(event_sink), error_sink = std::move(error_sink)]() mutable {
        impl_->run(std::move(event_sink), std::move(error_sink));
    });
    return true;
}

void ApiHookCollector::stop() noexcept {
    impl_->stopping.store(true, std::memory_order_relaxed);
    // Unblock a pending ConnectNamedPipe/ReadFile by poking the pipe and closing.
    const HANDLE current = impl_->pipe.load(std::memory_order_relaxed);
    if (current != INVALID_HANDLE_VALUE) CancelIoEx(current, nullptr);
    // A self-connect releases a ConnectNamedPipe waiting with no client.
    HANDLE poke = CreateFileW(PANOPTICON_APIHOOK_PIPE_NAME, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (poke != INVALID_HANDLE_VALUE) CloseHandle(poke);
    if (impl_->worker.joinable()) impl_->worker.join();
    impl_->active.store(false, std::memory_order_relaxed);
}

bool ApiHookCollector::running() const noexcept { return impl_->active.load(std::memory_order_relaxed); }

CollectorStatus ApiHookCollector::status() {
    CollectorStatus status;
    status.running = impl_->active.load(std::memory_order_relaxed);
    status.continuity_fault = impl_->continuity_fault.load(std::memory_order_relaxed);
    status.statistics_available = true;
    status.decode_failures = impl_->decode_failures.load(std::memory_order_relaxed);
    status.sink_failures = impl_->sink_failures.load(std::memory_order_relaxed);
    // Identity rejections are a subscription-integrity signal, surfaced alongside
    // subscription errors so the supervisor treats a spoofing attempt as a fault.
    status.subscription_errors = impl_->subscription_errors.load(std::memory_order_relaxed) +
        impl_->identity_rejections.load(std::memory_order_relaxed);
    const auto dropped = impl_->dropped.load(std::memory_order_relaxed);
    if (dropped > 0xffffffffull) status.events_lost = 0xffffffffu;
    else status.events_lost = static_cast<std::uint32_t>(dropped);
    return status;
}

}  // namespace panopticon::officer::collectors
