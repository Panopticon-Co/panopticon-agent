#include "panopticon/officer/collectors/minifilter_collector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define PANOPTICON_FSMON_USER
#include <windows.h>
#include <fltuser.h>

#include "panopticon/officer/minifilter/fsmon_protocol.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

namespace panopticon::officer::collectors {
namespace {

using minifilter::DecodedFsMonEvent;

// FilterGetMessage fills a FILTER_MESSAGE_HEADER immediately followed by our
// event. The reply buffer must hold both; the collector decodes past the header.
#pragma pack(push, 1)
struct PortMessage {
    FILTER_MESSAGE_HEADER header;
    PanopticonFsMonEvent event;
};
#pragma pack(pop)

telemetry::FileOperation to_file_operation(PanopticonFsMonOperation op) {
    switch (op) {
        case PanopticonFsMonOpCreate: return telemetry::FileOperation::create;
        case PanopticonFsMonOpOpen: return telemetry::FileOperation::open;
        case PanopticonFsMonOpWrite: return telemetry::FileOperation::write;
        case PanopticonFsMonOpSetInformation: return telemetry::FileOperation::set_information;
        case PanopticonFsMonOpOverwrite: return telemetry::FileOperation::overwrite;
        case PanopticonFsMonOpRename: return telemetry::FileOperation::rename;
        case PanopticonFsMonOpDelete: return telemetry::FileOperation::remove;
    }
    return telemetry::FileOperation::set_information;
}

// 100ns ticks since 1601 (FILETIME base) to the pipeline's sys_time<ns>.
telemetry::UtcTimestamp from_filetime_ticks(std::uint64_t ticks) {
    // FILETIME epoch (1601-01-01) precedes the Unix epoch by 11644473600 s.
    constexpr std::uint64_t kTicksToUnixEpoch = 116444736000000000ull;
    const std::int64_t unix_100ns = static_cast<std::int64_t>(ticks) - static_cast<std::int64_t>(kTicksToUnixEpoch);
    return telemetry::UtcTimestamp{std::chrono::nanoseconds{unix_100ns * 100}};
}

telemetry::RawFileEvent to_raw_event(const DecodedFsMonEvent& decoded) {
    telemetry::RawFileEvent file;
    file.source = {telemetry::TelemetrySourceKind::minifilter, "Panopticon-FsMon",
        "Panopticon-FsMon/Operational", decoded.sequence};
    file.timestamp = from_filetime_ticks(decoded.event_time);
    file.process.pid = decoded.actor_pid;
    // The driver supplies the actor's creation time as native 100ns ticks; the
    // normalizer joins it to an ETW/Sysmon start for native_exact identity.
    if (decoded.actor_create) file.process.start_time_ticks = *decoded.actor_create;
    file.operation = to_file_operation(decoded.operation);
    file.path = decoded.path;
    if (decoded.previous_path) file.previous_path = decoded.previous_path;
    file.phase = decoded.post ? telemetry::OperationPhase::completed : telemetry::OperationPhase::attempted;
    // NTSTATUS is only meaningful on the post (completion) phase.
    if (decoded.post) file.status = telemetry::NativeStatus{telemetry::NativeStatus::Kind::ntstatus,
        static_cast<std::uint32_t>(decoded.status)};
    return file;
}

}  // namespace

struct MinifilterCollector::Impl {
    HANDLE port = INVALID_HANDLE_VALUE;
    std::thread worker;
    std::atomic<bool> stopping{false};
    std::atomic<bool> active{false};
    std::atomic<bool> continuity_fault{false};
    std::atomic<std::uint64_t> decode_failures{0};
    std::atomic<std::uint64_t> sink_failures{0};
    std::atomic<std::uint64_t> subscription_errors{0};
    std::atomic<std::uint64_t> dropped{0};

    // Gap tracking across the driver's monotonic sequence/dropped counters.
    std::mutex sequence_mutex;
    bool have_last_sequence = false;
    std::uint64_t last_sequence = 0;

    void note_sequence(const DecodedFsMonEvent& decoded) {
        std::lock_guard<std::mutex> guard(sequence_mutex);
        dropped.store(decoded.dropped_before, std::memory_order_relaxed);
        if (decoded.dropped_before != 0) continuity_fault.store(true, std::memory_order_relaxed);
        if (have_last_sequence && decoded.sequence != last_sequence + 1)
            continuity_fault.store(true, std::memory_order_relaxed);
        last_sequence = decoded.sequence;
        have_last_sequence = true;
    }

    void run(RawEventSink event_sink, CollectorErrorSink error_sink) {
        while (!stopping.load(std::memory_order_relaxed)) {
            PortMessage message{};
            const HRESULT result = FilterGetMessage(port, &message.header, sizeof(message), nullptr);
            if (stopping.load(std::memory_order_relaxed)) break;
            if (result != S_OK) {
                subscription_errors.fetch_add(1, std::memory_order_relaxed);
                if (error_sink) error_sink("minifilter", "FilterGetMessage failed: 0x" +
                    [&] { char b[11]{}; std::snprintf(b, sizeof(b), "%08lx", static_cast<unsigned long>(result)); return std::string{b}; }());
                // A transient failure should not spin; a persistent one ends the loop.
                if (result == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) break;
                continue;
            }
            std::string error;
            const auto decoded = minifilter::decode_fsmon_event(
                reinterpret_cast<const unsigned char*>(&message.event), sizeof(message.event), error);
            if (!decoded) {
                decode_failures.fetch_add(1, std::memory_order_relaxed);
                if (error_sink) error_sink("minifilter", "record rejected: " + error);
                continue;
            }
            note_sequence(*decoded);
            try {
                event_sink(telemetry::RawEvent{to_raw_event(*decoded)});
            } catch (const std::exception&) {
                sink_failures.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
};

MinifilterCollector::MinifilterCollector() : impl_(std::make_unique<Impl>()) {}

MinifilterCollector::~MinifilterCollector() { stop(); }

std::string_view MinifilterCollector::name() const noexcept { return "minifilter"; }

bool MinifilterCollector::start(RawEventSink event_sink, CollectorErrorSink error_sink, std::string& error_message) {
    if (impl_->active.load(std::memory_order_relaxed)) { error_message = "already running"; return false; }
    const HRESULT connected = FilterConnectCommunicationPort(
        PANOPTICON_FSMON_PORT_NAME, 0, nullptr, 0, nullptr, &impl_->port);
    if (connected != S_OK) {
        impl_->port = INVALID_HANDLE_VALUE;
        char code[11]{};
        std::snprintf(code, sizeof(code), "%08lx", static_cast<unsigned long>(connected));
        // Not loaded / not test-signed is the expected state off the VM: report
        // it as an unavailable source rather than aborting agent startup.
        error_message = std::string{"panopticon-fsmon.sys port not available (0x"} + code +
            "); driver not loaded or connect denied";
        impl_->subscription_errors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    impl_->stopping.store(false, std::memory_order_relaxed);
    impl_->active.store(true, std::memory_order_relaxed);
    impl_->worker = std::thread([this, event_sink = std::move(event_sink), error_sink = std::move(error_sink)]() mutable {
        impl_->run(std::move(event_sink), std::move(error_sink));
    });
    return true;
}

void MinifilterCollector::stop() noexcept {
    impl_->stopping.store(true, std::memory_order_relaxed);
    if (impl_->port != INVALID_HANDLE_VALUE) {
        // Closing the port unblocks a pending FilterGetMessage.
        CloseHandle(impl_->port);
        impl_->port = INVALID_HANDLE_VALUE;
    }
    if (impl_->worker.joinable()) impl_->worker.join();
    impl_->active.store(false, std::memory_order_relaxed);
}

bool MinifilterCollector::running() const noexcept { return impl_->active.load(std::memory_order_relaxed); }

CollectorStatus MinifilterCollector::status() {
    CollectorStatus status;
    status.running = impl_->active.load(std::memory_order_relaxed);
    status.continuity_fault = impl_->continuity_fault.load(std::memory_order_relaxed);
    status.statistics_available = true;
    status.decode_failures = impl_->decode_failures.load(std::memory_order_relaxed);
    status.sink_failures = impl_->sink_failures.load(std::memory_order_relaxed);
    status.subscription_errors = impl_->subscription_errors.load(std::memory_order_relaxed);
    const auto dropped = impl_->dropped.load(std::memory_order_relaxed);
    if (dropped > 0xffffffffull) status.events_lost = 0xffffffffu;
    else status.events_lost = static_cast<std::uint32_t>(dropped);
    return status;
}

}  // namespace panopticon::officer::collectors
