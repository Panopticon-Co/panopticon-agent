#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <functional>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::collectors {

// Runtime sink return may mean volatile bounded handoff, not durable acceptance.
// Sink exceptions count failed handoff; worker commits/failures have separate health.
using RawEventSink = std::function<void(telemetry::RawEvent)>;
using CollectorErrorSink = std::function<void(std::string_view, std::string)>;

// Counters cover this collector lifetime only. Null source counters mean unknown,
// never zero loss. Events and buffers are deliberately separate units.
struct CollectorStatus {
    bool running{};
    bool continuity_fault{};
    bool statistics_available{};
    std::uint64_t decode_failures{};
    std::uint64_t sink_failures{};
    std::uint64_t subscription_errors{};
    std::optional<std::uint32_t> events_lost;
    std::optional<std::uint32_t> realtime_buffers_lost;
    std::optional<std::uint32_t> log_buffers_lost;
    std::string statistics_error;
};

// All acquisition sources implement this interface. A collector owns source
// lifecycle and decoding, then publishes owned source-neutral facts only.
class TelemetryCollector {
public:
    virtual ~TelemetryCollector() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual bool start(
        RawEventSink event_sink,
        CollectorErrorSink error_sink,
        std::string& error_message) = 0;
    virtual void stop() noexcept = 0;
    [[nodiscard]] virtual bool running() const noexcept = 0;
    [[nodiscard]] virtual CollectorStatus status() = 0;
};

}  // namespace panopticon::officer::collectors
