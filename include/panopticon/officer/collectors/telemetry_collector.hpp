#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace panopticon::officer::collectors {

using RawEventSink = std::function<void(telemetry::RawEvent)>;
using CollectorErrorSink = std::function<void(std::string_view, std::string)>;

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
};

}  // namespace panopticon::officer::collectors
