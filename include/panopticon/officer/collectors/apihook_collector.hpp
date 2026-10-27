#pragma once

#include "panopticon/officer/collectors/telemetry_collector.hpp"

#include <memory>

namespace panopticon::officer::collectors {

// Serves the officer-hook named pipe, verifies each connecting peer's PID and
// creation time out of band, and publishes verified intercepted API calls as
// RawFileEvent records sourced as api_hook (provider "Officer-Hook", channel =
// the concrete API). A record whose claimed actor fails verification is counted
// and dropped, never emitted. Hook injection and live interception are VM-gated;
// this server half is host-built.
class ApiHookCollector final : public TelemetryCollector {
public:
    ApiHookCollector();
    ~ApiHookCollector() override;

    ApiHookCollector(const ApiHookCollector&) = delete;
    ApiHookCollector& operator=(const ApiHookCollector&) = delete;

    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] bool start(
        RawEventSink event_sink,
        CollectorErrorSink error_sink,
        std::string& error_message) override;
    void stop() noexcept override;
    [[nodiscard]] bool running() const noexcept override;
    [[nodiscard]] CollectorStatus status() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace panopticon::officer::collectors
