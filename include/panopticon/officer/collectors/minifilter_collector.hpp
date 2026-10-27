#pragma once

#include "panopticon/officer/collectors/telemetry_collector.hpp"

#include <memory>

namespace panopticon::officer::collectors {

// Connects to the panopticon-fsmon.sys communication port, drains its bounded
// message queue, and publishes each decoded record as a RawFileEvent. If the
// driver is not loaded the collector starts in a non-running, unavailable state
// with an explicit reason rather than failing agent startup. Driver load and
// live interception are test-signed/VM-gated; this user-mode half is host-built.
class MinifilterCollector final : public TelemetryCollector {
public:
    MinifilterCollector();
    ~MinifilterCollector() override;

    MinifilterCollector(const MinifilterCollector&) = delete;
    MinifilterCollector& operator=(const MinifilterCollector&) = delete;

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
