#pragma once

#include "panopticon/officer/collectors/telemetry_collector.hpp"

#include <memory>

namespace panopticon::officer::collectors {

class SysmonEventCollector final : public TelemetryCollector {
public:
    SysmonEventCollector();
    ~SysmonEventCollector() override;

    SysmonEventCollector(const SysmonEventCollector&) = delete;
    SysmonEventCollector& operator=(const SysmonEventCollector&) = delete;

    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] bool start(
        RawEventSink event_sink,
        CollectorErrorSink error_sink,
        std::string& error_message) override;
    void stop() noexcept override;
    [[nodiscard]] bool running() const noexcept override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace panopticon::officer::collectors
