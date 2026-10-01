#pragma once

#include "panopticon/officer/collectors/telemetry_collector.hpp"

#include <memory>

namespace panopticon::officer::collectors {

// Live collector for PowerShell script-block logging (Schema 0.5). Subscribes to
// the Microsoft-Windows-PowerShell/Operational channel for EventID 4104 via
// EvtSubscribe -- the same mechanism SysmonEventCollector uses for the Sysmon
// channel -- renders each event to XML, and decodes it with
// PowerShellScriptBlockDecoder into a RawScriptBlockEvent.
//
// Requires PowerShell Script Block Logging to be enabled (Group Policy:
// Administrative Templates > Windows Components > Windows PowerShell > Turn on
// PowerShell Script Block Logging), otherwise the channel carries no 4104s.
class PowerShellEventCollector final : public TelemetryCollector {
public:
    PowerShellEventCollector();
    ~PowerShellEventCollector() override;

    PowerShellEventCollector(const PowerShellEventCollector&) = delete;
    PowerShellEventCollector& operator=(const PowerShellEventCollector&) = delete;

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
