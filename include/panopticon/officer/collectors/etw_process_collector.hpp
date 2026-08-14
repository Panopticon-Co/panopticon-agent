#pragma once

#include "panopticon/officer/collectors/telemetry_collector.hpp"

#include <memory>

namespace panopticon::officer::collectors {

class EtwProcessCollector final : public TelemetryCollector {
public:
    EtwProcessCollector();
    ~EtwProcessCollector() override;

    EtwProcessCollector(const EtwProcessCollector&) = delete;
    EtwProcessCollector& operator=(const EtwProcessCollector&) = delete;

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
