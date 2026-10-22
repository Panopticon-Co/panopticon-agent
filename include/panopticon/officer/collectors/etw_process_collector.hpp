#pragma once

#include "panopticon/officer/collectors/telemetry_collector.hpp"
#include "panopticon/officer/delivery/journal.hpp"

#include <memory>

namespace panopticon::officer::collectors {
struct EtwSessionCallbacks {
    std::string installation_scope;
    std::optional<std::string> boot_id;
    std::function<std::optional<delivery::SourceCheckpoint>()> load;
    // Commit a canonical lifecycle/gap record and encrypted checkpoint together.
    // False means no native new-session creation is allowed.
    std::function<bool(nlohmann::json, const std::string&, std::uint64_t)> commit;
};
namespace detail {
[[nodiscard]] std::optional<telemetry::RawProcessEvent> decode_etw_process_record(const void* event_record, std::string& error);
}

class EtwProcessCollector final : public TelemetryCollector {
public:
    explicit EtwProcessCollector(EtwSessionCallbacks callbacks = {});
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
    [[nodiscard]] CollectorStatus status() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace panopticon::officer::collectors
