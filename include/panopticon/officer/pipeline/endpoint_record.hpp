#pragma once
#include "panopticon/officer/core/process_instance.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include <mutex>

namespace panopticon::officer::pipeline {
class EndpointRecordFactory {
public:
    EndpointRecordFactory(NormalizationContext context, std::string device_id, std::string installation_id, std::optional<std::string> boot_id, std::uint64_t generation);
    [[nodiscard]] nlohmann::json observation(const telemetry::RawEvent& raw, const telemetry::PanopticonEvent& normalized);
    [[nodiscard]] nlohmann::json process_stop(const telemetry::RawProcessEvent& event);
    void accepted_process_stop(const telemetry::RawProcessEvent& event);
    [[nodiscard]] nlohmann::json state(std::string category, nlohmann::json data);
    [[nodiscard]] nlohmann::json health(nlohmann::json data);
    [[nodiscard]] nlohmann::json gap(std::string source, nlohmann::json data);
    [[nodiscard]] nlohmann::json normalization_failure(const telemetry::RawEvent& raw, std::string error);
    [[nodiscard]] nlohmann::json windows_event_log(std::string channel, nlohmann::json data,
        std::optional<telemetry::UtcTimestamp> event_time);
    [[nodiscard]] nlohmann::json usn_journal(std::string volume, nlohmann::json data, bool gap);
    [[nodiscard]] nlohmann::json capture_scope() const;
    [[nodiscard]] std::uint64_t process_state_admission_failures() const { return processes_.admission_failures(); }
private:
    nlohmann::json envelope(std::string kind, std::string category, telemetry::UtcTimestamp time,
        nlohmann::json provenance, nlohmann::json subject, nlohmann::json data);
    NormalizationContext context_;
    std::string device_id_;
    std::string installation_id_;
    std::optional<std::string> boot_id_;
    std::string epoch_;
    std::uint64_t sequence_ = 0;
    std::uint64_t generation_;
    std::mutex mutex_;
    core::ProcessInstanceStore processes_;
};
}  // namespace panopticon::officer::pipeline
