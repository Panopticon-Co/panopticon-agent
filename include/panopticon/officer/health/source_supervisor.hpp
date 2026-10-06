#pragma once
#include "panopticon/officer/collectors/telemetry_collector.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <deque>
#include <cstddef>
#include <cstdint>

namespace panopticon::officer::health {
[[nodiscard]] nlohmann::json source_status_json(const collectors::CollectorStatus& status);
// Compare consecutive observed samples. A null result means no new loss/status
// transition, not proof of complete source visibility or durable acceptance.
[[nodiscard]] std::optional<nlohmann::json> source_gap_since(
    const std::optional<collectors::CollectorStatus>& committed,
    const collectors::CollectorStatus& current);

// Single supervisor owner. The front report remains immutable until journal
// acceptance; every observed sample advances the measurement baseline even
// while that front report is pending. Bounded history is volatile, not a receipt.
class SourceGapBuffer {
public:
    SourceGapBuffer(std::size_t report_limit = 128, std::size_t byte_limit = 256 * 1024);
    bool observe(const collectors::CollectorStatus& current, std::uint64_t uptime_ms);
    [[nodiscard]] bool empty() const { return reports_.empty(); }
    [[nodiscard]] bool pending() const { return !reports_.empty() || omitted_pending_ != 0; }
    [[nodiscard]] const nlohmann::json& front() const { return reports_.front().data; }
    void acknowledge_front(); // Call only after the front's canonical record was accepted.
    [[nodiscard]] nlohmann::json snapshot() const;
private:
    struct Report { nlohmann::json data; std::size_t bytes; };
    bool append(nlohmann::json report);
    void flush_omissions();
    std::optional<collectors::CollectorStatus> observed_;
    std::optional<std::uint64_t> observed_uptime_;
    std::deque<Report> reports_;
    std::size_t report_limit_, byte_limit_, bytes_ = 0;
    std::uint64_t acknowledged_ = 0, omitted_total_ = 0, omitted_pending_ = 0;
    std::uint64_t first_omitted_uptime_ = 0, last_omitted_uptime_ = 0;
};
}
