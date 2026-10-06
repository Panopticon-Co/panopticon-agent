#include "panopticon/officer/health/source_supervisor.hpp"
#include <stdexcept>

namespace panopticon::officer::health {
using Json = nlohmann::json;
using Status = collectors::CollectorStatus;
namespace {
Json decimal(const std::optional<std::uint32_t>& value) {
    return value ? Json(std::to_string(*value)) : Json(nullptr);
}
void counter(Json& changes, const char* name, std::optional<std::uint64_t> before,
    std::optional<std::uint64_t> after, const char* unit, bool prior_sample = false) {
    if (before && !after) {
        changes.push_back({{"counter", name}, {"unit", unit}, {"previous", std::to_string(*before)},
            {"total", nullptr}, {"delta", nullptr}, {"reason", "counter_sample_unavailable"}});
        return;
    }
    if (!after || (before && *before == *after)) return;
    if (!before && *after == 0 && !prior_sample) return;
    const bool reset = before && *after < *before;
    changes.push_back({{"counter", name}, {"unit", unit},
        {"total", std::to_string(*after)},
        {"previous", before ? Json(std::to_string(*before)) : Json(nullptr)},
        {"delta", before && !reset ? Json(std::to_string(*after - *before)) : Json(nullptr)},
        {"reason", reset ? "counter_decreased_reset_or_wrap_unknown" : before ? "counter_advanced" :
            prior_sample ? "counter_sample_restored_history_unverified" : "initial_total_interval_unknown"}});
}
}
Json source_status_json(const Status& status) {
    return {{"running", status.running}, {"continuity_fault", status.continuity_fault},
        {"continuity", "unverified"}, {"statistics_available", status.statistics_available},
        {"decode_failures", std::to_string(status.decode_failures)},
        {"sink_failures", std::to_string(status.sink_failures)},
        {"subscription_errors", std::to_string(status.subscription_errors)},
        {"events_lost", decimal(status.events_lost)},
        {"realtime_buffers_lost", decimal(status.realtime_buffers_lost)},
        {"log_buffers_lost", decimal(status.log_buffers_lost)},
        {"statistics_error", status.statistics_error}};
}
std::optional<Json> source_gap_since(const std::optional<Status>& before, const Status& after) {
    auto changes = Json::array();
    if (!before) changes.push_back({{"reason", "startup_continuity_unknown"}, {"count", nullptr}});
    else {
        if (before->running != after.running)
            changes.push_back({{"reason", after.running ? "consumer_resumed_continuity_unverified" : "consumer_stopped"}, {"count", nullptr}});
        if (before->statistics_available != after.statistics_available)
            changes.push_back({{"reason", after.statistics_available ? "source_statistics_restored_history_unverified" : "source_statistics_unavailable"}, {"count", nullptr}});
        if (before->continuity_fault != after.continuity_fault)
            changes.push_back({{"reason", after.continuity_fault ? "continuity_fault_observed" : "continuity_fault_cleared_history_unverified"}, {"count", nullptr}});
    }
    counter(changes, "decode_failures", before ? std::optional{before->decode_failures} : std::nullopt, after.decode_failures, "events");
    counter(changes, "sink_failures", before ? std::optional{before->sink_failures} : std::nullopt, after.sink_failures, "events");
    counter(changes, "subscription_errors", before ? std::optional{before->subscription_errors} : std::nullopt, after.subscription_errors, "notifications");
    // Missing samples break the measured interval. Never infer a delta across
    // an unavailable query, reset or a 32-bit source counter wrap.
    counter(changes, "events_lost", before ? before->events_lost : std::nullopt, after.events_lost, "events", before.has_value());
    counter(changes, "realtime_buffers_lost", before ? before->realtime_buffers_lost : std::nullopt, after.realtime_buffers_lost, "buffers", before.has_value());
    counter(changes, "log_buffers_lost", before ? before->log_buffers_lost : std::nullopt, after.log_buffers_lost, "buffers", before.has_value());
    if (changes.empty()) return std::nullopt;
    return Json{{"changes", std::move(changes)}, {"source_status", source_status_json(after)},
        {"interval", "between_supervisor_samples_or_unknown"}, {"source_event_range", nullptr},
        {"reconciliation", "pending"}};
}
SourceGapBuffer::SourceGapBuffer(std::size_t reports, std::size_t bytes)
    : report_limit_(reports), byte_limit_(bytes) {
    if (!reports || reports > 1024 || bytes < 2048 || bytes > 1024 * 1024)
        throw std::invalid_argument("source history limits invalid");
}
bool SourceGapBuffer::append(Json report) {
    const auto bytes = report.dump().size();
    if (reports_.size() >= report_limit_ || bytes > byte_limit_ - bytes_) return false;
    reports_.push_back({std::move(report), bytes}); bytes_ += bytes;
    return true;
}
void SourceGapBuffer::flush_omissions() {
    if (!omitted_pending_) return;
    Json summary{{"changes", Json::array({{
        {"reason", "supervisor_history_bound"}, {"count", nullptr},
        {"omitted_gap_reports", std::to_string(omitted_pending_)},
        {"first_omitted_sample_uptime_ms", std::to_string(first_omitted_uptime_)},
        {"last_omitted_sample_uptime_ms", std::to_string(last_omitted_uptime_)},
        {"scope", "observed reports omitted from volatile supervision history; not native events or buffers"}
    }})}, {"source_status", nullptr}, {"source_event_range", nullptr},
        {"interval", "bounded_supervisor_history_omitted"}, {"reconciliation", "pending"}};
    if (append(std::move(summary))) omitted_pending_ = 0;
}
bool SourceGapBuffer::observe(const Status& current, std::uint64_t uptime) {
    flush_omissions();
    auto gap = source_gap_since(observed_, current);
    if (gap) {
        (*gap)["previous_sample_uptime_ms"] = observed_uptime_ ? Json(std::to_string(*observed_uptime_)) : Json(nullptr);
        (*gap)["sample_uptime_ms"] = std::to_string(uptime);
        if (omitted_pending_ || !append(std::move(*gap))) {
            if (!omitted_pending_) first_omitted_uptime_ = uptime;
            last_omitted_uptime_ = uptime; ++omitted_pending_; ++omitted_total_;
        }
    }
    observed_ = current; observed_uptime_ = uptime;
    return gap.has_value();
}
void SourceGapBuffer::acknowledge_front() {
    if (reports_.empty()) throw std::logic_error("no source gap to acknowledge");
    bytes_ -= reports_.front().bytes; reports_.pop_front(); ++acknowledged_;
    flush_omissions();
}
Json SourceGapBuffer::snapshot() const {
    return {{"state", "degraded"}, {"queued_reports", std::to_string(reports_.size())},
        {"encoded_gap_bytes", std::to_string(bytes_)}, {"report_limit", std::to_string(report_limit_)},
        {"byte_limit", std::to_string(byte_limit_)}, {"acknowledged_reports", std::to_string(acknowledged_)},
        {"omitted_reports_total", std::to_string(omitted_total_)}, {"omitted_reports_pending_summary", std::to_string(omitted_pending_)},
        {"last_observed_sample_uptime_ms", observed_uptime_ ? Json(std::to_string(*observed_uptime_)) : Json(nullptr)},
        {"scope", "volatile sampled source-gap history; encoded data bound excludes JSON/allocator/temporary/canonical record memory; counters reset on restart; abrupt-exit loss unknown"}};
}
}
