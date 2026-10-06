#include "panopticon/officer/health/state_freshness.hpp"
#include <charconv>
#include <string>
#include <string_view>
#include <array>
#include <stdexcept>
namespace panopticon::officer::health {
namespace {
using Json = nlohmann::json;
bool read(const Json& object, const char* key, std::uint64_t& value) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_string()) return false;
    const auto& text = found->get_ref<const std::string&>();
    if (text.empty() || (text.size() > 1 && text[0] == '0')) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
struct Source { const char* key; std::array<const char*, 8> prefixes; };
constexpr Source sources[]{
    {"host_inventory", {"A.host", "state.tpm_device", "state.entra_default_join", "state.storage_volumes", "state.system_audit_policy", "W.enterprise_identity", "Y.posture"}},
    {"process_inventory", {"state.process_inventory"}},
    {"service_inventory", {"state.service_", "K.service_driver"}},
    {"loaded_driver_inventory", {"state.loaded_driver_inventory"}},
    {"socket_inventory", {"state.socket_"}},
    {"route_inventory", {"state.route_"}},
    {"ip_interface_inventory", {"state.ip_interface_"}},
    {"firewall_profile_state", {"state.firewall_profiles", "state.firewall_exclusions.", "P.firewall"}},
    {"firewall_rule_inventory", {"state.firewall_rule_inventory", "P.firewall"}},
    {"security_center_state", {"state.security_center", "Q.security_product"}},
    {"defender_status", {"state.defender_status", "Q.security_product"}}
};
bool positive(const Json& state) { return state == "healthy" || state == "degraded"; }
}
void apply_state_capture_freshness(Json& health, std::uint64_t now) {
    for (const auto& source : sources) {
        auto found = health.find(source.key);
        if (found == health.end() || !found->is_object()) continue;
        auto& inventory = *found;
        Json freshness{{"state", "unavailable"}, {"evaluated_uptime_ms", std::to_string(now)},
            {"capture_age_ms", nullptr}, {"commit_age_ms", nullptr},
            {"nominal_capture_interval_ms", "300000"}, {"scheduling_tolerance_ms", "60000"},
            {"maximum_capture_age_ms", "360000"},
            {"scope", "age of last durably accepted capture start in this runtime uptime domain; not continuous visibility or backend receipt freshness"}};
        std::uint64_t start = 0, committed = 0;
        const auto record = inventory.find("last_committed_record_id");
        if (record == inventory.end() || !record->is_string() || record->get_ref<const std::string&>().empty())
            freshness["reason"] = "no_committed_capture";
        else if (!read(inventory, "last_committed_capture_started_uptime_ms", start) ||
                 !read(inventory, "last_committed_uptime_ms", committed))
            freshness["reason"] = "missing_or_invalid_capture_clock_evidence";
        else if (start > committed || committed > now)
            freshness["reason"] = "capture_clock_order_invalid";
        else {
            freshness["capture_age_ms"] = std::to_string(now - start);
            freshness["commit_age_ms"] = std::to_string(now - committed);
            freshness["state"] = now - start > 360000 ? "blind" : "healthy";
            freshness["reason"] = now - start > 360000 ? "committed_capture_overdue" : "capture_within_age_limit";
        }
        freshness["record_id"] = record == inventory.end() ? Json(nullptr) : *record;
        const auto stale = freshness["state"] != "healthy";
        inventory["capture_freshness"] = freshness;
        const auto derived = freshness["state"] == "blind" ? "blind" : "unavailable";
        if (stale && inventory.contains("state") && positive(inventory["state"])) {
            inventory["reported_state"] = inventory["state"];
            inventory["state"] = derived;
        }
        if (!health.contains("capabilities") || !health["capabilities"].is_array()) continue;
        for (auto& capability : health["capabilities"]) {
            if (!capability.is_object() || !capability.contains("id") || !capability["id"].is_string()) continue;
            const auto& id = capability["id"].get_ref<const std::string&>();
            bool matches = false;
            for (const auto* prefix : source.prefixes) if (prefix && std::string_view{id}.starts_with(prefix)) matches = true;
            if (!matches || !capability.contains("state")) continue;
            capability["state_capture_freshness"][source.key] = freshness;
            if (stale && positive(capability["state"])) {
                capability["reported_state"] = capability["state"];
                capability["state"] = derived;
                capability["reported_reason"] = capability.value("reason", "");
                capability["reason"] = std::string{source.key} + ": " + freshness["reason"].get<std::string>();
            }
        }
    }
    // Either independent source can provide partial posture. A client-only WSC
    // refusal must not erase fresh Defender reports on Server (or the reverse).
    if (health.contains("defender_status") && health.contains("capabilities") && health["capabilities"].is_array()) {
        bool available = false, blind = false;
        for (const auto* key : {"security_center_state", "defender_status"}) {
            const auto found = health.find(key);
            if (found == health.end() || !found->is_object()) continue;
            available |= found->contains("state") && positive(found->at("state"));
            blind |= found->value("state", "unavailable") == "blind";
        }
        for (auto& capability : health["capabilities"]) {
            if (!capability.is_object() || capability.value("id", "") != "Q.security_product") continue;
            capability["state"] = available ? "degraded" : blind ? "blind" : "unavailable";
            capability["reason"] = available ? "partial reports from at least one fresh independent security source; protection unverified" :
                blind ? "no eligible security source report; committed partial posture overdue" : "no eligible security source report";
        }
    }
}
StateCaptureGapBuffer::StateCaptureGapBuffer(std::size_t reports, std::size_t bytes)
    : report_limit_(reports), byte_limit_(bytes) {
    if (!reports || reports > 1024 || bytes < 2048 || bytes > 1024 * 1024)
        throw std::invalid_argument("state capture history limits invalid");
}
bool StateCaptureGapBuffer::append(Json data) {
    const auto size = data.dump().size();
    if (reports_.size() >= report_limit_ || size > byte_limit_ - bytes_) return false;
    reports_.push_back({std::move(data), size}); bytes_ += size; return true;
}
void StateCaptureGapBuffer::flush_omissions() {
    if (!omitted_pending_) return;
    if (append({{"gap_kind", "state_capture_freshness_history_bound"},
        {"omitted_transition_reports", std::to_string(omitted_pending_)},
        {"first_omitted_sample_uptime_ms", std::to_string(first_omitted_)},
        {"last_omitted_sample_uptime_ms", std::to_string(last_omitted_)},
        {"lost_native_events", nullptr}, {"source_event_range", nullptr}, {"reconciliation", "pending"},
        {"scope", "observed freshness transitions omitted from bounded volatile history; not a native event loss count"}}))
        omitted_pending_ = 0;
}
void StateCaptureGapBuffer::observe(const Json& health, std::uint64_t uptime) {
    flush_omissions();
    for (const auto& source : sources) {
        const auto found = health.find(source.key);
        if (found == health.end() || !found->is_object() || !found->contains("capture_freshness")) continue;
        const auto& current = found->at("capture_freshness");
        if (!current.is_object() || !current.contains("state") || !current.contains("reason")) continue;
        const auto prior = observed_.find(source.key);
        if (prior == observed_.end() || prior->at("state") != current.at("state") || prior->at("reason") != current.at("reason")) {
            Json data{{"gap_kind", "state_capture_freshness_transition"}, {"state_source", source.key},
                {"transition_kind", prior == observed_.end() ? "initial_sample_history_unknown" : "eligibility_changed"},
                {"previous_freshness", prior == observed_.end() ? Json(nullptr) : *prior}, {"current_freshness", current},
                {"previous_sample_uptime_ms", observed_samples_.value(source.key, Json(nullptr))},
                {"sample_uptime_ms", std::to_string(uptime)}, {"lost_native_events", nullptr}, {"source_event_range", nullptr},
                {"reconciliation", "pending"}, {"interval", "between_health_samples_or_unknown"},
                {"scope", "sampled state capture eligibility transition; not exact outage onset, continuous telemetry loss or proof of full coverage"}};
            if (omitted_pending_ || !append(std::move(data))) {
                if (!omitted_pending_) first_omitted_ = uptime;
                last_omitted_ = uptime; ++omitted_pending_; ++omitted_total_;
            }
        }
        // Always advance observed baseline, even when the journal front is refused.
        observed_[source.key] = current;
        observed_samples_[source.key] = std::to_string(uptime);
    }
    last_sample_ = uptime;
}
void StateCaptureGapBuffer::acknowledge_front() {
    if (reports_.empty()) throw std::logic_error("no state capture gap to acknowledge");
    bytes_ -= reports_.front().bytes; reports_.pop_front(); ++acknowledged_; flush_omissions();
}
Json StateCaptureGapBuffer::snapshot() const {
    return {{"state", "degraded"}, {"queued_reports", std::to_string(reports_.size())},
        {"encoded_gap_bytes", std::to_string(bytes_)}, {"report_limit", std::to_string(report_limit_)},
        {"byte_limit", std::to_string(byte_limit_)}, {"acknowledged_reports", std::to_string(acknowledged_)},
        {"omitted_reports_total", std::to_string(omitted_total_)}, {"omitted_reports_pending_summary", std::to_string(omitted_pending_)},
        {"last_sample_uptime_ms", last_sample_ ? Json(std::to_string(*last_sample_)) : Json(nullptr)},
        {"scope", "volatile bounded sampled transition history; encoded data excludes baseline/JSON/allocator/canonical record memory; restart counters reset and abrupt-exit loss unknown"}};
}
}
