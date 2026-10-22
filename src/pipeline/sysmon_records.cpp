#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/pipeline/source_facts.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include <algorithm>
#include <charconv>
#include <stdexcept>

namespace panopticon::officer::pipeline {
namespace {
using Json = nlohmann::json;
Json nullable_text(const std::optional<std::string>& value) { return value ? lossless_text(*value) : Json(nullptr); }
Json decimal(const std::optional<std::uint64_t>& value) { return value ? Json(std::to_string(*value)) : Json(nullptr); }
std::string digest(const std::string& value) {
    std::string error; const auto result = core::sha256_hex(value, error);
    if (!result) throw std::runtime_error(error);
    return *result;
}
Json bounded_text(const std::optional<std::string>& text) {
    if (!text) return nullptr;
    auto end = std::min<std::size_t>(text->size(), 16384);
    if (end < text->size()) while (end && (static_cast<unsigned char>((*text)[end]) & 0xc0) == 0x80) --end;
    return {{"text", lossless_text(std::string_view{*text}.substr(0, end))},
        {"original_bytes", std::to_string(text->size())}, {"truncated", end != text->size()}, {"sha256", digest(*text)}};
}
std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' || text.front() == '\n')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n')) text.remove_suffix(1);
    return text;
}
Json dns_answers(const std::optional<std::string>& results) {
    Json answers = Json::array(), unparsed = Json::array();
    bool bounded = false;
    if (results) {
        std::string_view remaining = *results;
        std::size_t tokens = 0;
        while (!remaining.empty()) {
            if (++tokens > 256) { bounded = true; break; }
            const auto separator = remaining.find(';');
            const auto token = trim(remaining.substr(0, separator));
            if (separator == std::string_view::npos) remaining = {};
            else remaining.remove_prefix(separator + 1);
            if (token.empty()) continue;
            const std::string value{token};
            IN_ADDR ipv4{}; IN6_ADDR ipv6{};
            if (InetPtonA(AF_INET, value.c_str(), &ipv4) == 1) answers.push_back({{"kind", "ip"}, {"family", "ipv4"}, {"value", value}});
            else if (InetPtonA(AF_INET6, value.c_str(), &ipv6) == 1) answers.push_back({{"kind", "ip"}, {"family", "ipv6"}, {"value", value}});
            else {
                bool cname = false;
                if (token.starts_with("type:")) {
                    auto tail = trim(token.substr(5));
                    unsigned type{};
                    const auto [end, status] = std::from_chars(tail.data(), tail.data() + tail.size(), type);
                    if (status == std::errc{} && type == 5 && end < tail.data() + tail.size() && (*end == ' ' || *end == '\t')) {
                        const auto name = trim(tail.substr(static_cast<std::size_t>(end - tail.data())));
                        const bool valid = !name.empty() && name.size() <= 254 && std::all_of(name.begin(), name.end(), [](unsigned char c) {
                            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
                        });
                        if (valid) { answers.push_back({{"kind", "cname"}, {"value", std::string{name}}}); cname = true; }
                    }
                }
                if (!cname) unparsed.push_back(lossless_text(token));
            }
        }
    }
    return {{"answers", std::move(answers)}, {"unparsed_tokens", std::move(unparsed)},
        {"token_limit", 256}, {"bound_exceeded", bounded}, {"source_results_present", results.has_value()}};
}
}
Json EndpointRecordFactory::sysmon_extended(const telemetry::RawSysmonExtendedEvent& event) {
    if ((event.event_id != 8 && event.event_id != 10 && event.event_id != 22) ||
        event.source.kind != telemetry::TelemetrySourceKind::sysmon || event.source.provider != "Microsoft-Windows-Sysmon" ||
        event.source.channel != std::optional<std::string>{"Microsoft-Windows-Sysmon/Operational"})
        throw std::invalid_argument("canonical Sysmon extension requires its exact source and closed event set");
    const auto scope = "sysmon:" + event.source.provider + ":" + *event.source.channel;
    const auto reference = [&](const telemetry::RawProcessContext& process) {
        if (process.process_guid && (process.process_guid->empty() || process.process_guid->size() > 256 || !valid_utf8(*process.process_guid)))
            throw std::invalid_argument("invalid Sysmon process GUID; retain failure evidence");
        return processes_.observe(process.pid, std::nullopt, process.process_guid, scope);
    };
    const auto actor = reference(event.process);
    const char* category = event.event_id == 22 ? "dns" : event.event_id == 10 ? "process_access" : "remote_thread";
    const char* operation = event.event_id == 22 ? "query" : event.event_id == 10 ? "access" : "create";
    const auto time = format_utc_timestamp(event.timestamp);
    if (time.empty()) throw std::invalid_argument("Sysmon event time is not representable");
    Json unavailable = Json::array();
    const auto missing = [&](const char* field, const char* reason) { unavailable.push_back({{"field", field}, {"reason", reason}}); };
    if (!actor.native_creation_ticks) missing("process.start_time_ticks", "source_does_not_supply_native_creation_token");
    const auto process = [&](const telemetry::RawProcessContext& raw, const core::ProcessReference& identity) {
        return Json{{"pid", raw.pid}, {"entity_id", identity.entity_id ? Json(*identity.entity_id) : Json(nullptr)},
            {"identity", identity.json()}, {"executable", nullable_text(raw.executable)}, {"user", nullable_text(raw.user_name)},
            {"start_time_ticks", decimal(identity.native_creation_ticks)}, {"parent", {{"entity_id", nullptr}}}};
    };
    Json data{{"format", "windows_sysmon_extended_v1"},
        {"event", {{"category", category}, {"type", operation}, {"timestamp", time}}},
        {"process", process(event.process, actor)}, {"source_facts", source_facts(telemetry::RawEvent{event})},
        {"enrichment", enrichment_facts(telemetry::RawEvent{event})},
        {"attribution", {{"confidence", "reported"}, {"native_instance_verified", false}}}};
    if (event.event_id == 22) {
        auto dns = dns_answers(event.query_results);
        dns["query_name"] = nullable_text(event.query_name);
        dns["query_status"] = event.query_status ? Json(*event.query_status) : Json(nullptr);
        dns["query_type"] = nullptr;
        dns["query_results"] = bounded_text(event.query_results);
        missing("dns.query_type", "source_does_not_report_field");
        if (!event.query_name) missing("dns.query_name", "source_not_reported");
        if (!event.query_status) missing("dns.query_status", "source_not_reported");
        if (!event.query_results) missing("dns.answers", "source_not_reported");
        if (dns["bound_exceeded"] == true) missing("dns.answers_remaining", "token_bound_exceeded");
        if (!dns["unparsed_tokens"].empty()) missing("dns.answers_unparsed", "unsupported_source_answer_syntax");
        data["dns"] = std::move(dns);
    } else {
        if (!event.target) throw std::invalid_argument("Sysmon interaction target PID is required");
        const auto target = reference(*event.target);
        Json body{{"target", process(*event.target, target)}};
        if (!target.native_creation_ticks) missing("target.start_time_ticks", "source_does_not_supply_native_creation_token");
        if (event.event_id == 10) {
            body["granted_access"] = decimal(event.granted_access);
            body["call_trace"] = bounded_text(event.call_trace);
            if (!event.granted_access) missing("process_access.granted_access", "source_not_reported");
            if (!event.call_trace) missing("process_access.call_trace", "source_not_reported");
        } else {
            body["new_thread_id"] = event.new_thread_id ? Json(*event.new_thread_id) : Json(nullptr);
            body["start_address"] = decimal(event.start_address);
            body["start_module"] = nullable_text(event.start_module);
            body["start_function"] = nullable_text(event.start_function);
            body["start_module_function_confidence"] = "reported_inference";
            if (!event.new_thread_id) missing("remote_thread.new_thread_id", "source_not_reported");
            if (!event.start_address) missing("remote_thread.start_address", "source_not_reported");
            if (!event.start_module) missing("remote_thread.start_module", "source_not_reported");
            if (!event.start_function) missing("remote_thread.start_function", "source_not_reported");
        }
        data[category] = std::move(body);
    }
    data["unavailable"] = std::move(unavailable);
    return envelope("observation", category, event.timestamp,
        {{"kind", "sysmon"}, {"provider", event.source.provider}, {"channel", *event.source.channel},
            {"native_record_id", event.source.record_id ? Json(std::to_string(*event.source.record_id)) : Json(nullptr)},
            {"native_observation_id", nullptr}, {"continuity", "unverified"}}, actor.json(), std::move(data));
}
}
