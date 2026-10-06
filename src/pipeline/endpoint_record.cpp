#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/pipeline/serializer.hpp"
#include "panopticon/officer/pipeline/source_facts.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace panopticon::officer::pipeline {
namespace {
using Json = nlohmann::json;
telemetry::UtcTimestamp now() { return std::chrono::time_point_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now()); }
std::string hash(const std::string& input) {
    std::string error; const auto result = core::sha256_hex(input, error);
    if (!result) throw std::runtime_error(error);
    return *result;
}
std::string fresh_epoch() {
    std::string bytes(32, '\0');
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("observation epoch entropy unavailable");
    return "epoch_" + hash(bytes);
}
Json nullable(const std::optional<std::string>& value) { return value ? Json(*value) : Json(nullptr); }
}
EndpointRecordFactory::EndpointRecordFactory(NormalizationContext context, std::string device_id, std::string installation_id, std::optional<std::string> boot_id, std::uint64_t generation)
    : context_(std::move(context)), device_id_(std::move(device_id)), installation_id_(std::move(installation_id)), boot_id_(std::move(boot_id)), epoch_(fresh_epoch()),
      generation_(generation), processes_(context_.host.id, boot_id_) {
    if (installation_id_.empty() || device_id_.empty() || generation_ == 0) throw std::invalid_argument("canonical records require device, installation and committed generation identity");
}
Json EndpointRecordFactory::envelope(std::string kind, std::string category, telemetry::UtcTimestamp time,
    Json provenance, Json subject, Json data) {
    std::scoped_lock lock{mutex_};
    if (sequence_ == std::numeric_limits<std::uint64_t>::max()) throw std::runtime_error("observation sequence exhausted");
    const auto sequence = ++sequence_;
    const auto received = now();
    provenance["collector_epoch"] = epoch_;
    provenance["collector_generation"] = std::to_string(generation_);
    provenance["capture_clock"] = "windows_uptime_ms";
    provenance["capture_uptime_ms"] = std::to_string(GetTickCount64());
    provenance["sequence"] = std::to_string(sequence);
    provenance["received_at"] = format_utc_timestamp(received);
    provenance["event_time_ns"] = std::to_string(time.time_since_epoch().count());
    return {{"schema_version", "1.0"}, {"record_id", "rec_" + hash(installation_id_ + ":" + epoch_ + ":" + std::to_string(sequence))},
        {"kind", kind}, {"category", category}, {"observed_at", format_utc_timestamp(time)},
        {"endpoint", {{"agent_id", context_.agent.id}, {"host_id", context_.host.id}, {"device_id", device_id_},
            {"installation_id", installation_id_}, {"boot_id", nullable(boot_id_)}}},
        {"provenance", std::move(provenance)}, {"subject", std::move(subject)}, {"data", std::move(data)}};
}
Json EndpointRecordFactory::observation(const telemetry::RawEvent& raw, const telemetry::PanopticonEvent& normalized) {
    auto data = event_to_json(normalized);
    data.erase("schema_version");
    data["source_facts"] = source_facts(raw);
    data["enrichment"] = enrichment_facts(raw);
    return std::visit([&](const auto& event) {
        using Event = std::decay_t<decltype(event)>;
        telemetry::UtcTimestamp time;
        core::ProcessReference reference;
        const auto source_namespace = normalized.source.kind + ":" + event.source.provider + ":" + event.source.channel.value_or("");
        if (event.source.provider.empty() || event.source.provider.size() > 512 ||
            !valid_utf8(event.source.provider) || source_namespace.size() > 1024 || !valid_utf8(source_namespace) ||
            (event.source.channel && event.source.channel->size() > 512))
            throw std::invalid_argument("source metadata cannot be represented in canonical provenance; retain decoded evidence");
        if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>) {
            time = event.process_start_time;
            if (event.process_guid && (event.process_guid->empty() || event.process_guid->size() > 256 || !valid_utf8(*event.process_guid)))
                throw std::invalid_argument("source process GUID cannot be represented in canonical reference");
            if (event.parent_process_guid && (event.parent_process_guid->empty() || event.parent_process_guid->size() > 256 || !valid_utf8(*event.parent_process_guid)))
                throw std::invalid_argument("source parent GUID cannot be represented in canonical reference");
            reference = processes_.observe(event.pid, event.start_time_ticks, event.process_guid, source_namespace);
            data["process"]["parent"]["entity_id"] = nullptr;
            data["process"]["parent"]["identity"] = nullptr;
            if (event.parent_pid) {
                const auto parent = processes_.observe(*event.parent_pid, std::nullopt, event.parent_process_guid, source_namespace);
                data["process"]["parent"]["entity_id"] = nullable(parent.entity_id);
                data["process"]["parent"]["identity"] = parent.json();
            }
        } else {
            time = event.timestamp;
            if (event.process.process_guid && (event.process.process_guid->empty() || event.process.process_guid->size() > 256 || !valid_utf8(*event.process.process_guid)))
                throw std::invalid_argument("source process GUID cannot be represented in canonical reference");
            reference = processes_.observe(event.process.pid, std::nullopt, event.process.process_guid, source_namespace);
            data["process"]["parent"]["entity_id"] = nullptr;
        }
        data["process"]["entity_id"] = nullable(reference.entity_id);
        if (format_utc_timestamp(time).empty()) throw std::invalid_argument("native event time cannot be rendered as UTC; retain exact decoded value");
        data["process"]["start_time_ticks"] = reference.native_creation_ticks ? Json(std::to_string(*reference.native_creation_ticks)) : Json(nullptr);
        Json provenance{{"kind", normalized.source.kind}, {"provider", event.source.provider}, {"channel", nullable(event.source.channel)},
            {"native_record_id", event.source.record_id ? Json(std::to_string(*event.source.record_id)) : Json(nullptr)},
            {"native_observation_id", normalized.event.id}, {"continuity", "unverified"}};
        return envelope("observation", normalized.event.category, time, std::move(provenance), reference.json(), std::move(data));
    }, raw);
}
Json EndpointRecordFactory::capture_scope() const {
    return {{"installation_id", installation_id_}, {"boot_id", nullable(boot_id_)},
        {"collector_generation", std::to_string(generation_)}, {"collector_epoch", epoch_}};
}
Json EndpointRecordFactory::state(std::string category, Json data) {
    return envelope("state", std::move(category), now(), {{"kind", "win32"}, {"provider", "Officer-State"}, {"channel", nullptr},
        {"native_record_id", nullptr}, {"native_observation_id", nullptr}, {"continuity", "snapshot"}}, nullptr, std::move(data));
}
Json EndpointRecordFactory::health(Json data) {
    return envelope("health", "endpoint_health", now(), {{"kind", "agent"}, {"provider", "Officer-Health"}, {"channel", nullptr},
        {"native_record_id", nullptr}, {"native_observation_id", nullptr}, {"continuity", "snapshot"}}, nullptr, std::move(data));
}
Json EndpointRecordFactory::gap(std::string source, Json data) {
    return envelope("gap", "source_loss", now(), {{"kind", "agent"}, {"provider", "Officer-Source-Supervisor"}, {"channel", std::move(source)},
        {"native_record_id", nullptr}, {"native_observation_id", nullptr}, {"continuity", "unverified"}}, nullptr, std::move(data));
}
Json EndpointRecordFactory::normalization_failure(const telemetry::RawEvent& raw, std::string error) {
    return std::visit([&](const auto& event) {
        using Event = std::decay_t<decltype(event)>;
        const auto kind = observed_source_kind_name(event.source.kind);
        const auto original_namespace = kind + ":" + event.source.provider + ":" + event.source.channel.value_or("");
        const bool valid_scope = valid_utf8(original_namespace) && original_namespace.size() <= 1024;
        auto guid = [&]() {
            if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>) return event.process_guid;
            else return event.process.process_guid;
        }();
        if (!valid_scope || (guid && (guid->empty() || guid->size() > 256 || !valid_utf8(*guid)))) guid.reset();
        core::ProcessReference reference;
        const auto scope = valid_scope ? original_namespace : "Officer-Decoded-Facts:invalid-source-scope";
        if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>)
            reference = processes_.observe(event.pid, event.start_time_ticks, guid, scope);
        else reference = processes_.observe(event.process.pid, std::nullopt, guid, scope);
        // A failure is captured now; the original event clock/value is retained
        // in source_facts even when it cannot be rendered as a valid UTC date.
        return envelope("evidence", "normalization_failure", now(), {{"kind", "agent"},
            {"provider", "Officer-Decoded-Facts"}, {"channel", nullptr},
            {"native_record_id", event.source.record_id ? Json(std::to_string(*event.source.record_id)) : Json(nullptr)},
            {"native_observation_id", nullptr}, {"continuity", "unverified"}}, reference.json(),
            {{"stage", "normalization_or_serialization"}, {"error", lossless_text(error)},
                {"source_facts", source_facts(raw)}, {"enrichment", enrichment_facts(raw)}, {"native_bytes_retained", false}});
    }, raw);
}
}  // namespace panopticon::officer::pipeline
