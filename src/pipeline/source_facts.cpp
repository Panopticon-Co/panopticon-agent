#include "panopticon/officer/pipeline/source_facts.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <limits>
#include <type_traits>

namespace panopticon::officer::pipeline {
using Json = nlohmann::json;
bool valid_utf8(std::string_view text) {
    return text.empty() || (text.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0) > 0);
}
Json lossless_text(std::string_view text) {
    if (valid_utf8(text)) return std::string{text};
    std::string bytes;
    bytes.reserve(text.size() * 2);
    constexpr char digits[] = "0123456789abcdef";
    for (const unsigned char byte : text) { bytes += digits[byte >> 4]; bytes += digits[byte & 15]; }
    return {{"encoding", "hex"}, {"bytes", std::move(bytes)}, {"byte_length", std::to_string(text.size())}};
}
std::string observed_source_kind_name(telemetry::TelemetrySourceKind kind) {
    switch (kind) {
    case telemetry::TelemetrySourceKind::etw: return "etw";
    case telemetry::TelemetrySourceKind::sysmon: return "sysmon";
    case telemetry::TelemetrySourceKind::windows_event_log: return "windows_event_log";
    }
    return "unknown";
}
namespace {
Json text(const std::optional<std::string>& value) { return value ? lossless_text(*value) : Json(nullptr); }
Json number(const std::optional<std::uint16_t>& value) { return value ? Json(*value) : Json(nullptr); }
Json decimal(const std::optional<std::uint64_t>& value) { return value ? Json(std::to_string(*value)) : Json(nullptr); }
Json context(const telemetry::RawProcessContext& process) {
    return {{"pid", process.pid}, {"executable", text(process.executable)}, {"process_name", text(process.process_name)},
        {"user_name", text(process.user_name)}, {"user_sid", text(process.user_sid)}, {"process_guid", text(process.process_guid)}};
}
}
Json source_facts(const telemetry::RawEvent& raw) {
    return std::visit([](const auto& event) {
        using Event = std::decay_t<decltype(event)>;
        Json result{{"representation", "decoded_source_facts_v1"},
            {"source", {{"kind", observed_source_kind_name(event.source.kind)}, {"kind_value", static_cast<int>(event.source.kind)},
                {"provider", lossless_text(event.source.provider)}, {"channel", text(event.source.channel)}, {"record_id", decimal(event.source.record_id)}}}};
        if constexpr (std::is_same_v<Event, telemetry::RawProcessEvent>) {
            result["family"] = "process";
            result["event_time_ns"] = std::to_string(event.process_start_time.time_since_epoch().count());
            result["process"] = {{"pid", event.pid}, {"start_time_ticks", decimal(event.start_time_ticks)},
                {"process_guid", text(event.process_guid)}, {"parent_process_guid", text(event.parent_process_guid)},
                {"parent_pid", event.parent_pid ? Json(*event.parent_pid) : Json(nullptr)}, {"parent_executable", text(event.parent_executable)},
                {"executable", text(event.executable)}, {"command_line", text(event.command_line)},
                {"user_sid", text(event.user_sid)}, {"user_name", text(event.user_name)}, {"sha256", text(event.sha256)}};
        } else {
            result["event_time_ns"] = std::to_string(event.timestamp.time_since_epoch().count());
            result["process"] = context(event.process);
            if constexpr (std::is_same_v<Event, telemetry::RawNetworkEvent>) {
                result["family"] = "network";
                result["network"] = {{"direction_value", static_cast<int>(event.direction)}, {"protocol_value", static_cast<int>(event.protocol)},
                    {"source_ip", text(event.source_ip)}, {"source_port", number(event.source_port)}, {"destination_ip", text(event.destination_ip)},
                    {"destination_port", number(event.destination_port)}, {"destination_hostname", text(event.destination_hostname)}};
            } else if constexpr (std::is_same_v<Event, telemetry::RawFileEvent>) {
                result["family"] = "file";
                result["file"] = {{"operation_value", static_cast<int>(event.operation)}, {"path", text(event.path)},
                    {"target_path", text(event.target_path)}, {"previous_path", text(event.previous_path)}, {"sha256", text(event.sha256)}};
            } else if constexpr (std::is_same_v<Event, telemetry::RawRegistryEvent>) {
                result["family"] = "registry";
                result["registry"] = {{"operation_value", static_cast<int>(event.operation)}, {"key_path", text(event.key_path)},
                    {"value_name", text(event.value_name)}, {"value_type", text(event.value_type)}, {"value_data", text(event.value_data)}};
            } else if constexpr (std::is_same_v<Event, telemetry::RawImageLoadEvent>) {
                result["family"] = "image_load";
                result["image"] = {{"path", text(event.path)}, {"is_signed", event.is_signed ? Json(*event.is_signed) : Json(nullptr)},
                    {"signature_status", text(event.signature_status)}, {"sha256", text(event.sha256)}};
            }
        }
        return result;
    }, raw);
}
Json enrichment_facts(const telemetry::RawEvent& raw) {
    return std::visit([](const auto& event) -> Json {
        using Event = std::decay_t<decltype(event)>;
        if constexpr (!std::is_same_v<Event, telemetry::RawProcessEvent>) {
            if (event.process.cached_context) {
                const auto& hint = *event.process.cached_context;
                return {{"cached_process_context", {{"basis", "retained_process_start_guid_pid_match"},
                    {"applicable", cached_context_applicable(event.source, event.process)},
                    {"source", {{"kind", observed_source_kind_name(hint.source.kind)}, {"provider", lossless_text(hint.source.provider)},
                        {"channel", text(hint.source.channel)}, {"record_id", decimal(hint.source.record_id)}}},
                    {"process_start_time_ns", std::to_string(hint.process_start_time.time_since_epoch().count())},
                    {"pid", hint.pid}, {"process_guid", lossless_text(hint.process_guid)},
                    {"executable", text(hint.executable)}, {"user_name", text(hint.user_name)}, {"user_sid", text(hint.user_sid)}}}};
            }
        }
        return Json::object();
    }, raw);
}
bool cached_context_applicable(const telemetry::SourceProvenance& source, const telemetry::RawProcessContext& process) {
    if (!process.cached_context || !process.process_guid) return false;
    const auto& cached = *process.cached_context;
    return cached.executable && !cached.executable->empty() && *cached.executable != "<unknown process>" &&
        cached.pid == process.pid && cached.process_guid == *process.process_guid &&
        cached.source.kind == source.kind && cached.source.provider == source.provider && cached.source.channel == source.channel &&
        (!process.executable || process.executable->empty() || *process.executable == "<unknown process>");
}
}
