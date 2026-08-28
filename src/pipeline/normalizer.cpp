#include "panopticon/officer/pipeline/normalizer.hpp"

#include "panopticon/officer/core/entity_id.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <string>

namespace panopticon::officer::pipeline {
namespace {

bool is_hexadecimal(char character) {
    return std::isxdigit(static_cast<unsigned char>(character)) != 0;
}

std::optional<std::string> normalized_sha256(
    const std::optional<std::string>& input,
    std::string& error_message) {
    if (!input) {
        return std::nullopt;
    }
    if (input->size() != 64 || !std::all_of(input->begin(), input->end(), is_hexadecimal)) {
        error_message = "A process SHA-256 value must contain exactly 64 hexadecimal characters.";
        return std::nullopt;
    }

    std::string result = *input;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool context_is_valid(const NormalizationContext& context, std::string& error_message) {
    if (context.agent.id.empty() || context.agent.version.empty()) {
        error_message = "Normalization requires a non-empty agent ID and agent version.";
        return false;
    }
    if (context.host.id.empty() || context.host.hostname.empty() ||
        context.host.os.name.empty() || context.host.os.build.empty()) {
        error_message = "Normalization requires complete host identity and OS metadata.";
        return false;
    }
    return true;
}

std::string source_kind_name(telemetry::TelemetrySourceKind kind) {
    switch (kind) {
        case telemetry::TelemetrySourceKind::etw:
            return "etw";
        case telemetry::TelemetrySourceKind::sysmon:
            return "sysmon";
        case telemetry::TelemetrySourceKind::windows_event_log:
            return "windows_event_log";
    }
    return "unknown";
}

}  // namespace

std::string format_utc_timestamp(telemetry::UtcTimestamp timestamp) {
    const auto whole_seconds = std::chrono::floor<std::chrono::seconds>(timestamp);
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp - whole_seconds);
    const auto system_time = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        whole_seconds);
    const std::time_t seconds_since_epoch = std::chrono::system_clock::to_time_t(system_time);

    std::tm utc{};
    if (gmtime_s(&utc, &seconds_since_epoch) != 0) {
        return {};
    }

    char buffer[32]{};
    const int characters = std::snprintf(
        buffer,
        sizeof(buffer),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        static_cast<long long>(milliseconds.count()));
    return characters > 0 && characters < static_cast<int>(sizeof(buffer))
               ? std::string{buffer, static_cast<std::size_t>(characters)}
               : std::string{};
}

std::optional<telemetry::PanopticonEvent> normalize_process_event(
    const enrichment::EnrichedProcessEvent& enriched,
    const NormalizationContext& context,
    std::string& error_message) {
    error_message.clear();
    if (!context_is_valid(context, error_message)) {
        return std::nullopt;
    }
    if (enriched.raw.source.provider.empty()) {
        error_message = "A raw process event must identify its source provider.";
        return std::nullopt;
    }
    if (enriched.parent_start_time && !enriched.raw.parent_pid) {
        error_message = "A parent process start time cannot be used without a parent PID.";
        return std::nullopt;
    }

    const auto entity_id = core::derive_process_entity_id(
        context.host.id, enriched.raw.pid, enriched.raw.process_start_time, error_message);
    if (!entity_id) {
        return std::nullopt;
    }
    const auto event_id = core::derive_process_event_id(
        context.host.id, enriched.raw, error_message);
    if (!event_id) {
        return std::nullopt;
    }

    std::optional<std::string> parent_entity_id;
    if (enriched.raw.parent_pid && enriched.parent_start_time) {
        parent_entity_id = core::derive_process_entity_id(
            context.host.id,
            *enriched.raw.parent_pid,
            *enriched.parent_start_time,
            error_message);
        if (!parent_entity_id) {
            return std::nullopt;
        }
    }

    const auto sha256 = normalized_sha256(enriched.sha256, error_message);
    if (enriched.sha256 && !sha256) {
        return std::nullopt;
    }

    const std::string timestamp = format_utc_timestamp(enriched.raw.process_start_time);
    if (timestamp.empty()) {
        error_message = "The process start time could not be formatted as UTC.";
        return std::nullopt;
    }

    telemetry::PanopticonEvent result;
    result.event = {*event_id, "process", "start", timestamp};
    result.source = {
        source_kind_name(enriched.raw.source.kind),
        enriched.raw.source.provider,
        enriched.raw.source.channel,
        enriched.raw.source.record_id,
    };
    result.agent = context.agent;
    result.host = context.host;
    result.user = {
        enriched.user.name,
        enriched.user.domain,
        enriched.user.sid ? enriched.user.sid : enriched.raw.user_sid,
    };
    result.process = {
        *entity_id,
        enriched.raw.pid,
        enriched.process_name,
        enriched.raw.executable,
        enriched.raw.command_line,
        {parent_entity_id, enriched.raw.parent_pid, enriched.parent_name},
        {sha256},
    };
    return result;
}

// -- V3 telemetry-family normalization --------------------------------
namespace {

std::optional<std::string> leaf_name(const std::optional<std::string>& path) {
    if (!path || path->empty()) {
        return std::nullopt;
    }
    const std::size_t separator = path->find_last_of("\\/");
    return separator == std::string::npos ? *path : path->substr(separator + 1);
}

void split_account(
    const std::optional<std::string>& account,
    telemetry::UserMetadata& user) {
    if (!account || account->empty()) {
        return;
    }
    const std::size_t separator = account->find('\\');
    if (separator == std::string::npos) {
        user.name = *account;
        return;
    }
    if (separator != 0) {
        user.domain = account->substr(0, separator);
    }
    if (separator + 1 < account->size()) {
        user.name = account->substr(separator + 1);
    }
}

std::optional<std::string> canonical_sha256(
    const std::optional<std::string>& input, std::string& error_message) {
    if (!input) {
        return std::nullopt;
    }
    if (input->size() != 64 || !std::all_of(input->begin(), input->end(), is_hexadecimal)) {
        error_message = "A telemetry SHA-256 value must contain exactly 64 hexadecimal characters.";
        return std::nullopt;
    }
    std::string result = *input;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

// Builds the shared skeleton (identity + process context) for a family event.
// Returns std::nullopt with error_message set on failure.
std::optional<telemetry::PanopticonEvent> build_family_base(
    const telemetry::SourceProvenance& source,
    const telemetry::RawProcessContext& process,
    telemetry::UtcTimestamp timestamp,
    std::string_view category,
    std::string_view type,
    const NormalizationContext& context,
    std::string& error_message) {
    error_message.clear();
    if (!context_is_valid(context, error_message)) {
        return std::nullopt;
    }
    if (source.provider.empty()) {
        error_message = "A raw telemetry event must identify its source provider.";
        return std::nullopt;
    }

    const auto entity_id = core::derive_process_context_entity_id(
        context.host.id, process.pid, process.process_guid.value_or(""), error_message);
    if (!entity_id) {
        return std::nullopt;
    }
    const auto event_id = core::derive_telemetry_event_id(
        context.host.id, source, category, type, process.pid, timestamp, error_message);
    if (!event_id) {
        return std::nullopt;
    }
    const std::string formatted = format_utc_timestamp(timestamp);
    if (formatted.empty()) {
        error_message = "The telemetry timestamp could not be formatted as UTC.";
        return std::nullopt;
    }

    telemetry::PanopticonEvent result;
    result.event = {*event_id, std::string{category}, std::string{type}, formatted};
    result.source = {
        source_kind_name(source.kind),
        source.provider,
        source.channel,
        source.record_id,
    };
    result.agent = context.agent;
    result.host = context.host;
    split_account(process.user_name, result.user);
    if (!result.user.sid) {
        result.user.sid = process.user_sid;
    }
    result.process = {
        *entity_id,
        process.pid,
        process.process_name ? process.process_name : leaf_name(process.executable),
        process.executable,
        std::nullopt,
        {std::nullopt, std::nullopt, std::nullopt},
        {std::nullopt},
    };
    return result;
}

std::string network_direction_name(telemetry::NetworkDirection d) {
    return d == telemetry::NetworkDirection::inbound ? "inbound" : "outbound";
}

std::optional<std::string> network_protocol_name(telemetry::NetworkProtocol p) {
    switch (p) {
        case telemetry::NetworkProtocol::tcp: return "tcp";
        case telemetry::NetworkProtocol::udp: return "udp";
        case telemetry::NetworkProtocol::other: return std::nullopt;
    }
    return std::nullopt;
}

std::string file_operation_name(telemetry::FileOperation op) {
    switch (op) {
        case telemetry::FileOperation::create: return "create";
        case telemetry::FileOperation::remove: return "delete";
        case telemetry::FileOperation::rename: return "rename";
    }
    return "create";
}

std::string registry_operation_name(telemetry::RegistryOperation op) {
    switch (op) {
        case telemetry::RegistryOperation::add_key: return "add_key";
        case telemetry::RegistryOperation::delete_key: return "delete_key";
        case telemetry::RegistryOperation::set_value: return "set_value";
        case telemetry::RegistryOperation::rename_key: return "rename_key";
    }
    return "set_value";
}

}  // namespace

std::optional<telemetry::PanopticonEvent> normalize_network_event(
    const telemetry::RawNetworkEvent& event,
    const NormalizationContext& context,
    std::string& error_message) {
    auto base = build_family_base(
        event.source, event.process, event.timestamp, "network", "connect", context, error_message);
    if (!base) {
        return std::nullopt;
    }
    base->network = telemetry::NetworkMetadata{
        network_direction_name(event.direction),
        network_protocol_name(event.protocol),
        event.source_ip,
        event.source_port,
        event.destination_ip,
        event.destination_port,
        event.destination_hostname,
    };
    return base;
}

std::optional<telemetry::PanopticonEvent> normalize_file_event(
    const telemetry::RawFileEvent& event,
    const NormalizationContext& context,
    std::string& error_message) {
    const std::string operation = file_operation_name(event.operation);
    auto base = build_family_base(
        event.source, event.process, event.timestamp, "file", operation, context, error_message);
    if (!base) {
        return std::nullopt;
    }
    const auto sha256 = canonical_sha256(event.sha256, error_message);
    if (event.sha256 && !sha256) {
        return std::nullopt;
    }
    base->file = telemetry::FileMetadata{
        operation,
        event.path,
        event.target_path,
        event.previous_path,
        {sha256},
    };
    return base;
}

std::optional<telemetry::PanopticonEvent> normalize_registry_event(
    const telemetry::RawRegistryEvent& event,
    const NormalizationContext& context,
    std::string& error_message) {
    const std::string operation = registry_operation_name(event.operation);
    auto base = build_family_base(
        event.source, event.process, event.timestamp, "registry", operation, context, error_message);
    if (!base) {
        return std::nullopt;
    }
    base->registry = telemetry::RegistryMetadata{
        operation,
        event.key_path,
        event.value_name,
        event.value_type,
        event.value_data,  // metadata-only; the decoder leaves this unset by policy
    };
    return base;
}

std::optional<telemetry::PanopticonEvent> normalize_image_load_event(
    const telemetry::RawImageLoadEvent& event,
    const NormalizationContext& context,
    std::string& error_message) {
    auto base = build_family_base(
        event.source, event.process, event.timestamp, "image_load", "load", context, error_message);
    if (!base) {
        return std::nullopt;
    }
    const auto sha256 = canonical_sha256(event.sha256, error_message);
    if (event.sha256 && !sha256) {
        return std::nullopt;
    }
    base->image_load = telemetry::ImageLoadMetadata{
        event.path,
        event.is_signed,
        event.signature_status,
        {sha256},
    };
    return base;
}

}  // namespace panopticon::officer::pipeline
