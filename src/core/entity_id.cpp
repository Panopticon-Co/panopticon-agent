#include "panopticon/officer/core/entity_id.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <chrono>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace panopticon::officer::core {
namespace {

void append_field(std::string& destination, std::string_view value) {
    destination.append(std::to_string(value.size()));
    destination.push_back(':');
    destination.append(value);
    destination.push_back('|');
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

std::optional<std::string> sha256_hex(std::string_view input, std::string& error_message) {
    error_message.clear();
    if (input.size() > std::numeric_limits<ULONG>::max()) {
        error_message = "Cannot hash an identity larger than the Windows CNG input limit.";
        return std::nullopt;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error_message = "BCryptOpenAlgorithmProvider failed for SHA-256.";
        return std::nullopt;
    }

    ULONG digest_size = 0;
    ULONG bytes_written = 0;
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&digest_size),
        sizeof(digest_size),
        &bytes_written,
        0);
    if (status < 0 || digest_size == 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error_message = "BCryptGetProperty failed to report the SHA-256 digest size.";
        return std::nullopt;
    }

    std::vector<unsigned char> digest(digest_size);
    auto* input_bytes = reinterpret_cast<PUCHAR>(const_cast<char*>(input.data()));
    status = BCryptHash(
        algorithm,
        nullptr,
        0,
        input_bytes,
        static_cast<ULONG>(input.size()),
        digest.data(),
        digest_size);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    if (status < 0) {
        error_message = "BCryptHash failed while deriving a telemetry identity.";
        return std::nullopt;
    }

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const unsigned char byte : digest) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

std::string timestamp_nanoseconds(telemetry::UtcTimestamp timestamp) {
    const auto ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           timestamp.time_since_epoch())
                           .count();
    return std::to_string(ticks);
}

std::string timestamp_milliseconds(telemetry::UtcTimestamp timestamp) {
    const auto ticks = std::chrono::duration_cast<std::chrono::milliseconds>(
                           timestamp.time_since_epoch())
                           .count();
    return std::to_string(ticks);
}

}  // namespace

std::optional<std::string> derive_process_entity_id(
    std::string_view host_id,
    std::uint32_t pid,
    telemetry::UtcTimestamp process_start_time,
    std::string& error_message) {
    if (host_id.empty()) {
        error_message = "A non-empty host ID is required to derive a process entity ID.";
        return std::nullopt;
    }

    std::string canonical;
    append_field(canonical, "process-entity-v2");
    append_field(canonical, host_id);
    append_field(canonical, std::to_string(pid));
    // Sysmon timestamps have millisecond precision while ETW carries FILETIME
    // precision. Canonicalizing here lets both sources identify the same process.
    append_field(canonical, timestamp_milliseconds(process_start_time));

    const auto digest = sha256_hex(canonical, error_message);
    return digest ? std::optional<std::string>{"proc_" + *digest} : std::nullopt;
}

std::optional<std::string> derive_process_event_id(
    std::string_view host_id,
    const telemetry::RawProcessEvent& event,
    std::string& error_message) {
    if (host_id.empty()) {
        error_message = "A non-empty host ID is required to derive an event ID.";
        return std::nullopt;
    }
    if (event.source.provider.empty()) {
        error_message = "A source provider is required to derive an event ID.";
        return std::nullopt;
    }

    std::string canonical;
    append_field(canonical, "process-start-event-v1");
    append_field(canonical, host_id);
    append_field(canonical, source_kind_name(event.source.kind));
    append_field(canonical, event.source.provider);
    append_field(canonical, event.source.channel.value_or(""));
    append_field(
        canonical,
        event.source.record_id ? std::to_string(*event.source.record_id) : std::string{});
    append_field(canonical, std::to_string(event.pid));
    append_field(canonical, timestamp_nanoseconds(event.process_start_time));

    const auto digest = sha256_hex(canonical, error_message);
    return digest ? std::optional<std::string>{"evt_" + *digest} : std::nullopt;
}

}  // namespace panopticon::officer::core
