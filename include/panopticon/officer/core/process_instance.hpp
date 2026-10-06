#pragma once
#include "panopticon/officer/telemetry/raw_event_common.hpp"
#include <nlohmann/json.hpp>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace panopticon::officer::core {

struct ProcessReference {
    std::uint32_t observed_pid = 0;
    std::optional<std::string> entity_id;
    std::string resolution = "unresolved";
    std::optional<std::uint64_t> native_creation_ticks;
    std::optional<std::string> source_guid;
    std::optional<std::string> boot_id;
    std::string source_namespace;
    [[nodiscard]] nlohmann::json json() const;
};

// Exact native facts and source-scoped aliases only. No timestamp rounding,
// PID-only lookup, live PID probing, or proximity-based alias promotion.
class ProcessInstanceStore {
public:
    ProcessInstanceStore(std::string host_id, std::optional<std::string> boot_id, std::size_t resident_limit = 32768);
    [[nodiscard]] ProcessReference observe(std::uint32_t pid, std::optional<std::uint64_t> ticks,
        std::optional<std::string> guid, std::string source_namespace);
    void terminate(const ProcessReference& reference, telemetry::UtcTimestamp time);
    [[nodiscard]] nlohmann::json snapshot() const;
    [[nodiscard]] std::uint64_t admission_failures() const;
private:
    struct Instance { ProcessReference reference; std::optional<telemetry::UtcTimestamp> terminated_at; };
    std::string host_id_;
    std::optional<std::string> boot_id_;
    std::size_t resident_limit_;
    std::uint64_t admission_failures_ = 0;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Instance> instances_;
};

// Native query is dynamically resolved and optional. Never approximate boot
// identity from current wall clock minus uptime when the query is unavailable.
[[nodiscard]] std::optional<std::string> query_native_boot_id(std::string& error);
}  // namespace panopticon::officer::core
