#pragma once

#include <cstdint>
#include <string>

namespace panopticon::officer::delivery {

// Phase 1 minimum plus Phase 5's durable spool (see
// docs/architecture/phase-9-telemetry-durability.md). Identity
// (agent_id/agent_key) and enrollment remain Phase 4 scope.
struct DeliveryConfig {
    std::string manager_url;         // e.g. https://192.168.1.50:8443
    bool verify_tls = true;          // false only when --insecure-tls is passed
    unsigned batch_max_events = 1000;
    unsigned flush_interval_ms = 5000;

    // Every batch is durably persisted here before an HTTP attempt is made,
    // and replayed from here after a failure/restart -- see spool.hpp.
    // Relative paths resolve against the process's current working
    // directory, matching how officer-agent.exe already resolves other
    // relative paths (e.g. --rules-dir).
    std::string spool_directory = "spool";
    std::uint64_t spool_max_segment_bytes = 8ull * 1024 * 1024;
    std::uint64_t spool_max_total_bytes = 64ull * 1024 * 1024;
    unsigned spool_max_delivery_attempts = 8;
    unsigned spool_base_backoff_ms = 1000;
    unsigned spool_max_backoff_ms = 60000;
};

}  // namespace panopticon::officer::delivery
