#pragma once

#include <cstdint>
#include <string>

namespace panopticon::officer::response {

// Opt-in response configuration, analogous to panopticon-linux-agent's
// response_enabled/isolation_socket_path settings. Every field here is
// additive: an operator who never sets --enable-response gets byte-
// identical behavior to today's telemetry-only agent (no polling, no new
// files written, no new outbound calls).
struct ResponseConfig {
    bool enabled = false;
    std::string identity_path;          // Enrolled identity file (agent_id/host_id/bearer_token).
    std::string bootstrap_token_path;   // One-shot enrollment token file; only read if identity_path is missing.
    std::string replay_ledger_path;     // Durable command-id ledger.
    std::string file_collection_root;   // Allow-listed root for COLLECT_FILE / QUARANTINE_FILE.
    std::string quarantine_root;        // Destination root for QUARANTINE_FILE.
    std::string manager_exception_host; // Numeric address the isolation filter must keep reachable.
    std::uint16_t manager_exception_port = 0;
    std::size_t maximum_event_bytes = 262144;
    std::size_t maximum_connections_per_table = 512;
    std::size_t replay_ledger_capacity = 4096;
};

}  // namespace panopticon::officer::response
