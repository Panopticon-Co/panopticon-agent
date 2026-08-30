#pragma once

#include <string>

namespace panopticon::officer::delivery {

// Phase 1 minimum. Identity (agent_id/agent_key), enrollment, and durable
// spool config arrive in Phase 4/5 -- see docs/architecture/phase-6-delivery.md.
struct DeliveryConfig {
    std::string manager_url;         // e.g. https://192.168.1.50:8443
    bool verify_tls = true;          // false only when --insecure-tls is passed
    unsigned batch_max_events = 1000;
    unsigned flush_interval_ms = 5000;
};

}  // namespace panopticon::officer::delivery
