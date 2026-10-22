#pragma once

#include <nlohmann/json.hpp>

namespace panopticon::officer::collectors {

// Produces additive, source-native semantics from decode_windows_event_xml's
// bounded result. The input object is never modified. Raw values remain source
// claims; this layer does not verify an actor, token, process, or target.
class SecurityAuditSemantics {
public:
    [[nodiscard]] static nlohmann::json enrich(const nlohmann::json& decoded_event);

    // Read-only view of system advanced audit policy. This neither enables nor
    // changes auditing. It intentionally does not compute per-user/token policy.
    [[nodiscard]] static nlohmann::json query_system_policy();
};

}  // namespace panopticon::officer::collectors
