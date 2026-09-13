#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::response {

// The Manager management connection this host must keep reachable even
// while isolated -- the only exception to a default-deny filter set. No
// SSH/RDP break-glass and no general ESTABLISHED/RELATED bypass exist here,
// mirroring the Linux agent's isolation ADR exactly: the sole carve-out is
// "stay reachable by the one channel that can release the isolation."
struct IsolationExceptionEndpoint {
    std::string manager_host;  // Numeric IPv4/IPv6 literal or empty (host, not URL).
    std::uint16_t manager_port = 0;
};

// A fully-determined, pure description of the WFP objects an isolate/
// release operation would create or remove -- deterministic GUIDs derived
// from a fixed provider namespace, so isolate() followed by release()
// always targets exactly the objects this agent itself created (idempotent:
// isolating an already-isolated host, or releasing an already-released one,
// touches nothing new). Constructing this plan calls no Win32 API and is
// fully unit-testable without WFP, elevation, or a live network.
struct IsolationPlan {
    std::string sublayer_name;
    std::string block_outbound_filter_name;
    std::string block_inbound_filter_name;
    std::string permit_manager_outbound_filter_name;
    std::string permit_manager_inbound_filter_name;
    IsolationExceptionEndpoint manager_exception;
};

[[nodiscard]] IsolationPlan build_isolation_plan(const IsolationExceptionEndpoint& manager_exception);

// Applies (isolate) or removes (release) the filter set described by
// build_isolation_plan() via FwpmEngineOpen0/FwpmSubLayerAdd0/
// FwpmFilterAdd0/FwpmFilterDeleteByKey0. Idempotent: calling isolate() when
// already isolated, or release() when not isolated, succeeds without
// duplicating or erroring. Requires an elevated process and the WFP engine
// to be reachable -- callers must check the return value and must not
// assume real network-level enforcement was exercised just because this
// returned true (see RESPONSE.md's ENVIRONMENT-BLOCKED note: real
// enforcement against a live non-loopback adapter has not been validated in
// this development environment).
[[nodiscard]] std::optional<bool> apply_isolation(const IsolationPlan& plan, std::string& error_message);
[[nodiscard]] std::optional<bool> release_isolation(const IsolationPlan& plan, std::string& error_message);

}  // namespace panopticon::officer::response
