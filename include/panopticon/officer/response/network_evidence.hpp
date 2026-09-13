#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::response {

// Collects bounded TCP/UDP (v4 and v6) connection tables via
// GetExtendedTcpTable/GetExtendedUdpTable and serializes them as a single
// bounded JSON line, mirroring panopticon-linux-agent's
// collect_network_evidence(). owner_pid is always populated here (the
// *_OWNER_PID table classes always carry it on Windows), but the field
// stays optional/nullable in the wire shape for parity with Linux, where
// the kernel does not always supply an owner.
[[nodiscard]] std::optional<std::string> collect_network_evidence(std::size_t maximum_connections_per_table,
                                                                    std::size_t maximum_bytes,
                                                                    std::string& error_message);

}  // namespace panopticon::officer::response
