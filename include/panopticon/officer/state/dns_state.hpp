#pragma once

#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace panopticon::officer::state {

// Bounded application-side copies. Windows API/registry calls and allocations
// performed internally by Windows are not hard-time or hard-memory bounded.
struct DnsStateLimits {
    std::size_t adapter_buffer_bytes = 1024 * 1024;
    std::size_t max_adapters = 1024;
    std::size_t max_nrpt_rules = 2048;
    std::size_t max_pages = 256;
    std::size_t page_entries = 64;
    std::size_t page_bytes = 512 * 1024;
    std::size_t max_field_bytes = 16 * 1024;
    std::uint64_t soft_budget_ms = 30000;
};

// Read-only snapshot of caller-visible adapter resolver configuration,
// interface DNS settings, selected global policy values, and persisted NRPT
// rules. Pages are emitted before the returned capture manifest.
[[nodiscard]] nlohmann::json collect_dns_state_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    const std::function<bool()>& cancelled = {},
    DnsStateLimits limits = {});

} // namespace panopticon::officer::state
