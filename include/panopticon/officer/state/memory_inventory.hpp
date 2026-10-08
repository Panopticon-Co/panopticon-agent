#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <functional>
#include <optional>
#include <string>
#include <vector>
namespace panopticon::officer::state {
struct MemoryInventoryLimits {
    NativeInventoryLimits pages;
    std::size_t processes = 8, regions_per_process = 256, queries_per_process = 4096;
    std::uint32_t after_pid = 0;
};
// Read-only region metadata on one held process at a time. No VM_READ,
// memory content, privilege enablement, target mutation or injection verdict.
[[nodiscard]] nlohmann::json collect_memory_inventory_pages(const std::string& host_id,
    const std::optional<std::string>& boot_id, const std::function<bool(nlohmann::json)>& consumer,
    MemoryInventoryLimits limits = {}, const std::function<bool()>& cancelled = {},
    const std::vector<std::uint32_t>& requested_pids = {});
}
