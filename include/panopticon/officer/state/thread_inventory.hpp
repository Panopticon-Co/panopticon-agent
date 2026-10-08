#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <functional>
#include <optional>
#include <string>
namespace panopticon::officer::state {
// Toolhelp descriptors and later held thread queries are separate observations.
// No PID-only owner join, start-address guess or continuous thread coverage.
[[nodiscard]] nlohmann::json collect_thread_inventory_pages(const std::string& host_id,
    const std::optional<std::string>& boot_id, const std::function<bool(nlohmann::json)>& consumer,
    NativeInventoryLimits limits = {}, const std::function<bool()>& cancelled = {});
}
