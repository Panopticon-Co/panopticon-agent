#pragma once

#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <functional>
#include <nlohmann/json.hpp>

namespace panopticon::officer::state {

// Caller-visible local SMB server sessions and open-file records only.
// This does not enumerate outbound client connections or attribute activity to
// a process. Native NetAPI allocations/calls are outside application bounds.
[[nodiscard]] nlohmann::json collect_remote_access_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    NativeInventoryLimits limits = {}, const std::function<bool()>& cancelled = {});

}
