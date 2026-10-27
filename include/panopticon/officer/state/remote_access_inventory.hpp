#pragma once

#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <functional>
#include <nlohmann/json.hpp>

namespace panopticon::officer::state {

// Caller-visible local SMB server sessions and open files, TermService/WinRM
// SCM state, configured RDP settings (incl. the Group Policy key) and WSMan
// listeners. Configured values are not effective policy or proof that a listener
// accepts connections. No outbound clients or process attribution. Native
// NetAPI/SCM/registry allocations and calls are outside application bounds.
[[nodiscard]] nlohmann::json collect_remote_access_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    NativeInventoryLimits limits = {}, const std::function<bool()>& cancelled = {});

}
