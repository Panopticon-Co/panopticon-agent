#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <functional>
namespace panopticon::officer::state {
enum class SoftwareSource { msi, uninstall_registry };
const char* software_source_name(SoftwareSource source);
nlohmann::json collect_software_inventory_pages(SoftwareSource source,
    const std::function<bool(nlohmann::json)>& consumer, NativeInventoryLimits limits = {},
    const std::function<bool()>& cancelled = {});
}
