#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <functional>
#include <optional>
#include <string>
#include <vector>
namespace panopticon::officer::state {
struct ModuleInventoryLimits {
    NativeInventoryLimits pages;
    std::size_t processes = 8, modules_per_process = 512, snapshot_attempts = 3;
    std::uint32_t after_pid = 0;
};
// Toolhelp loader-list descriptors only, not memory contents, mapped-file
// identity, signer verification or comprehensive image-load/unload coverage.
[[nodiscard]] nlohmann::json collect_module_inventory_pages(const std::string& host_id,
    const std::optional<std::string>& boot_id, const std::function<bool(nlohmann::json)>& consumer,
    ModuleInventoryLimits limits = {}, const std::function<bool()>& cancelled = {},
    const std::vector<std::uint32_t>& requested_pids = {});
}
