#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>

namespace panopticon::officer::state {
enum class PersistenceSource { scheduled_tasks, wmi_subscriptions, startup };
using PersistenceLimits = NativeInventoryLimits;
// Local, caller-visible, non-atomic state only. The budget is checked between
// native calls, not a hard deadline on COM/RPC or native allocations.
[[nodiscard]] nlohmann::json collect_persistence_inventory_pages(PersistenceSource source,
    const std::function<bool(nlohmann::json)>& consumer, PersistenceLimits limits = {},
    const std::function<bool()>& cancelled = {});
[[nodiscard]] const char* persistence_source_name(PersistenceSource source);
namespace detail {
[[nodiscard]] nlohmann::json persistence_registry_data(std::uint32_t type,
    std::span<const std::byte> bytes);
[[nodiscard]] nlohmann::json persistence_task_xml(std::string_view xml);
// Borrowed VARIANT, retained native type; no reference dereference or execution.
[[nodiscard]] nlohmann::json persistence_variant(const void* value, std::size_t byte_limit);
}
}
