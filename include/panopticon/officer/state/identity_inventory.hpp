#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <functional>
#include <span>
namespace panopticon::officer::state {
enum class IdentitySource { accounts, groups, logons, terminal_sessions };
[[nodiscard]] const char* identity_source_name(IdentitySource source);
[[nodiscard]] nlohmann::json collect_identity_inventory_pages(IdentitySource source,
    const std::function<bool(nlohmann::json)>& consumer, NativeInventoryLimits limits = {},
    const std::function<bool()>& cancelled = {});
namespace detail {
[[nodiscard]] nlohmann::json identity_buffer_text(std::span<const std::byte> buffer,
    const void* pointer, std::size_t unit_limit = 4096);
[[nodiscard]] nlohmann::json identity_buffer_sid(std::span<const std::byte> buffer, const void* pointer);
[[nodiscard]] nlohmann::json identity_counted_text(const void* borrowed_unicode_string, std::size_t byte_limit);
[[nodiscard]] nlohmann::json identity_wts_field(std::uint32_t information_class, std::span<const std::byte> buffer);
}
}
