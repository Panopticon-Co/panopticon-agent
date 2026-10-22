#pragma once
#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <cstddef>
#include <functional>

namespace panopticon::officer::state {
using DefenderPreferencesLimits = NativeInventoryLimits;
// Read-only snapshot of caller-visible MSFT_MpPreference values. Pages are
// delivered to consumer; returned JSON is a manifest and never asserts enforcement.
[[nodiscard]] nlohmann::json collect_defender_preferences_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    DefenderPreferencesLimits limits = {}, const std::function<bool()>& cancelled = {});
namespace detail {
// Borrowed VARIANT decoder used by the native collector; preserves VARIANT type
// and raw carriers, including arrays, within application copy bounds.
[[nodiscard]] nlohmann::json decode_defender_preference_variant(
    const void* borrowed_variant, std::size_t byte_limit);
}
}
