#pragma once
#include <cstdint>
#include <cstddef>
#include <nlohmann/json.hpp>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_device_guard_state();
namespace detail {
// Trusted local provider VARIANT only; BYREF and coercion are prohibited.
[[nodiscard]] nlohmann::json decode_device_guard_property(std::uint32_t hresult,
    const void* value, std::uint32_t expected_type, std::uint32_t reported_type, std::size_t& copied);
}
}
