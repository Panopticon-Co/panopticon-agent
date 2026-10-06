#pragma once
#include <cstdint>
#include <cstddef>
#include <nlohmann/json.hpp>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_defender_status();
namespace detail {
// Borrows a trusted local WMI VARIANT. Does not dereference BYREF or coerce types.
[[nodiscard]] nlohmann::json decode_defender_property(const void* value,
    std::uint32_t expected_cim_type, std::uint32_t reported_cim_type, std::size_t& copied_text_bytes);
[[nodiscard]] nlohmann::json decode_defender_query_result(const char* property, bool modern_optional,
    std::uint32_t hresult, const void* value, std::uint32_t expected_cim_type,
    std::uint32_t reported_cim_type, std::size_t& copied_text_bytes);
[[nodiscard]] nlohmann::json defender_modern_property_quality(const nlohmann::json& captured_entries);
}
}
