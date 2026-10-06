#pragma once
#include <nlohmann/json.hpp>
#include <cstdint>
#include <span>

namespace panopticon::officer::state {
// Read-only, non-atomic snapshot. Each query names its source and uncertainty;
// unavailable/not-yet-implemented facts are never converted to false or empty.
[[nodiscard]] nlohmann::json collect_host_inventory();
namespace detail {
[[nodiscard]] nlohmann::json system_audit_flags(std::uint32_t flags);
[[nodiscard]] nlohmann::json volume_mount_paths(std::span<const wchar_t> characters);
// Classifies documented native query results, independently of live machine state.
[[nodiscard]] nlohmann::json tpm_device_result(std::uint32_t status, std::uint32_t structure_version = 0,
    std::uint32_t tpm_version = 0, std::uint32_t reserved_interface_type = 0,
    std::uint32_t reserved_implementation_revision = 0);
[[nodiscard]] nlohmann::json entra_join_result(std::uint32_t status, bool information_present,
    std::uint32_t join_type, nlohmann::json attributes, bool text_bound_exceeded = false);
}
}
