#pragma once
#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json query_ip_interface(bool ipv6, std::uint64_t luid, std::uint32_t index);
namespace detail {
[[nodiscard]] nlohmann::json decode_ip_interface(std::span<const std::byte> row);
}
}
