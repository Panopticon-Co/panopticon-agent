#pragma once
#include <nlohmann/json.hpp>
#include <functional>
#include <span>
#include <cstddef>
#include <cstdint>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_socket_inventory_pages(const std::function<bool(nlohmann::json)>& consumer);
namespace detail {
using SocketTableQuery = std::function<std::uint32_t(std::span<std::byte>, std::uint32_t&, bool, bool)>;
[[nodiscard]] nlohmann::json collect_socket_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer, const SocketTableQuery& query);
// Decode one successful native owner-PID table with bounded row access.
[[nodiscard]] nlohmann::json decode_socket_table(std::span<const std::byte> buffer, bool tcp, bool ipv6,
    const std::function<bool(nlohmann::json)>& consumer);
}
}
