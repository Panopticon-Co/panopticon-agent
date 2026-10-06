#pragma once
#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_route_inventory_pages(const std::function<bool(nlohmann::json)>& consumer);
namespace detail {
// Copied rows have SDK sizeof(MIB_IPFORWARD_ROW2) stride; no native pointers escape.
struct RouteTableResult {
    std::uint32_t error = 0;
    bool native_success_without_table = false;
    std::uint32_t reported_rows = 0;
    std::vector<std::byte> rows;
};
[[nodiscard]] nlohmann::json decode_route_row(std::span<const std::byte> row);
[[nodiscard]] nlohmann::json collect_route_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    const std::function<RouteTableResult(bool ipv6)>& query,
    const std::function<nlohmann::json(bool, std::uint64_t, std::uint32_t)>& interface_query = {});
}
}
