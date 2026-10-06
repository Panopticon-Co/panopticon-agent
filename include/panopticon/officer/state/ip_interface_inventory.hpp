#pragma once
#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_ip_interface_inventory_pages(const std::function<bool(nlohmann::json)>& consumer);
namespace detail {
struct IpInterfaceTableResult {
    std::uint32_t error = 0;
    bool native_success_without_table = false;
    std::uint32_t reported_rows = 0;
    std::vector<std::byte> rows;
};
[[nodiscard]] nlohmann::json collect_ip_interface_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    const std::function<IpInterfaceTableResult(bool ipv6)>& query);
}
}
