#pragma once
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <cstddef>
#include <functional>
#include <cstdint>
namespace panopticon::officer::state {
struct ProcessInventoryLimits { std::size_t entries = 2048, encoded_bytes = 512 * 1024; };
// Toolhelp descriptors and later PID queries remain separate. Same PID does not
// prove the held instance is the instance originally enumerated by Toolhelp.
[[nodiscard]] nlohmann::json collect_process_inventory(const std::string& host_id,
    const std::optional<std::string>& boot_id, ProcessInventoryLimits limits = {});
// One pinned Toolhelp snapshot; one bounded page at a time. False consumer return
// aborts without claiming full enumeration. Caller owns durable acceptance/retry.
[[nodiscard]] nlohmann::json collect_process_inventory_pages(const std::string& host_id,
    const std::optional<std::string>& boot_id,
    const std::function<bool(nlohmann::json)>& consumer, ProcessInventoryLimits page_limits = {},
    std::size_t total_entry_limit = 65536, std::size_t page_limit = 4096);
namespace detail {
// Interpret only documented level symbols; unknown/reserved results remain raw.
[[nodiscard]] nlohmann::json process_protection_result(std::uint32_t level);
[[nodiscard]] nlohmann::json process_machine_result(std::uint16_t process_machine, std::uint16_t native_machine);
}
}
