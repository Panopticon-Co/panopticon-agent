#pragma once
#include <nlohmann/json.hpp>
#include <cstdint>
#include <functional>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_firewall_profile_state();
namespace detail {
enum class FirewallField { current_profiles, modify_state, enabled, block_inbound,
    notifications_disabled, unicast_responses_disabled, default_inbound, default_outbound };
struct FirewallQueryResult {
    std::uint32_t hresult = 0;
    std::int32_t output = 0;
    std::uint64_t started_uptime_ms = 0, completed_uptime_ms = 0;
};
using FirewallQuery = std::function<FirewallQueryResult(FirewallField, std::uint32_t profile)>;
using FirewallExclusionQuery = std::function<nlohmann::json(std::uint32_t profile)>;
// Borrowed trusted COM VARIANT; never takes ownership or dereferences BYREF data.
[[nodiscard]] nlohmann::json decode_firewall_exclusions(const void* variant);
[[nodiscard]] nlohmann::json collect_firewall_profile_state(const FirewallQuery& query,
    const FirewallExclusionQuery& exclusions = {});
}
}
