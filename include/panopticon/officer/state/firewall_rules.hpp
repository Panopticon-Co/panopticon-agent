#pragma once
#include <nlohmann/json.hpp>
#include <functional>
struct INetFwRule;
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_firewall_rule_pages(const std::function<bool(nlohmann::json)>& consumer);
namespace detail {
// Borrows an already-held rule; never registers or changes firewall policy.
using FirewallExtensionQuery = std::function<long(const char*, void**)>;
[[nodiscard]] nlohmann::json query_firewall_rule_fields(
    INetFwRule* rule, const FirewallExtensionQuery& query = {});
using FirewallRuleEnumerator = std::function<nlohmann::json(const std::function<bool(nlohmann::json)>&)>;
[[nodiscard]] nlohmann::json collect_firewall_rule_pages(
    const std::function<bool(nlohmann::json)>& consumer, const FirewallRuleEnumerator& enumerate);
}
}
