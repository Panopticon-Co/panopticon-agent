#pragma once
#include <cstdint>
#include <functional>
#include <nlohmann/json.hpp>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_security_center_state();
namespace detail {
struct SecurityHealthResult {
    std::uint32_t hresult = 0;
    std::int32_t output = -1;
    std::uint64_t started_uptime_ms = 0, completed_uptime_ms = 0;
};
using SecurityHealthQuery = std::function<SecurityHealthResult(std::uint32_t)>;
struct SecurityPlatformResult {
    bool attempted = false;
    std::uint32_t ntstatus = 0, resolver_error = 0;
    std::uint32_t major = 0, minor = 0, build = 0, product_type = 0;
    std::uint64_t started_uptime_ms = 0, completed_uptime_ms = 0;
};
[[nodiscard]] nlohmann::json security_center_platform(const SecurityPlatformResult& result);
[[nodiscard]] nlohmann::json collect_security_center_state(
    const SecurityHealthQuery& query, nlohmann::json availability = nlohmann::json::object(),
    nlohmann::json platform = nlohmann::json::object());
}
}
