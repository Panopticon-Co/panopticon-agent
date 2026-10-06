#pragma once
#include <nlohmann/json.hpp>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::officer::health {

enum class CapabilityState { healthy, degraded, unavailable, disabled, unsupported, blind };
[[nodiscard]] std::string_view state_name(CapabilityState state);
struct Capability {
    std::string id;
    CapabilityState state;
    std::string reason;
    std::string scope;
    std::string updated_at;
    std::uint64_t failure_count = 0;
};

// Registry covers the declared security surface, including missing features.
// Collector running() alone is never evidence of complete domain coverage.
class CoverageRegistry {
public:
    CoverageRegistry();
    void set(std::string id, CapabilityState state, std::string reason, std::string scope, bool failure = false);
    [[nodiscard]] nlohmann::json snapshot(const std::string& agent_id, const std::string& host_id) const;
private:
    mutable std::mutex mutex_;
    std::vector<Capability> capabilities_;
};
}  // namespace panopticon::officer::health
