#include "panopticon/officer/health/coverage.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace panopticon::officer::health {
namespace {
std::string timestamp() {
    return pipeline::format_utc_timestamp(std::chrono::time_point_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now()));
}
}
std::string_view state_name(CapabilityState state) {
    switch (state) {
        case CapabilityState::healthy: return "healthy";
        case CapabilityState::degraded: return "degraded";
        case CapabilityState::unavailable: return "unavailable";
        case CapabilityState::disabled: return "disabled";
        case CapabilityState::unsupported: return "unsupported";
        case CapabilityState::blind: return "blind";
    }
    throw std::invalid_argument("unknown capability state");
}
CoverageRegistry::CoverageRegistry() {
    const auto now = timestamp();
    for (const auto* id : {"A.host", "B.process", "C.thread_handle", "D.user_session", "E.authentication",
             "F.powershell", "G.scripting_lolbin", "H.filesystem", "I.registry", "J.persistence",
             "K.service_driver", "L.scheduled_task", "M.wmi", "N.network", "O.dns", "P.firewall",
             "Q.security_product", "R.memory_injection", "S.browser", "T.office", "U.remote_access",
             "V.ipc", "W.enterprise_identity", "X.virtualization", "Y.posture", "Z.software",
             "AA.windows_logs", "AB.forensics", "AC.response", "AD.isolation", "AE.self_protection",
             "AF.loss", "AG.durability", "AH.transport", "AI.configuration", "AJ.update",
             "AK.performance", "AL.compatibility", "AM.validation", "AN.detection_context"})
        capabilities_.push_back({id, CapabilityState::unavailable, "full-domain implementation or qualification pending", "approved full-surface domain", now});
    set("A.host", CapabilityState::degraded, "boot/device/install identity and host-state inventory pending", "hostname and OS name/build");
    set("AC.response", CapabilityState::disabled, "response requires explicit configuration and enrolled identity", "typed actions; full response qualification pending");
    set("AD.isolation", CapabilityState::disabled, "response configuration required; IPv6 and recovery qualification pending", "existing IPv4 WFP actions");
    set("AE.self_protection", CapabilityState::degraded, "service split, tamper monitoring, driver/PPL qualification pending", "journal DACL and user-scoped DPAPI only");
    set("AF.loss", CapabilityState::degraded, "provider-loss counters, durable gap records and emergency reserve pending", "runtime failure counters and legacy migration gaps");
    set("AI.configuration", CapabilityState::degraded, "signed policy and controlled configuration lifecycle pending", "validated CLI options");
    set("AK.performance", CapabilityState::degraded, "approved workload budgets have not been qualified", "component test runtime only");
    set("AL.compatibility", CapabilityState::degraded, "OS/security configuration and ARM64 matrix not qualified", "current Windows x64 development host");
    set("AM.validation", CapabilityState::degraded, "VM, attack simulation, stress, chaos and soak qualification pending", "component/contract tests");
}
void CoverageRegistry::set(std::string id, CapabilityState state, std::string reason, std::string scope, bool failure) {
    if (id.empty() || id.size() > 128 || reason.size() > 2048 || scope.size() > 2048)
        throw std::invalid_argument("capability metadata exceeds bounds");
    std::scoped_lock lock{mutex_};
    const auto found = std::find_if(capabilities_.begin(), capabilities_.end(), [&](const auto& capability) { return capability.id == id; });
    if (found == capabilities_.end()) capabilities_.push_back({std::move(id), state, std::move(reason), std::move(scope), timestamp(), failure ? 1u : 0u});
    else {
        found->state = state;
        found->reason = std::move(reason);
        found->scope = std::move(scope);
        found->updated_at = timestamp();
        if (failure) ++found->failure_count;
    }
}
nlohmann::json CoverageRegistry::snapshot(const std::string& agent_id, const std::string& host_id) const {
    std::scoped_lock lock{mutex_};
    auto list = nlohmann::json::array();
    for (const auto& capability : capabilities_)
        list.push_back({{"id", capability.id}, {"state", state_name(capability.state)}, {"reason", capability.reason},
            {"scope", capability.scope}, {"updated_at", capability.updated_at}, {"failure_count", capability.failure_count}});
    return {{"schema_version", "1.0"}, {"kind", "endpoint_health"}, {"agent_id", agent_id}, {"host_id", host_id},
        {"observed_at", timestamp()}, {"capabilities", std::move(list)}};
}
}  // namespace panopticon::officer::health
