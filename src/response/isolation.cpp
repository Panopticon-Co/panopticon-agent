#include "panopticon/officer/response/isolation.hpp"
#include "panopticon/officer/core/entity_id.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>

#include <array>
#include <cstring>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

namespace panopticon::officer::response {

namespace {

// Derives a deterministic GUID from a fixed name so isolate()/release() are
// idempotent and always agree on which WFP objects belong to this agent --
// no state file is needed to remember "which GUID did I use last time."
// This is a name-based derivation (akin in spirit to a v5 UUID), not a
// security boundary; collision resistance of SHA-256 is more than
// sufficient for a namespace of ~5 fixed names.
GUID deterministic_guid(const std::string& name) {
    std::string error_message;
    const auto digest = core::sha256_hex("panopticon-officer-isolation-v1:" + name, error_message);
    std::array<unsigned char, 16> bytes{};
    if (digest && digest->size() >= 32U) {
        for (std::size_t index = 0; index < 16U; ++index) {
            const auto byte_hex = digest->substr(index * 2U, 2U);
            bytes[index] = static_cast<unsigned char>(std::strtoul(byte_hex.c_str(), nullptr, 16));
        }
    }
    GUID guid{};
    std::memcpy(&guid.Data1, bytes.data(), 4);
    std::memcpy(&guid.Data2, bytes.data() + 4, 2);
    std::memcpy(&guid.Data3, bytes.data() + 6, 2);
    std::memcpy(&guid.Data4, bytes.data() + 8, 8);
    return guid;
}

class WfpEngine {
public:
    WfpEngine() {
        FWPM_SESSION0 session{};
        session.flags = 0;  // Non-dynamic: filters persist across this process's lifetime by design --
                              // isolation must survive this agent process restarting while isolated.
        handle_result_ = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_);
    }
    ~WfpEngine() {
        if (engine_ != nullptr) FwpmEngineClose0(engine_);
    }
    WfpEngine(const WfpEngine&) = delete;
    WfpEngine& operator=(const WfpEngine&) = delete;
    [[nodiscard]] bool ok() const { return handle_result_ == ERROR_SUCCESS && engine_ != nullptr; }
    [[nodiscard]] HANDLE get() const { return engine_; }

private:
    HANDLE engine_ = nullptr;
    DWORD handle_result_ = ERROR_SUCCESS;
};

bool ensure_sublayer(HANDLE engine, const GUID& sublayer_key, const std::wstring& name, std::string& error_message) {
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData.name = const_cast<wchar_t*>(name.c_str());
    sublayer.weight = 0x8000;
    const auto result = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        error_message = "FwpmSubLayerAdd0 failed";
        return false;
    }
    return true;
}

// Adds one filter blocking all traffic at the given ALE layer, plus (only
// when manager_exception.manager_host is non-empty) a higher-weight permit
// filter scoped to that single remote address -- the sole exception to the
// default-deny set, never a general ESTABLISHED/RELATED or SSH/RDP
// carve-out.
bool add_block_and_exception(HANDLE engine, const GUID& sublayer_key, const GUID& block_filter_key,
                              const GUID& permit_filter_key, const GUID& layer_key, bool outbound,
                              const IsolationExceptionEndpoint& manager_exception, const std::wstring& block_name,
                              const std::wstring& permit_name, std::string& error_message) {
    FWPM_FILTER0 block{};
    block.filterKey = block_filter_key;
    block.displayData.name = const_cast<wchar_t*>(block_name.c_str());
    block.layerKey = layer_key;
    block.subLayerKey = sublayer_key;
    block.weight.type = FWP_UINT8;
    block.weight.uint8 = 0;
    block.action.type = FWP_ACTION_BLOCK;
    block.numFilterConditions = 0;
    const auto block_result = FwpmFilterAdd0(engine, &block, nullptr, nullptr);
    if (block_result != ERROR_SUCCESS && block_result != FWP_E_ALREADY_EXISTS) {
        error_message = "FwpmFilterAdd0 (block) failed";
        return false;
    }

    if (manager_exception.manager_host.empty()) return true;

    ADDRINFOA hints{};
    hints.ai_family = AF_UNSPEC;
    ADDRINFOA* resolved = nullptr;
    if (getaddrinfo(manager_exception.manager_host.c_str(), nullptr, &hints, &resolved) != 0 || resolved == nullptr) {
        error_message = "cannot resolve manager exception address for isolation filter";
        return false;
    }
    FWP_V4_ADDR_AND_MASK v4{};
    FWP_V6_ADDR_AND_MASK v6{};
    bool is_v4 = false;
    if (resolved->ai_family == AF_INET) {
        is_v4 = true;
        const auto* address = reinterpret_cast<sockaddr_in*>(resolved->ai_addr);
        v4.addr = ntohl(address->sin_addr.S_un.S_addr);
        v4.mask = 0xFFFFFFFFU;
    } else if (resolved->ai_family == AF_INET6) {
        const auto* address = reinterpret_cast<sockaddr_in6*>(resolved->ai_addr);
        std::memcpy(v6.addr, &address->sin6_addr, 16);
        v6.prefixLength = 128;
    }
    freeaddrinfo(resolved);

    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey = outbound ? FWPM_CONDITION_IP_REMOTE_ADDRESS : FWPM_CONDITION_IP_LOCAL_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    if (is_v4) {
        condition.conditionValue.type = FWP_V4_ADDR_MASK;
        condition.conditionValue.v4AddrMask = &v4;
    } else {
        condition.conditionValue.type = FWP_V6_ADDR_MASK;
        condition.conditionValue.v6AddrMask = &v6;
    }

    FWPM_FILTER0 permit{};
    permit.filterKey = permit_filter_key;
    permit.displayData.name = const_cast<wchar_t*>(permit_name.c_str());
    permit.layerKey = layer_key;
    permit.subLayerKey = sublayer_key;
    permit.weight.type = FWP_UINT8;
    permit.weight.uint8 = 15;  // Higher than the block filter's weight 0 -> evaluated first.
    permit.action.type = FWP_ACTION_PERMIT;
    permit.numFilterConditions = 1;
    permit.filterCondition = &condition;
    const auto permit_result = FwpmFilterAdd0(engine, &permit, nullptr, nullptr);
    if (permit_result != ERROR_SUCCESS && permit_result != FWP_E_ALREADY_EXISTS) {
        error_message = "FwpmFilterAdd0 (permit-manager-exception) failed";
        return false;
    }
    return true;
}

}  // namespace

IsolationPlan build_isolation_plan(const IsolationExceptionEndpoint& manager_exception) {
    return IsolationPlan{
        "panopticon-officer-isolation-sublayer",
        "panopticon-officer-block-outbound",
        "panopticon-officer-block-inbound",
        "panopticon-officer-permit-manager-outbound",
        "panopticon-officer-permit-manager-inbound",
        manager_exception,
    };
}

std::optional<bool> apply_isolation(const IsolationPlan& plan, std::string& error_message) {
    WfpEngine engine;
    if (!engine.ok()) {
        error_message = "FwpmEngineOpen0 failed (requires an elevated process)";
        return std::nullopt;
    }
    const auto sublayer_key = deterministic_guid(plan.sublayer_name);
    if (!ensure_sublayer(engine.get(), sublayer_key, L"Panopticon Officer host isolation", error_message)) {
        return std::nullopt;
    }
    const auto block_out = deterministic_guid(plan.block_outbound_filter_name);
    const auto permit_out = deterministic_guid(plan.permit_manager_outbound_filter_name);
    const auto block_in = deterministic_guid(plan.block_inbound_filter_name);
    const auto permit_in = deterministic_guid(plan.permit_manager_inbound_filter_name);

    if (!add_block_and_exception(engine.get(), sublayer_key, block_out, permit_out, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                  true, plan.manager_exception, L"panopticon-officer-block-outbound-v4",
                                  L"panopticon-officer-permit-manager-outbound-v4", error_message)) {
        return std::nullopt;
    }
    if (!add_block_and_exception(engine.get(), sublayer_key, block_in, permit_in, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                  false, plan.manager_exception, L"panopticon-officer-block-inbound-v4",
                                  L"panopticon-officer-permit-manager-inbound-v4", error_message)) {
        return std::nullopt;
    }
    return true;
}

std::optional<bool> release_isolation(const IsolationPlan& plan, std::string& error_message) {
    WfpEngine engine;
    if (!engine.ok()) {
        error_message = "FwpmEngineOpen0 failed (requires an elevated process)";
        return std::nullopt;
    }
    const std::array<GUID, 4> filter_keys{
        deterministic_guid(plan.block_outbound_filter_name),
        deterministic_guid(plan.permit_manager_outbound_filter_name),
        deterministic_guid(plan.block_inbound_filter_name),
        deterministic_guid(plan.permit_manager_inbound_filter_name),
    };
    bool all_ok = true;
    for (const auto& key : filter_keys) {
        const auto result = FwpmFilterDeleteByKey0(engine.get(), &key);
        if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) all_ok = false;
    }
    const auto sublayer_key = deterministic_guid(plan.sublayer_name);
    const auto sublayer_result = FwpmSubLayerDeleteByKey0(engine.get(), &sublayer_key);
    if (sublayer_result != ERROR_SUCCESS && sublayer_result != FWP_E_SUBLAYER_NOT_FOUND) all_ok = false;
    if (!all_ok) {
        error_message = "one or more isolation WFP objects could not be removed";
        return std::nullopt;
    }
    return true;
}

}  // namespace panopticon::officer::response
