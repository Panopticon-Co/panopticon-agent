#include "panopticon/officer/response/isolation.hpp"
#include "panopticon/officer/core/entity_id.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>

#include <array>
#include <cwchar>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

namespace panopticon::officer::response {
namespace {

GUID deterministic_guid(const std::string& name, const char* version = "v2") {
    std::string error_message;
    const auto digest = core::sha256_hex(std::string("panopticon-officer-isolation-") + version + ":" + name, error_message);
    std::array<unsigned char, 16> bytes{};
    if (!digest || digest->size() < 32U) throw std::runtime_error("cannot derive deterministic WFP isolation key: " + error_message);
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<unsigned char>(std::strtoul(digest->substr(i * 2U, 2U).c_str(), nullptr, 16));
    GUID guid{};
    std::memcpy(&guid.Data1, bytes.data(), 4); std::memcpy(&guid.Data2, bytes.data() + 4, 2);
    std::memcpy(&guid.Data3, bytes.data() + 6, 2); std::memcpy(guid.Data4, bytes.data() + 8, 8);
    return guid;
}

class WfpEngine {
public:
    WfpEngine() {
        FWPM_SESSION0 session{};
        handle_result_ = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_);
    }
    ~WfpEngine() { if (engine_) FwpmEngineClose0(engine_); }
    WfpEngine(const WfpEngine&) = delete;
    WfpEngine& operator=(const WfpEngine&) = delete;
    [[nodiscard]] bool ok() const noexcept { return handle_result_ == ERROR_SUCCESS && engine_; }
    [[nodiscard]] HANDLE get() const noexcept { return engine_; }
private:
    HANDLE engine_ = nullptr;
    DWORD handle_result_ = ERROR_SUCCESS;
};

class WfpTransaction {
public:
    explicit WfpTransaction(HANDLE engine) : engine_(engine), active_(FwpmTransactionBegin0(engine, 0) == ERROR_SUCCESS) {}
    ~WfpTransaction() { if (active_) FwpmTransactionAbort0(engine_); }
    [[nodiscard]] bool active() const noexcept { return active_; }
    bool commit(std::string& error) {
        const auto status = FwpmTransactionCommit0(engine_);
        if (status != ERROR_SUCCESS) { error = "WFP transaction commit failed: " + std::to_string(status); return false; }
        active_ = false; return true;
    }
private:
    HANDLE engine_;
    bool active_;
};

bool ensure_sublayer(HANDLE engine, const GUID& key, std::string& error) {
    FWPM_SUBLAYER0 sublayer{}; sublayer.subLayerKey = key; sublayer.weight = 0x8000;
    const wchar_t name[] = L"Panopticon Officer host isolation";
    sublayer.displayData.name = const_cast<wchar_t*>(name);
    const auto status = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (status == FWP_E_ALREADY_EXISTS) {
        FWPM_SUBLAYER0* existing = nullptr;
        const auto query = FwpmSubLayerGetByKey0(engine, &key, &existing);
        const bool expected = query == ERROR_SUCCESS && existing && existing->displayData.name &&
            wcscmp(existing->displayData.name, name) == 0 && existing->weight == sublayer.weight;
        if (existing) FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
        if (!expected) {
            error = "isolation sublayer key collides with an unexpected WFP sublayer";
            return false;
        }
        return true;
    }
    if (status != ERROR_SUCCESS) {
        error = "FwpmSubLayerAdd0 failed: " + std::to_string(status); return false;
    }
    return true;
}

bool find_filter(HANDLE engine, const GUID& key, FWPM_FILTER0*& filter, bool& exists, std::string& error) {
    filter = nullptr;
    exists = false;
    const auto status = FwpmFilterGetByKey0(engine, &key, &filter);
    if (status == FWP_E_FILTER_NOT_FOUND) return true;
    if (status != ERROR_SUCCESS || !filter) {
        error = "cannot inspect isolation filter ownership: " + std::to_string(status);
        return false;
    }
    exists = true;
    return true;
}

bool delete_filter_if_owned(HANDLE engine, const GUID& key, const GUID& sublayer, std::string& error) {
    FWPM_FILTER0* existing = nullptr;
    bool found = false;
    if (!find_filter(engine, key, existing, found, error)) return false;
    if (!found) return true;
    const bool owned = IsEqualGUID(existing->subLayerKey, sublayer);
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    if (!owned) {
        error = "refusing to delete a filter key currently assigned to another WFP sublayer";
        return false;
    }
    const auto status = FwpmFilterDeleteByKey0(engine, &key);
    if (status != ERROR_SUCCESS && status != FWP_E_FILTER_NOT_FOUND) {
        error = "cannot delete owned isolation filter: " + std::to_string(status);
        return false;
    }
    return true;
}

bool delete_sublayer_if_owned(HANDLE engine, const GUID& key, std::string& error) {
    FWPM_SUBLAYER0* existing = nullptr;
    const auto query = FwpmSubLayerGetByKey0(engine, &key, &existing);
    if (query == FWP_E_SUBLAYER_NOT_FOUND) return true;
    if (query != ERROR_SUCCESS || !existing) {
        error = "cannot inspect isolation sublayer ownership: " + std::to_string(query);
        if (existing) FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
        return false;
    }
    const wchar_t expected_name[] = L"Panopticon Officer host isolation";
    const bool owned = existing->displayData.name && wcscmp(existing->displayData.name, expected_name) == 0 &&
        existing->weight == 0x8000;
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    if (!owned) {
        error = "refusing to delete a sublayer key with unexpected identity";
        return false;
    }
    const auto status = FwpmSubLayerDeleteByKey0(engine, &key);
    if (status != ERROR_SUCCESS && status != FWP_E_SUBLAYER_NOT_FOUND) {
        error = "cannot delete owned isolation sublayer: " + std::to_string(status);
        return false;
    }
    return true;
}

bool add_block(HANDLE engine, const GUID& sublayer, const GUID& key, const GUID& layer,
               const wchar_t* name, std::string& error) {
    FWPM_FILTER0 filter{}; filter.filterKey = key; filter.displayData.name = const_cast<wchar_t*>(name);
    filter.layerKey = layer; filter.subLayerKey = sublayer; filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0; filter.action.type = FWP_ACTION_BLOCK;
    const auto status = FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
    if (status == FWP_E_ALREADY_EXISTS) {
        error = "isolation filter key already exists after owned-key reconciliation; refusing false-success block";
        return false;
    }
    if (status != ERROR_SUCCESS) {
        error = "FwpmFilterAdd0 block failed: " + std::to_string(status); return false;
    }
    return true;
}

struct ManagerAddress { bool ipv4 = false; FWP_V4_ADDR_AND_MASK v4{}; FWP_V6_ADDR_AND_MASK v6{}; };

bool parse_numeric_manager(const IsolationExceptionEndpoint& endpoint, ManagerAddress& address, std::string& error) {
    if (endpoint.manager_host.empty()) return true;
    if (endpoint.manager_port == 0) { error = "manager exception requires a nonzero port"; return false; }
    ADDRINFOA hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST;
    ADDRINFOA* resolved = nullptr;
    const auto status = getaddrinfo(endpoint.manager_host.c_str(), nullptr, &hints, &resolved);
    if (status != 0 || !resolved) { error = "manager isolation exception must be one numeric IPv4 or IPv6 address"; return false; }
    if (resolved->ai_family == AF_INET && resolved->ai_addrlen >= sizeof(sockaddr_in)) {
        const auto* sa = reinterpret_cast<const sockaddr_in*>(resolved->ai_addr);
        const auto host_order = ntohl(sa->sin_addr.s_addr);
        if (host_order == INADDR_ANY || host_order == INADDR_BROADCAST || IN_MULTICAST(host_order)) {
            freeaddrinfo(resolved); error = "manager exception address must be a specific unicast IPv4 address"; return false;
        }
        address.ipv4 = true; address.v4.addr = host_order; address.v4.mask = 0xFFFFFFFFU;
    } else if (resolved->ai_family == AF_INET6 && resolved->ai_addrlen >= sizeof(sockaddr_in6)) {
        const auto* sa = reinterpret_cast<const sockaddr_in6*>(resolved->ai_addr);
        if (IN6_IS_ADDR_UNSPECIFIED(&sa->sin6_addr) || IN6_IS_ADDR_MULTICAST(&sa->sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&sa->sin6_addr)) {
            freeaddrinfo(resolved); error = "manager exception address must be unscoped IPv6 unicast"; return false;
        }
        std::memcpy(address.v6.addr, &sa->sin6_addr, sizeof(address.v6.addr)); address.v6.prefixLength = 128;
    } else {
        freeaddrinfo(resolved); error = "unsupported manager exception address family"; return false;
    }
    freeaddrinfo(resolved); return true;
}

bool add_manager_permit(HANDLE engine, const GUID& sublayer, const GUID& key, const GUID& layer,
                        const ManagerAddress& manager, bool ipv4, std::uint16_t port, std::string& error) {
    FWPM_FILTER_CONDITION0 conditions[3]{};
    conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    if (ipv4) { conditions[0].conditionValue.type = FWP_V4_ADDR_MASK; conditions[0].conditionValue.v4AddrMask = const_cast<FWP_V4_ADDR_AND_MASK*>(&manager.v4); }
    else { conditions[0].conditionValue.type = FWP_V6_ADDR_MASK; conditions[0].conditionValue.v6AddrMask = const_cast<FWP_V6_ADDR_AND_MASK*>(&manager.v6); }
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT; conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT16; conditions[1].conditionValue.uint16 = port;
    conditions[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL; conditions[2].matchType = FWP_MATCH_EQUAL;
    conditions[2].conditionValue.type = FWP_UINT8; conditions[2].conditionValue.uint8 = IPPROTO_TCP;
    FWPM_FILTER0 filter{}; filter.filterKey = key;
    const wchar_t name4[] = L"panopticon-officer-permit-manager-outbound-v4";
    const wchar_t name6[] = L"panopticon-officer-permit-manager-outbound-v6";
    filter.displayData.name = const_cast<wchar_t*>(ipv4 ? name4 : name6); filter.layerKey = layer;
    filter.subLayerKey = sublayer; filter.weight.type = FWP_UINT8; filter.weight.uint8 = 15;
    filter.action.type = FWP_ACTION_PERMIT; filter.numFilterConditions = 3; filter.filterCondition = conditions;
    const auto status = FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
    if (status == FWP_E_ALREADY_EXISTS) {
        error = "manager exception filter key already exists after owned-key reconciliation; refusing false-success permit";
        return false;
    }
    if (status != ERROR_SUCCESS) { error = "FwpmFilterAdd0 manager exception failed: " + std::to_string(status); return false; }
    return true;
}

std::array<GUID, 6> filter_keys(const IsolationPlan& plan) {
    return {deterministic_guid(plan.block_outbound_filter_name), deterministic_guid(plan.block_inbound_filter_name),
        deterministic_guid(plan.block_outbound_v6_filter_name), deterministic_guid(plan.block_inbound_v6_filter_name),
        deterministic_guid(plan.permit_manager_outbound_filter_name), deterministic_guid(plan.permit_manager_outbound_v6_filter_name)};
}
bool remove_legacy_filter_set(HANDLE engine, std::string& error) {
    const std::array<const char*, 5> names{"panopticon-officer-block-outbound", "panopticon-officer-block-inbound",
        "panopticon-officer-permit-manager-outbound", "panopticon-officer-permit-manager-inbound", "panopticon-officer-isolation-sublayer"};
    const auto sublayer = deterministic_guid(names[4], "v1");
    for (std::size_t i = 0; i < 4; ++i) {
        const auto key = deterministic_guid(names[i], "v1");
        if (!delete_filter_if_owned(engine, key, sublayer, error)) {
            error = "legacy WFP isolation filter migration refused: " + error;
            return false;
        }
    }
    return delete_sublayer_if_owned(engine, sublayer, error);
}
bool replace_filters(HANDLE engine, const IsolationPlan& plan, std::string& error) {
    // Replacement inside the same transaction makes an address/port policy
    // change atomic and prevents FWP_E_ALREADY_EXISTS from preserving stale
    // permit conditions across repeated isolation commands.
    const auto sublayer = deterministic_guid(plan.sublayer_name);
    for (const auto& key : filter_keys(plan)) if (!delete_filter_if_owned(engine, key, sublayer, error)) return false;
    return true;
}
}

IsolationPlan build_isolation_plan(const IsolationExceptionEndpoint& exception) {
    return {"panopticon-officer-isolation-sublayer", "panopticon-officer-block-outbound-v4",
        "panopticon-officer-block-inbound-v4", "panopticon-officer-block-outbound-v6",
        "panopticon-officer-block-inbound-v6", "panopticon-officer-permit-manager-outbound-v4",
        "panopticon-officer-permit-manager-outbound-v6", exception};
}

std::optional<bool> apply_isolation(const IsolationPlan& plan, std::string& error) {
    ManagerAddress manager{};
    if (!parse_numeric_manager(plan.manager_exception, manager, error)) return std::nullopt;
    WfpEngine engine; if (!engine.ok()) { error = "FwpmEngineOpen0 failed (requires an elevated process)"; return std::nullopt; }
    WfpTransaction transaction(engine.get());
    if (!transaction.active()) { error = "FwpmTransactionBegin0 failed"; return std::nullopt; }
    const auto sublayer = deterministic_guid(plan.sublayer_name);
    if (!ensure_sublayer(engine.get(), sublayer, error) || !replace_filters(engine.get(), plan, error)
        || !add_block(engine.get(), sublayer, deterministic_guid(plan.block_outbound_filter_name), FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"panopticon-officer-block-outbound-v4", error)
        || !add_block(engine.get(), sublayer, deterministic_guid(plan.block_inbound_filter_name), FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, L"panopticon-officer-block-inbound-v4", error)
        || !add_block(engine.get(), sublayer, deterministic_guid(plan.block_outbound_v6_filter_name), FWPM_LAYER_ALE_AUTH_CONNECT_V6, L"panopticon-officer-block-outbound-v6", error)
        || !add_block(engine.get(), sublayer, deterministic_guid(plan.block_inbound_v6_filter_name), FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, L"panopticon-officer-block-inbound-v6", error)) return std::nullopt;
    if (!plan.manager_exception.manager_host.empty()) {
        if (manager.ipv4 && !add_manager_permit(engine.get(), sublayer, deterministic_guid(plan.permit_manager_outbound_filter_name), FWPM_LAYER_ALE_AUTH_CONNECT_V4, manager, true, plan.manager_exception.manager_port, error)) return std::nullopt;
        if (!manager.ipv4 && !add_manager_permit(engine.get(), sublayer, deterministic_guid(plan.permit_manager_outbound_v6_filter_name), FWPM_LAYER_ALE_AUTH_CONNECT_V6, manager, false, plan.manager_exception.manager_port, error)) return std::nullopt;
    }
    if (!remove_legacy_filter_set(engine.get(), error) || !transaction.commit(error)) return std::nullopt;
    return true;
}

std::optional<bool> release_isolation(const IsolationPlan& plan, std::string& error) {
    WfpEngine engine; if (!engine.ok()) { error = "FwpmEngineOpen0 failed (requires an elevated process)"; return std::nullopt; }
    WfpTransaction transaction(engine.get());
    if (!transaction.active()) { error = "FwpmTransactionBegin0 failed"; return std::nullopt; }
    bool all_ok = true;
    const auto sublayer = deterministic_guid(plan.sublayer_name);
    for (const auto& key : filter_keys(plan)) if (!delete_filter_if_owned(engine.get(), key, sublayer, error)) all_ok = false;
    if (!delete_sublayer_if_owned(engine.get(), sublayer, error)) all_ok = false;
    if (!remove_legacy_filter_set(engine.get(), error)) return std::nullopt;
    if (!all_ok) { error = "one or more isolation WFP objects could not be removed"; return std::nullopt; }
    if (!transaction.commit(error)) return std::nullopt;
    return true;
}
}  // namespace panopticon::officer::response
