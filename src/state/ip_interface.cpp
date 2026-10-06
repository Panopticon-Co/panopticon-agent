#include "panopticon/officer/state/ip_interface.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cstring>
#include <string>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
Json boolean(UCHAR raw) { return {{"reported_raw_byte", std::to_string(raw)}, {"value", raw <= 1 ? Json(raw == 1) : Json(nullptr)}}; }
Json behavior(std::uint32_t raw, bool discovery) {
    const char* symbol = nullptr;
    if (raw == 0) symbol = discovery ? "Disabled" : "AlwaysOff";
    if (raw == 1) symbol = discovery ? "Enabled" : "Delayed";
    if (raw == 2) symbol = discovery ? "Dhcp" : "AlwaysOn";
    if (raw == 4294967295u) symbol = "Unchanged";
    return {{"reported_raw_dword", std::to_string(raw)}, {"symbol", symbol ? Json(symbol) : Json(nullptr)},
        {"current_behavior_interpreted", raw <= 2}};
}
Json offload(const NL_INTERFACE_OFFLOAD_ROD& raw) {
    return {{"nl_checksum_supported", raw.NlChecksumSupported != 0}, {"nl_options_supported", raw.NlOptionsSupported != 0},
        {"tl_datagram_checksum_supported", raw.TlDatagramChecksumSupported != 0}, {"tl_stream_checksum_supported", raw.TlStreamChecksumSupported != 0},
        {"tl_stream_options_supported", raw.TlStreamOptionsSupported != 0}, {"fast_path_compatible", raw.FastPathCompatible != 0},
        {"tl_large_send_offload_supported", raw.TlLargeSendOffloadSupported != 0}, {"tl_giant_send_offload_supported", raw.TlGiantSendOffloadSupported != 0}};
}
}
Json detail::decode_ip_interface(std::span<const std::byte> bytes) {
    if (bytes.size() != sizeof(MIB_IPINTERFACE_ROW)) return {{"state", "unavailable"}, {"value", nullptr}, {"error_domain", "validation"}, {"error_code", "native_ip_interface_size_invalid"}};
    MIB_IPINTERFACE_ROW row{}; std::memcpy(&row, bytes.data(), sizeof(row));
    Json flags{{"advertising_enabled", boolean(row.AdvertisingEnabled)}, {"forwarding_enabled", boolean(row.ForwardingEnabled)},
        {"weak_host_send", boolean(row.WeakHostSend)}, {"weak_host_receive", boolean(row.WeakHostReceive)},
        {"use_automatic_metric", boolean(row.UseAutomaticMetric)}, {"use_neighbor_unreachability_detection", boolean(row.UseNeighborUnreachabilityDetection)},
        {"managed_address_configuration_supported", boolean(row.ManagedAddressConfigurationSupported)}, {"other_stateful_configuration_supported", boolean(row.OtherStatefulConfigurationSupported)},
        {"advertise_default_route", boolean(row.AdvertiseDefaultRoute)}, {"connected", boolean(row.Connected)},
        {"supports_wake_up_patterns", boolean(row.SupportsWakeUpPatterns)}, {"supports_neighbor_discovery", boolean(row.SupportsNeighborDiscovery)},
        {"supports_router_discovery", boolean(row.SupportsRouterDiscovery)}, {"disable_default_routes", boolean(row.DisableDefaultRoutes)}};
    bool known = row.Family == AF_INET || row.Family == AF_INET6;
    const bool site_prefix_valid = known && row.SitePrefixLength <= (row.Family == AF_INET ? 32u : 128u);
    known = known && site_prefix_valid;
    for (const auto& flag : flags) if (flag["value"].is_null()) known = false;
    const auto discovery = behavior(static_cast<std::uint32_t>(row.RouterDiscoveryBehavior), true);
    const auto link_local = behavior(static_cast<std::uint32_t>(row.LinkLocalAddressBehavior), false);
    known = known && discovery["current_behavior_interpreted"] == true && link_local["current_behavior_interpreted"] == true;
    Json zones = Json::array(); for (const auto zone : row.ZoneIndices) zones.push_back(std::to_string(zone));
    Json value{{"reported_address_family", std::to_string(row.Family)}, {"reported_interface_luid", std::to_string(row.InterfaceLuid.Value)},
        {"reported_interface_index", std::to_string(row.InterfaceIndex)}, {"interface_instance_reference", nullptr}, {"flags", std::move(flags)},
        {"reported_metric", std::to_string(row.Metric)}, {"reported_network_layer_mtu", std::to_string(row.NlMtu)},
        {"router_discovery_behavior", discovery}, {"link_local_address_behavior", link_local}, {"reported_zone_indices", std::move(zones)},
        {"reported_site_prefix_length", std::to_string(row.SitePrefixLength)}, {"site_prefix_valid", site_prefix_valid}, {"reported_dad_transmits", std::to_string(row.DadTransmits)},
        {"reported_base_reachable_time", std::to_string(row.BaseReachableTime)}, {"reported_retransmit_time", std::to_string(row.RetransmitTime)},
        {"reported_path_mtu_discovery_timeout", std::to_string(row.PathMtuDiscoveryTimeout)}, {"reported_link_local_address_timeout", std::to_string(row.LinkLocalAddressTimeout)},
        {"reported_reachable_time", std::to_string(row.ReachableTime)}, {"reported_min_router_advertisement_interval", std::to_string(row.MinRouterAdvertisementInterval)},
        {"reported_max_router_advertisement_interval", std::to_string(row.MaxRouterAdvertisementInterval)},
        {"reported_reserved_max_reassembly_size", std::to_string(row.MaxReassemblySize)}, {"reported_reserved_interface_identifier", std::to_string(row.InterfaceIdentifier)},
        {"transmit_offload", offload(row.TransmitOffload)}, {"receive_offload", offload(row.ReceiveOffload)},
        {"field_scope", "reported family-specific management fields; reserved values and applicability-dependent timers/prefixes retained without deriving configuration effects"}};
    return {{"state", known ? "healthy" : "degraded"}, {"value", std::move(value)},
        {"scope", "one later family/interface lookup; no persistent lifetime, full interface census, effective packet path or original padding bytes"}};
}
Json query_ip_interface(bool ipv6, std::uint64_t luid, std::uint32_t index) {
    const auto started = GetTickCount64();
    MIB_IPINTERFACE_ROW row{}; InitializeIpInterfaceEntry(&row);
    row.Family = ipv6 ? AF_INET6 : AF_INET; row.InterfaceLuid.Value = luid; row.InterfaceIndex = luid ? 0 : index;
    const auto error = GetIpInterfaceEntry(&row);
    auto result = error ? Json{{"state", error == ERROR_NOT_SUPPORTED ? "unsupported" : "unavailable"}, {"value", nullptr}, {"error_domain", "Win32"}, {"error_code", std::to_string(error)}}
        : detail::decode_ip_interface(std::as_bytes(std::span{&row, 1}));
    result["source"] = "GetIpInterfaceEntry"; result["native_query_succeeded"] = error == NO_ERROR;
    result["native_error_code"] = std::to_string(error); result["requested_address_family"] = ipv6 ? "ipv6" : "ipv4";
    result["requested_interface_luid"] = std::to_string(luid); result["requested_interface_index"] = std::to_string(luid ? 0 : index);
    result["lookup_selection"] = luid ? "nonzero LUID; index not used as alternate" : "zero LUID; index fallback";
    result["query_started_uptime_ms"] = std::to_string(started); result["query_completed_uptime_ms"] = std::to_string(GetTickCount64());
    if (!error) {
        const bool matches = row.Family == (ipv6 ? AF_INET6 : AF_INET) && (luid ? row.InterfaceLuid.Value == luid : row.InterfaceIndex == index);
        result["lookup_key_matches_returned_fields"] = matches;
        if (!matches) result["state"] = "degraded";
    }
    return result;
}
}
