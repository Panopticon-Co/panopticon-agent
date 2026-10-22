#include "panopticon/officer/collectors/network_state_change.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <array>
#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;

constexpr std::size_t max_row_bytes = (std::max)({sizeof(MIB_IPINTERFACE_ROW), sizeof(MIB_UNICASTIPADDRESS_ROW), sizeof(MIB_IPFORWARD_ROW2)});
constexpr std::size_t hard_snapshot_row_limit = 65536;

NetworkStateChangeLimits validated_limits(NetworkStateChangeLimits limits) {
    if (limits.callback_queue_capacity == 0 || limits.callback_queue_capacity > 65536 ||
        limits.snapshot_row_limit == 0 || limits.snapshot_row_limit > hard_snapshot_row_limit)
        throw std::invalid_argument("invalid network state change limits");
    return limits;
}

std::string utc_now() {
    FILETIME ft{};
    GetSystemTimePreciseAsFileTime(&ft);
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return {};
    std::ostringstream out;
    out << std::setfill('0') << std::setw(4) << st.wYear << '-' << std::setw(2) << st.wMonth
        << '-' << std::setw(2) << st.wDay << 'T' << std::setw(2) << st.wHour << ':'
        << std::setw(2) << st.wMinute << ':' << std::setw(2) << st.wSecond << '.'
        << std::setw(3) << st.wMilliseconds << 'Z';
    return out.str();
}

std::string utc_from_filetime(std::uint64_t ticks) {
    ULARGE_INTEGER value{};
    value.QuadPart = ticks;
    FILETIME ft{value.LowPart, value.HighPart};
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return {};
    std::ostringstream out;
    out << std::setfill('0') << std::setw(4) << st.wYear << '-' << std::setw(2) << st.wMonth
        << '-' << std::setw(2) << st.wDay << 'T' << std::setw(2) << st.wHour << ':'
        << std::setw(2) << st.wMinute << ':' << std::setw(2) << st.wSecond << '.'
        << std::setw(3) << st.wMilliseconds << 'Z';
    return out.str();
}

std::string address(const SOCKADDR_INET& addr) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (addr.si_family == AF_INET) {
        if (!InetNtopA(AF_INET, const_cast<IN_ADDR*>(&addr.Ipv4.sin_addr), buffer, sizeof(buffer))) return {};
        return buffer;
    }
    if (addr.si_family == AF_INET6) {
        if (!InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&addr.Ipv6.sin6_addr), buffer, sizeof(buffer))) return {};
        return buffer;
    }
    return {};
}

const char* notification_name(MIB_NOTIFICATION_TYPE type) {
    switch (type) {
    case MibInitialNotification: return "initial_notification";
    case MibAddInstance: return "add";
    case MibDeleteInstance: return "delete";
    case MibParameterNotification: return "parameter_change";
    default: return "unknown_notification";
    }
}

Json interface_row(const MIB_IPINTERFACE_ROW& row) {
    return {{"address_family", row.Family == AF_INET ? "ipv4" : row.Family == AF_INET6 ? "ipv6" : "unknown"},
        {"interface_luid", std::to_string(row.InterfaceLuid.Value)},
        {"interface_index", std::to_string(row.InterfaceIndex)},
        {"reported_mtu", std::to_string(row.NlMtu)},
        {"reported_metric", std::to_string(row.Metric)},
        {"reported_connection_type", std::to_string(static_cast<unsigned>(row.ConnectionType))},
        {"reported_interface_type", std::to_string(static_cast<unsigned>(row.Type))},
        {"record_scope", "native interface row; interface index and LUID are reported identifiers, not durable entity identity"}};
}

Json address_row(const MIB_UNICASTIPADDRESS_ROW& row) {
    return {{"address", address(row.Address)},
        {"address_family", row.Address.si_family == AF_INET ? "ipv4" : row.Address.si_family == AF_INET6 ? "ipv6" : "unknown"},
        {"reported_ipv6_scope_id", row.Address.si_family == AF_INET6 ? std::to_string(row.Address.Ipv6.sin6_scope_id) : "0"},
        {"interface_luid", std::to_string(row.InterfaceLuid.Value)},
        {"interface_index", std::to_string(row.InterfaceIndex)},
        {"reported_prefix_length", std::to_string(row.OnLinkPrefixLength)},
        {"reported_suffix_origin", std::to_string(static_cast<unsigned>(row.SuffixOrigin))},
        {"reported_prefix_origin", std::to_string(static_cast<unsigned>(row.PrefixOrigin))},
        {"reported_dad_state", std::to_string(static_cast<unsigned>(row.DadState))},
        {"record_scope", "native address row; notification rows may contain incomplete fields"}};
}

Json route_row(const MIB_IPFORWARD_ROW2& row) {
    return {{"address_family", row.DestinationPrefix.Prefix.si_family == AF_INET ? "ipv4" : row.DestinationPrefix.Prefix.si_family == AF_INET6 ? "ipv6" : "unknown"},
        {"destination", address(row.DestinationPrefix.Prefix)},
        {"reported_destination_prefix_length", std::to_string(row.DestinationPrefix.PrefixLength)},
        {"next_hop", address(row.NextHop)},
        {"interface_luid", std::to_string(row.InterfaceLuid.Value)},
        {"interface_index", std::to_string(row.InterfaceIndex)},
        {"reported_metric_offset", std::to_string(row.Metric)},
        {"reported_protocol", std::to_string(static_cast<unsigned>(row.Protocol))},
        {"reported_origin", std::to_string(static_cast<unsigned>(row.Origin))},
        {"record_scope", "native route row; effective path and process actor are not established"}};
}

template <typename Table, typename FreeFn, typename RowFn>
Json snapshot_table(DWORD error, Table* table, std::size_t row_limit, const char* name,
                    std::string capture_started, FreeFn free_table, RowFn encode) {
    Json rows = Json::array();
    DWORD reported = 0;
    const bool table_available = table != nullptr;
    if (!error && table_available) {
        reported = table->NumEntries;
        const auto accepted = (std::min)(static_cast<std::size_t>(reported), row_limit);
        for (std::size_t i = 0; i < accepted; ++i) rows.push_back(encode(table->Table[i]));
    }
    if (table) free_table(table);
    const auto capture_ended = utc_now();
    const bool complete = error == NO_ERROR && table_available && reported <= row_limit;
    return {{"kind", "network_state_snapshot"}, {"table", name},
        {"snapshot_capture_started_utc", capture_started}, {"snapshot_capture_completed_utc", capture_ended},
        {"reported_row_count", std::to_string(reported)}, {"captured_row_count", std::to_string(rows.size())},
        {"rows", std::move(rows)}, {"state", error ? "unavailable" : complete ? "healthy" : "degraded"},
        {"native_error_code", std::to_string(error)}, {"truncated", reported > row_limit},
        {"consistency", "non_atomic_table_snapshot"},
        {"reconciliation", "subscriptions were active before enumeration; notifications observed during enumeration remain separately sequenced and may duplicate rows visible in this snapshot"}};
}

} // namespace

struct NetworkStateChangeSource::Impl {
    struct Pending {
        enum class Kind : std::uint8_t { interface, address, route } kind{};
        MIB_NOTIFICATION_TYPE notification{};
        std::uint64_t sequence{};
        std::uint64_t captured_filetime{};
        std::array<std::byte, max_row_bytes> bytes{};
        std::size_t size{};
    };

    explicit Impl(NetworkStateChangeLimits value) : limits(value), queue(value.callback_queue_capacity) {}
    NetworkStateChangeLimits limits;
    mutable std::mutex mutex;
    std::mutex lifecycle;
    std::condition_variable callback_done;
    // Fixed-capacity storage is allocated before subscriptions start. The
    // native callback path must not allocate or serialize telemetry.
    std::vector<Pending> queue;
    std::size_t queue_head{};
    std::size_t queue_size{};
    std::vector<Json> snapshots;
    HANDLE interface_handle{};
    HANDLE address_handle{};
    HANDLE route_handle{};
    bool interface_active{};
    bool address_active{};
    bool route_active{};
    std::uint64_t next_sequence{};
    std::uint64_t accepted{};
    std::uint64_t dropped_full{};
    std::uint64_t rejected_stopping{};
    std::uint64_t callback_errors{};
    std::uint64_t callbacks_in_flight{};
    DWORD start_error{};
    DWORD stop_error{};
    bool started{};
    bool starting{};
    bool stopping{};
    bool stopped{};
    bool snapshot_ready{};

    void on_change(Pending::Kind kind, const void* row, std::size_t size,
                   MIB_NOTIFICATION_TYPE type) noexcept {
        try {
            Pending event;
            event.kind = kind;
            event.notification = type;
            FILETIME captured{};
            GetSystemTimePreciseAsFileTime(&captured);
            ULARGE_INTEGER captured_value{};
            captured_value.LowPart = captured.dwLowDateTime;
            captured_value.HighPart = captured.dwHighDateTime;
            event.captured_filetime = captured_value.QuadPart;
            std::lock_guard lock(mutex);
            event.sequence = ++next_sequence;
            if (stopping || stopped) { ++rejected_stopping; return; }
            event.size = row ? size : 0;
            if (row && size <= event.bytes.size()) std::memcpy(event.bytes.data(), row, size);
            else if (row) { ++callback_errors; return; }
            if (queue_size >= limits.callback_queue_capacity) { ++dropped_full; return; }
            const auto tail = (queue_head + queue_size) % limits.callback_queue_capacity;
            queue[tail] = event;
            ++queue_size;
            ++accepted;
        } catch (...) {
            std::lock_guard lock(mutex);
            ++callback_errors;
        }
    }

    void enter_callback() noexcept {
        std::lock_guard lock(mutex);
        ++callbacks_in_flight;
    }
    void leave_callback() noexcept {
        std::lock_guard lock(mutex);
        if (callbacks_in_flight) --callbacks_in_flight;
        callback_done.notify_all();
    }

    static VOID CALLBACK interface_callback(PVOID context, PMIB_IPINTERFACE_ROW row,
                                             MIB_NOTIFICATION_TYPE type) noexcept {
        auto* self = static_cast<Impl*>(context); self->enter_callback();
        self->on_change(Pending::Kind::interface, row, row ? sizeof(*row) : 0, type);
        self->leave_callback();
    }
    static VOID CALLBACK address_callback(PVOID context, PMIB_UNICASTIPADDRESS_ROW row,
                                           MIB_NOTIFICATION_TYPE type) noexcept {
        auto* self = static_cast<Impl*>(context); self->enter_callback();
        self->on_change(Pending::Kind::address, row, row ? sizeof(*row) : 0, type);
        self->leave_callback();
    }
    static VOID CALLBACK route_callback(PVOID context, PMIB_IPFORWARD_ROW2 row,
                                         MIB_NOTIFICATION_TYPE type) noexcept {
        auto* self = static_cast<Impl*>(context); self->enter_callback();
        self->on_change(Pending::Kind::route, row, row ? sizeof(*row) : 0, type);
        self->leave_callback();
    }

    Json encode(Pending&& pending) {
        Json row = nullptr;
        if (pending.size) {
            switch (pending.kind) {
            case Pending::Kind::interface:
                if (pending.size == sizeof(MIB_IPINTERFACE_ROW)) {
                    MIB_IPINTERFACE_ROW value{}; std::memcpy(&value, pending.bytes.data(), sizeof(value));
                    row = {{"address_family", value.Family == AF_INET ? "ipv4" : value.Family == AF_INET6 ? "ipv6" : "unknown"},
                        {"interface_luid", std::to_string(value.InterfaceLuid.Value)},
                        {"interface_index", std::to_string(value.InterfaceIndex)}};
                } break;
            case Pending::Kind::address:
                if (pending.size == sizeof(MIB_UNICASTIPADDRESS_ROW)) {
                    MIB_UNICASTIPADDRESS_ROW value{}; std::memcpy(&value, pending.bytes.data(), sizeof(value));
                    row = {{"address", address(value.Address)},
                        {"address_family", value.Address.si_family == AF_INET ? "ipv4" : value.Address.si_family == AF_INET6 ? "ipv6" : "unknown"},
                        {"reported_ipv6_scope_id", value.Address.si_family == AF_INET6 ? std::to_string(value.Address.Ipv6.sin6_scope_id) : "0"},
                        {"interface_luid", std::to_string(value.InterfaceLuid.Value)},
                        {"interface_index", std::to_string(value.InterfaceIndex)}};
                } break;
            case Pending::Kind::route:
                if (pending.size == sizeof(MIB_IPFORWARD_ROW2)) {
                    MIB_IPFORWARD_ROW2 value{}; std::memcpy(&value, pending.bytes.data(), sizeof(value));
                    row = {{"address_family", value.DestinationPrefix.Prefix.si_family == AF_INET ? "ipv4" : value.DestinationPrefix.Prefix.si_family == AF_INET6 ? "ipv6" : "unknown"},
                        {"destination", address(value.DestinationPrefix.Prefix)},
                        {"reported_destination_prefix_length", std::to_string(value.DestinationPrefix.PrefixLength)},
                        {"next_hop", address(value.NextHop)},
                        {"reported_next_hop_ipv6_scope_id", value.NextHop.si_family == AF_INET6 ? std::to_string(value.NextHop.Ipv6.sin6_scope_id) : "0"},
                        {"interface_luid", std::to_string(value.InterfaceLuid.Value)},
                        {"interface_index", std::to_string(value.InterfaceIndex)}};
                } break;
            }
        }
        const char* kind = pending.kind == Pending::Kind::interface ? "ip_interface" :
            pending.kind == Pending::Kind::address ? "unicast_address" : "route";
        return {{"kind", "network_state_change"}, {"table", kind},
            {"notification", notification_name(pending.notification)},
            {"notification_type_raw", std::to_string(static_cast<unsigned>(pending.notification))},
            {"notification_sequence", std::to_string(pending.sequence)},
            {"event_time_utc", utc_from_filetime(pending.captured_filetime)}, {"event_time_source", "GetSystemTimePreciseAsFileTime sampled at callback entry; local receipt time, not kernel event time"},
            {"source", "Windows IP Helper notification API"}, {"row", std::move(row)},
            {"row_complete", false},
            {"initial_notification", pending.notification == MibInitialNotification},
            {"process_id", nullptr}, {"process_attribution", "unavailable from this API"},
            {"row_scope", "notification row may be incomplete; bytes copied during callback; do not infer an absent field as a deletion"}};
    }

    static DWORD cancel(HANDLE& handle) noexcept {
        if (!handle) return NO_ERROR;
        const auto result = CancelMibChangeNotify2(handle);
        if (result == NO_ERROR) handle = nullptr;
        return static_cast<DWORD>(result);
    }
};

NetworkStateChangeSource::NetworkStateChangeSource(NetworkStateChangeLimits limits)
    : impl_(std::make_unique<Impl>(validated_limits(limits))) {}

NetworkStateChangeSource::~NetworkStateChangeSource() {
    if (stop() != NO_ERROR) (void)impl_.release(); // A failed native cancel must not leave callbacks targeting freed context.
}

std::uint32_t NetworkStateChangeSource::start() {
    std::lock_guard lifecycle(impl_->lifecycle);
    {
        std::lock_guard lock(impl_->mutex);
        if (impl_->started || impl_->starting || impl_->stopping || impl_->stopped ||
            impl_->interface_handle || impl_->address_handle || impl_->route_handle)
            return ERROR_ALREADY_INITIALIZED;
        impl_->starting = true;
    }
    DWORD error = NotifyIpInterfaceChange(AF_UNSPEC, &Impl::interface_callback, impl_.get(), TRUE, &impl_->interface_handle);
    if (!error) { std::lock_guard lock(impl_->mutex); impl_->interface_active = true; }
    if (!error) error = NotifyUnicastIpAddressChange(AF_UNSPEC, &Impl::address_callback, impl_.get(), TRUE, &impl_->address_handle);
    if (!error) { std::lock_guard lock(impl_->mutex); impl_->address_active = true; }
    if (!error) error = NotifyRouteChange2(AF_UNSPEC, &Impl::route_callback, impl_.get(), TRUE, &impl_->route_handle);
    if (!error) { std::lock_guard lock(impl_->mutex); impl_->route_active = true; }
    if (error) {
        {
            std::lock_guard lock(impl_->mutex); impl_->stopping = true;
        }
        const DWORD route_cancel = Impl::cancel(impl_->route_handle);
        const DWORD address_cancel = Impl::cancel(impl_->address_handle);
        const DWORD interface_cancel = Impl::cancel(impl_->interface_handle);
        std::unique_lock lock(impl_->mutex);
        impl_->callback_done.wait(lock, [&] { return impl_->callbacks_in_flight == 0; });
        impl_->interface_active = impl_->interface_handle != nullptr;
        impl_->address_active = impl_->address_handle != nullptr;
        impl_->route_active = impl_->route_handle != nullptr;
        impl_->start_error = error; impl_->stop_error = route_cancel ? route_cancel : address_cancel ? address_cancel : interface_cancel;
        impl_->starting = false; impl_->stopped = impl_->stop_error == NO_ERROR;
        impl_->stopping = !impl_->stopped; impl_->snapshot_ready = true;
        return error;
    }

    const auto limit = impl_->limits.snapshot_row_limit;
    MIB_IPINTERFACE_TABLE* interfaces = nullptr;
    auto capture_started = utc_now();
    error = GetIpInterfaceTable(AF_UNSPEC, &interfaces);
    std::vector<Json> snapshots;
    snapshots.push_back(snapshot_table(error, interfaces, limit, "ip_interface", std::move(capture_started), FreeMibTable,
        [](const MIB_IPINTERFACE_ROW& row) { return interface_row(row); }));
    MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
    capture_started = utc_now();
    error = GetUnicastIpAddressTable(AF_UNSPEC, &addresses);
    snapshots.push_back(snapshot_table(error, addresses, limit, "unicast_address", std::move(capture_started), FreeMibTable,
        [](const MIB_UNICASTIPADDRESS_ROW& row) { return address_row(row); }));
    MIB_IPFORWARD_TABLE2* routes = nullptr;
    capture_started = utc_now();
    error = GetIpForwardTable2(AF_UNSPEC, &routes);
    snapshots.push_back(snapshot_table(error, routes, limit, "route", std::move(capture_started), FreeMibTable,
        [](const MIB_IPFORWARD_ROW2& row) { return route_row(row); }));

    {
        std::lock_guard lock(impl_->mutex);
        impl_->snapshots = std::move(snapshots); impl_->snapshot_ready = true;
        impl_->starting = false; impl_->started = true; impl_->start_error = NO_ERROR;
    }
    return NO_ERROR;
}

std::uint32_t NetworkStateChangeSource::stop() noexcept {
    if (!impl_) return NO_ERROR;
    std::lock_guard lifecycle(impl_->lifecycle);
    {
        std::lock_guard lock(impl_->mutex);
        if (impl_->stopped) return impl_->stop_error;
        impl_->stopping = true;
    }
    const DWORD route_cancel = Impl::cancel(impl_->route_handle);
    const DWORD address_cancel = Impl::cancel(impl_->address_handle);
    const DWORD interface_cancel = Impl::cancel(impl_->interface_handle);
    std::unique_lock lock(impl_->mutex);
    impl_->callback_done.wait(lock, [&] { return impl_->callbacks_in_flight == 0; });
    impl_->interface_active = impl_->interface_handle != nullptr;
    impl_->address_active = impl_->address_handle != nullptr;
    impl_->route_active = impl_->route_handle != nullptr;
    impl_->stop_error = route_cancel ? route_cancel : address_cancel ? address_cancel : interface_cancel;
    impl_->stopped = impl_->stop_error == NO_ERROR;
    impl_->stopping = !impl_->stopped;
    return impl_->stop_error;
}

std::vector<nlohmann::json> NetworkStateChangeSource::drain(std::size_t maximum_records) {
    std::vector<Json> result;
    if (!maximum_records) return result;
    std::lock_guard lock(impl_->mutex);
    if (!impl_->snapshot_ready) return result;
    while (!impl_->snapshots.empty() && result.size() < maximum_records) {
        result.push_back(std::move(impl_->snapshots.front())); impl_->snapshots.erase(impl_->snapshots.begin());
    }
    while (impl_->queue_size && result.size() < maximum_records) {
        result.push_back(impl_->encode(std::move(impl_->queue[impl_->queue_head])));
        impl_->queue[impl_->queue_head] = {};
        impl_->queue_head = (impl_->queue_head + 1) % impl_->limits.callback_queue_capacity;
        --impl_->queue_size;
    }
    return result;
}

nlohmann::json NetworkStateChangeSource::status() const {
    std::lock_guard lock(impl_->mutex);
    const char* state = impl_->stopped ? "stopped" : impl_->stop_error ? "stop_failed" : impl_->stopping ? "stopping" :
        impl_->started ? "running" : impl_->starting ? "starting" : "not_started";
    return {{"source", "windows_ip_helper_network_state_change"}, {"state", state},
        {"subscription_families", {"ip_interface", "unicast_address", "route"}},
        {"interface_subscription_active", impl_->interface_active},
        {"address_subscription_active", impl_->address_active},
        {"route_subscription_active", impl_->route_active},
        {"notification_sequence_high_water", std::to_string(impl_->next_sequence)},
        {"accepted_notifications", std::to_string(impl_->accepted)},
        {"dropped_queue_full", std::to_string(impl_->dropped_full)},
        {"rejected_during_stop", std::to_string(impl_->rejected_stopping)},
        {"callback_copy_or_queue_errors", std::to_string(impl_->callback_errors)},
        {"queued_notifications", std::to_string(impl_->queue_size)},
        {"start_error_code", std::to_string(impl_->start_error)},
        {"stop_error_code", std::to_string(impl_->stop_error)},
        {"loss_scope", "callback sequence advances for each callback reaching this process; full-queue and stop refusals are counted, and sequence gaps expose rejected notifications; provider-side loss before callback delivery is not reported by IP Helper"}};
}

} // namespace panopticon::officer::collectors
