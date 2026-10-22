#include "panopticon/officer/collectors/service_state_change.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
using NotifyFunction = DWORD (WINAPI*)(SC_HANDLE, DWORD, PSERVICE_NOTIFYW);

struct ServiceCloser { void operator()(void* value) const noexcept { if (value) CloseServiceHandle(static_cast<SC_HANDLE>(value)); } };
using ServiceHandle = std::unique_ptr<void, ServiceCloser>;

std::string utf8(const std::wstring& text, std::size_t limit = 256) {
    const auto length = text.size();
    if (!length || length > limit) return {};
    if (!length) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (required <= 0 || required > 1024) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(length), result.data(), required, nullptr, nullptr)) return {};
    return result;
}

Json encoded_name(const std::wstring& name) {
    auto value = utf8(name);
    if (!value.empty() || name.empty()) return value;
    constexpr char digits[] = "0123456789abcdef";
    const auto* bytes = reinterpret_cast<const unsigned char*>(name.data());
    std::string hex;
    hex.reserve(name.size() * sizeof(wchar_t) * 2);
    for (std::size_t i = 0; i < name.size() * sizeof(wchar_t); ++i) {
        hex.push_back(digits[bytes[i] >> 4]);
        hex.push_back(digits[bytes[i] & 0x0f]);
    }
    return {{"encoding", "utf16le_hex"}, {"value", std::move(hex)}};
}

const char* state_name(DWORD value) noexcept {
    switch (value) {
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "start_pending";
    case SERVICE_STOP_PENDING: return "stop_pending";
    case SERVICE_RUNNING: return "running";
    case SERVICE_CONTINUE_PENDING: return "continue_pending";
    case SERVICE_PAUSE_PENDING: return "pause_pending";
    case SERVICE_PAUSED: return "paused";
    default: return "unknown";
    }
}

std::string filetime_now() {
    FILETIME file_time{};
    GetSystemTimePreciseAsFileTime(&file_time);
    ULARGE_INTEGER value{};
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    return std::to_string(value.QuadPart);
}

struct CaseInsensitiveLess {
    bool operator()(const std::wstring& left, const std::wstring& right) const noexcept {
        const int result = CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
            right.data(), static_cast<int>(right.size()), TRUE);
        return result == CSTR_LESS_THAN;
    }
};
} // namespace

struct ServiceStateChangeSource::Impl {
    struct Pending {
        std::wstring name;
        DWORD callback_status{};
        DWORD triggered{};
        SERVICE_STATUS_PROCESS service_status{};
        std::uint64_t sequence{};
        std::string callback_time;
    };
    struct Watch {
        Impl* owner{};
        std::wstring name;
        SC_HANDLE handle{};
        SERVICE_NOTIFYW notification{};
        std::mutex api_mutex;
        bool rearm_queued{}; // guarded by Impl::mutex
    };

    explicit Impl(ServiceStateChangeLimits value) : limits(value) {}
    ServiceStateChangeLimits limits;
    mutable std::mutex mutex;
    std::mutex lifecycle;
    std::mutex reconcile_mutex;
    std::mutex watches_mutex;
    std::mutex wake_mutex;
    std::condition_variable callbacks_done;
    std::condition_variable wake_reconciler;
    std::deque<Pending> queue;
    std::deque<Watch*> rearm_queue;
    std::map<std::wstring, std::unique_ptr<Watch>, CaseInsensitiveLess> watches;
    SC_HANDLE manager{};
    HMODULE advapi{};
    NotifyFunction notify{};
    std::jthread reconciler;
    std::atomic_bool stopping{false};
    std::uint64_t next_sequence{};
    std::uint64_t accepted{};
    std::uint64_t queue_drops{};
    std::uint64_t registration_failures{};
    std::uint64_t enumeration_failures{};
    std::uint64_t callbacks_in_flight{};
    std::uint64_t reconciliation_runs{};
    std::uint64_t truncated_enumerations{};
    std::uint64_t watch_limit_skips{};
    std::uint64_t last_enumerated_service_count{};
    DWORD start_error{};
    DWORD last_enumeration_error{};
    DWORD stop_error{};
    DWORD last_registration_error{};
    bool started{};
    bool start_attempted{};
    bool unsupported{};
    bool stopping_complete{};

    static VOID CALLBACK on_notification(PVOID context) noexcept {
        auto* watch = static_cast<Watch*>(context);
        if (!watch || !watch->owner) return;
        auto& self = *watch->owner;
        SERVICE_NOTIFYW* notification = &watch->notification;
        {
            std::lock_guard lock(self.mutex);
            ++self.callbacks_in_flight;
        }
        try {
          {
            std::lock_guard lock(self.mutex);
            if (!self.stopping.load(std::memory_order_acquire)) {
                Pending item;
                item.sequence = ++self.next_sequence;
                item.name = watch->name;
                item.callback_status = notification->dwNotificationStatus;
                item.triggered = notification->dwNotificationTriggered;
                item.service_status = notification->ServiceStatus;
                item.callback_time = filetime_now();
                if (item.callback_status != ERROR_SUCCESS) {
                    ++self.registration_failures;
                    self.last_registration_error = item.callback_status;
                }
                if (self.queue.size() < self.limits.callback_queue_capacity) {
                    try { self.queue.push_back(std::move(item)); ++self.accepted; }
                    catch (...) { ++self.queue_drops; }
                } else {
                    ++self.queue_drops;
                }
                if (!watch->rearm_queued) {
                    try { self.rearm_queue.push_back(watch); watch->rearm_queued = true; }
                    catch (...) { ++self.registration_failures; self.last_registration_error = ERROR_NOT_ENOUGH_MEMORY; }
                }
            }
          }
          self.wake_reconciler.notify_one();
        } catch (...) {
            std::lock_guard lock(self.mutex);
            ++self.queue_drops;
            ++self.registration_failures;
            self.last_registration_error = ERROR_NOT_ENOUGH_MEMORY;
        }
        {
            std::lock_guard lock(self.mutex);
            if (self.callbacks_in_flight) --self.callbacks_in_flight;
            self.callbacks_done.notify_all();
        }
        self.wake_reconciler.notify_one();
    }

    DWORD add_watch(const std::wstring& name) {
        if (watches.find(name) != watches.end()) return ERROR_SUCCESS;
        if (watches.size() >= limits.maximum_watched_services) {
            std::lock_guard lock(mutex);
            ++registration_failures;
            last_registration_error = ERROR_NOT_ENOUGH_MEMORY;
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        ServiceHandle handle{OpenServiceW(manager, name.c_str(), SERVICE_QUERY_STATUS)};
        if (!handle) {
            const auto error = GetLastError();
            std::lock_guard lock(mutex);
            ++registration_failures; last_registration_error = error;
            return error;
        }
        auto watch = std::make_unique<Watch>();
        watch->owner = this;
        watch->name = name;
        watch->handle = static_cast<SC_HANDLE>(handle.release());
        watch->notification.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        watch->notification.pfnNotifyCallback = &Impl::on_notification;
        watch->notification.pContext = watch.get();
        const auto error = notify(watch->handle,
            SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING |
            SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_CONTINUE_PENDING | SERVICE_NOTIFY_PAUSE_PENDING |
            SERVICE_NOTIFY_PAUSED | SERVICE_NOTIFY_DELETE_PENDING | SERVICE_NOTIFY_DELETED,
            &watch->notification);
        if (error != ERROR_SUCCESS) {
            CloseServiceHandle(watch->handle); watch->handle = nullptr;
            std::lock_guard lock(mutex);
            ++registration_failures; last_registration_error = error;
            return error;
        }
        watches.emplace(name, std::move(watch));
        return ERROR_SUCCESS;
    }

    DWORD reconcile() {
        std::lock_guard reconciliation(reconcile_mutex);
        std::vector<std::byte> buffer(limits.enumeration_buffer_bytes);
        DWORD bytes_needed = 0, services_returned = 0, resume = 0;
        const BOOL ok = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
            reinterpret_cast<BYTE*>(buffer.data()), static_cast<DWORD>(buffer.size()),
            &bytes_needed, &services_returned, &resume, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        {
            std::lock_guard lock(mutex);
            ++reconciliation_runs;
            last_enumeration_error = error;
            last_enumerated_service_count = services_returned;
            if (!ok && error == ERROR_MORE_DATA) ++truncated_enumerations;
            if (!ok && error != ERROR_MORE_DATA) ++enumeration_failures;
        }
        if (!ok && error != ERROR_MORE_DATA) return error;
        const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        std::lock_guard watch_lock(watches_mutex);
        DWORD subscribed = 0;
        DWORD i = 0;
        for (; i < services_returned && subscribed < limits.maximum_watched_services; ++i) {
            if (!entries[i].lpServiceName) continue;
            const std::wstring name{entries[i].lpServiceName};
            if (name.empty() || name.size() > 256) continue;
            if (watches.find(name) != watches.end()) { ++subscribed; continue; }
            (void)add_watch(name);
            ++subscribed;
        }
        if (i < services_returned) {
            std::lock_guard lock(mutex);
            watch_limit_skips += services_returned - i;
        }
        return error;
    }

    Json encode(Pending&& item) const {
        const auto& status = item.service_status;
        return {{"kind", "service_state_change"}, {"service_name", encoded_name(item.name)},
            {"callback_status_code", std::to_string(item.callback_status)},
            {"notification_mask", std::to_string(item.triggered)},
            {"service_state", state_name(status.dwCurrentState)},
            {"reported_service_state_code", std::to_string(status.dwCurrentState)},
            {"reported_service_type", std::to_string(status.dwServiceType)},
            {"reported_controls_accepted", std::to_string(status.dwControlsAccepted)},
            {"reported_win32_exit_code", std::to_string(status.dwWin32ExitCode)},
            {"reported_service_exit_code", std::to_string(status.dwServiceSpecificExitCode)},
            {"reported_checkpoint", std::to_string(status.dwCheckPoint)},
            {"reported_wait_hint_ms", std::to_string(status.dwWaitHint)},
            {"reported_process_id", std::to_string(status.dwProcessId)},
            {"process_attribution", "SCM status PID only; not verified as a process instance"},
            {"notification_sequence", std::to_string(item.sequence)},
            {"callback_receipt_filetime_100ns", std::move(item.callback_time)},
            {"event_time_source", "local system clock sampled in NotifyServiceStatusChange callback; receipt time, not exact transition time"},
            {"source", "Windows Service Control Manager NotifyServiceStatusChangeW"},
            {"scope", "service status transitions only; not service configuration, driver load lifecycle, actor identity, or proof of complete SCM coverage"}};
    }
};

ServiceStateChangeSource::ServiceStateChangeSource(ServiceStateChangeLimits limits)
    : impl_(std::make_unique<Impl>(limits)) {
    if (limits.callback_queue_capacity == 0 || limits.callback_queue_capacity > 65536 ||
        limits.maximum_watched_services == 0 || limits.maximum_watched_services > 32768 ||
        limits.enumeration_buffer_bytes < 4096 || limits.enumeration_buffer_bytes > 64 * 1024 * 1024 ||
        limits.reconciliation_interval_ms < 1000 || limits.reconciliation_interval_ms > 3600000)
        throw std::invalid_argument("invalid service state change limits");
}

ServiceStateChangeSource::~ServiceStateChangeSource() { (void)stop(); }

std::uint32_t ServiceStateChangeSource::start() {
    std::lock_guard lifecycle(impl_->lifecycle);
    { std::lock_guard lock(impl_->mutex);
      if (impl_->start_attempted || impl_->stopping_complete) return ERROR_ALREADY_INITIALIZED;
      impl_->start_attempted = true; }
    impl_->advapi = LoadLibraryExW(L"advapi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const auto resolved_notify = impl_->advapi
        ? reinterpret_cast<NotifyFunction>(GetProcAddress(impl_->advapi, "NotifyServiceStatusChangeW")) : nullptr;
    { std::lock_guard lock(impl_->mutex); impl_->notify = resolved_notify; }
    if (!impl_->notify) {
        std::lock_guard lock(impl_->mutex);
        impl_->unsupported = true; impl_->start_error = ERROR_CALL_NOT_IMPLEMENTED;
        return impl_->start_error;
    }
    impl_->manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!impl_->manager) { std::lock_guard lock(impl_->mutex); impl_->start_error = GetLastError(); return impl_->start_error; }
    const auto initial = impl_->reconcile();
    if (initial != ERROR_SUCCESS && initial != ERROR_MORE_DATA) {
        { std::lock_guard lock(impl_->mutex); impl_->start_error = initial; }
        CloseServiceHandle(impl_->manager); impl_->manager = nullptr;
        return initial;
    }
    { std::lock_guard lock(impl_->mutex); impl_->started = true; impl_->start_error = ERROR_SUCCESS; }
    impl_->stopping.store(false, std::memory_order_release);
    impl_->reconciler = std::jthread([state = impl_.get()](std::stop_token stop) {
        auto next_reconciliation = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(state->limits.reconciliation_interval_ms);
        while (!stop.stop_requested() && !state->stopping.load(std::memory_order_acquire)) {
            std::unique_lock wake_lock(state->wake_mutex);
            state->wake_reconciler.wait_until(wake_lock, next_reconciliation);
            wake_lock.unlock();
            if (stop.stop_requested() || state->stopping.load(std::memory_order_acquire)) break;
            std::deque<Impl::Watch*> pending_rearms;
            {
                std::lock_guard lock(state->mutex);
                // The notification structure belongs to the callback until
                // that callback returns; wait for all callbacks before reuse.
                if (state->callbacks_in_flight == 0) {
                    pending_rearms.swap(state->rearm_queue);
                    for (auto* watch : pending_rearms) watch->rearm_queued = false;
                }
            }
            for (auto* watch : pending_rearms) {
                if (stop.stop_requested() || state->stopping.load(std::memory_order_acquire)) break;
                std::lock_guard api_lock(watch->api_mutex);
                if (!watch->handle) continue;
                const auto error = state->notify(watch->handle,
                    SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING |
                    SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_CONTINUE_PENDING | SERVICE_NOTIFY_PAUSE_PENDING |
                    SERVICE_NOTIFY_PAUSED | SERVICE_NOTIFY_DELETE_PENDING | SERVICE_NOTIFY_DELETED,
                    &watch->notification);
                if (error != ERROR_SUCCESS) {
                    std::lock_guard lock(state->mutex);
                    ++state->registration_failures;
                    state->last_registration_error = error;
                }
            }
            if (std::chrono::steady_clock::now() >= next_reconciliation) {
                if (!state->stopping.load(std::memory_order_acquire)) (void)state->reconcile();
                next_reconciliation = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(state->limits.reconciliation_interval_ms);
            }
        }
    });
    return ERROR_SUCCESS;
}

std::uint32_t ServiceStateChangeSource::stop() noexcept {
    if (!impl_) return ERROR_SUCCESS;
    std::lock_guard lifecycle(impl_->lifecycle);
    { std::lock_guard lock(impl_->mutex); if (impl_->stopping_complete) return impl_->stop_error; }
    impl_->stopping.store(true, std::memory_order_release);
    impl_->wake_reconciler.notify_all();
    if (impl_->reconciler.joinable()) { impl_->reconciler.request_stop(); impl_->reconciler.join(); }
    DWORD close_error = ERROR_SUCCESS;
    {
        std::lock_guard watch_lock(impl_->watches_mutex);
        for (auto& [_, watch] : impl_->watches) {
            std::lock_guard api_lock(watch->api_mutex);
            if (watch->handle) {
                if (!CloseServiceHandle(watch->handle) && close_error == ERROR_SUCCESS) close_error = GetLastError();
                watch->handle = nullptr;
            }
        }
    }
    {
        std::unique_lock lock(impl_->mutex);
        impl_->callbacks_done.wait(lock, [&] { return impl_->callbacks_in_flight == 0; });
    }
    if (impl_->manager) {
        if (!CloseServiceHandle(impl_->manager) && close_error == ERROR_SUCCESS) close_error = GetLastError();
        impl_->manager = nullptr;
    }
    if (impl_->advapi) { FreeLibrary(impl_->advapi); impl_->advapi = nullptr; }
    { std::lock_guard lock(impl_->mutex); impl_->stop_error = close_error; impl_->stopping_complete = true; impl_->started = false; }
    return impl_->stop_error;
}

std::vector<nlohmann::json> ServiceStateChangeSource::drain(std::size_t maximum_records) {
    std::vector<Json> result;
    if (!maximum_records) return result;
    std::lock_guard lock(impl_->mutex);
    const auto count = (std::min)(maximum_records, impl_->queue.size());
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        auto item = std::move(impl_->queue.front()); impl_->queue.pop_front();
        result.push_back(impl_->encode(std::move(item)));
    }
    return result;
}

nlohmann::json ServiceStateChangeSource::status() const {
    std::scoped_lock lock(impl_->mutex, impl_->watches_mutex);
    const auto state = impl_->unsupported ? "unsupported" : !impl_->start_error && impl_->started && !impl_->stopping ? "running" :
        impl_->stopping_complete ? "stopped" : impl_->start_error ? "unavailable" : impl_->stopping ? "stopping" : "not_started";
    const bool known_blindness = impl_->queue_drops || impl_->registration_failures || impl_->enumeration_failures ||
        impl_->truncated_enumerations || impl_->watch_limit_skips;
    const auto coverage_state = impl_->unsupported ? "unsupported" : !impl_->started ? "unavailable" :
        known_blindness ? "blind" : "degraded";
    return {{"source", "windows_scm_service_status_notifications"}, {"state", state},
        {"coverage_state", coverage_state},
        {"notification_api", impl_->notify ? "NotifyServiceStatusChangeW" : "unavailable"},
        {"watched_service_count", std::to_string(impl_->watches.size())},
        {"maximum_watched_services", std::to_string(impl_->limits.maximum_watched_services)},
        {"callback_sequence_high_water", std::to_string(impl_->next_sequence)},
        {"accepted_notifications", std::to_string(impl_->accepted)},
        {"dropped_queue_full_or_allocation", std::to_string(impl_->queue_drops)},
        {"subscription_failures", std::to_string(impl_->registration_failures)},
        {"last_subscription_error", std::to_string(impl_->last_registration_error)},
        {"enumeration_failures", std::to_string(impl_->enumeration_failures)},
        {"last_enumeration_error", std::to_string(impl_->last_enumeration_error)},
        {"truncated_enumerations", std::to_string(impl_->truncated_enumerations)},
        {"last_enumerated_service_count", std::to_string(impl_->last_enumerated_service_count)},
        {"enumeration_rows_skipped_due_to_watch_limit", std::to_string(impl_->watch_limit_skips)},
        {"reconciliation_runs", std::to_string(impl_->reconciliation_runs)},
        {"queued_notifications", std::to_string(impl_->queue.size())},
        {"start_error", std::to_string(impl_->start_error)}, {"stop_error", std::to_string(impl_->stop_error)},
        {"reconciliation_interval_ms", std::to_string(impl_->limits.reconciliation_interval_ms)},
        {"scope", "status notifications only for successfully opened services; new service discovery is periodic and best effort; no configuration, driver-load, actor, or process-instance coverage claim"}};
}

} // namespace panopticon::officer::collectors
