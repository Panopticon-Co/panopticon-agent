#include "panopticon/officer/collectors/etw_process_collector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace panopticon::officer::collectors {
namespace {

constexpr wchar_t kSessionName[] = L"Panopticon-Officer-Process";
constexpr wchar_t kProviderName[] = L"Microsoft-Windows-Kernel-Process";
constexpr std::uint16_t kProcessStartEventId = 1;
constexpr std::uint64_t kProcessKeyword = 0x10;
constexpr GUID kKernelProcessProvider{
    0x22fb2cd6,
    0x0e7b,
    0x422b,
    {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

std::string win32_error_message(ULONG error) {
    char* message = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<char*>(&message),
        0,
        nullptr);
    std::string result = length != 0 && message != nullptr
                             ? std::string{message, length}
                             : "Win32 error " + std::to_string(error);
    if (message != nullptr) {
        LocalFree(message);
    }
    while (!result.empty() && (result.back() == '\r' || result.back() == '\n')) {
        result.pop_back();
    }
    return result;
}

std::string property_name_for_error(const wchar_t* property_name) {
    std::string result;
    while (*property_name != L'\0') {
        result.push_back(*property_name <= 0x7f ? static_cast<char>(*property_name) : '?');
        ++property_name;
    }
    return result;
}

std::optional<std::vector<std::byte>> event_information(
    const EVENT_RECORD& record,
    std::string& error_message) {
    ULONG required = 0;
    TDHSTATUS status = TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(&record), 0, nullptr, nullptr, &required);
    if (status != ERROR_INSUFFICIENT_BUFFER || required < sizeof(TRACE_EVENT_INFO)) {
        error_message = "TdhGetEventInformation could not size event metadata: " +
                        win32_error_message(status);
        return std::nullopt;
    }
    std::vector<std::byte> buffer(required);
    status = TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(&record),
        0,
        nullptr,
        reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data()),
        &required);
    if (status != ERROR_SUCCESS) {
        error_message = "TdhGetEventInformation could not read event metadata: " +
                        win32_error_message(status);
        return std::nullopt;
    }
    return buffer;
}

bool has_property_type(
    const std::vector<std::byte>& metadata,
    std::wstring_view property_name,
    USHORT expected_type) {
    const auto* info = reinterpret_cast<const TRACE_EVENT_INFO*>(metadata.data());
    for (ULONG index = 0; index < info->TopLevelPropertyCount; ++index) {
        const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[index];
        if ((property.Flags & PropertyStruct) != 0 || property.NameOffset >= metadata.size()) {
            continue;
        }
        const auto* name = reinterpret_cast<const wchar_t*>(
            metadata.data() + property.NameOffset);
        if (property_name == name) {
            return property.nonStructType.InType == expected_type;
        }
    }
    return false;
}

std::optional<std::vector<std::byte>> property_bytes(
    const EVENT_RECORD& record,
    const wchar_t* property_name,
    std::string& error_message) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(property_name);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    TDHSTATUS status = TdhGetPropertySize(
        const_cast<EVENT_RECORD*>(&record),
        0,
        nullptr,
        1,
        &descriptor,
        &size);
    if (status != ERROR_SUCCESS) {
        error_message = "TDH could not size property '" +
                        property_name_for_error(property_name) + "': " +
                        win32_error_message(status);
        return std::nullopt;
    }
    std::vector<std::byte> buffer(size);
    status = TdhGetProperty(
        const_cast<EVENT_RECORD*>(&record),
        0,
        nullptr,
        1,
        &descriptor,
        size,
        reinterpret_cast<PBYTE>(buffer.data()));
    if (status != ERROR_SUCCESS) {
        error_message = "TDH could not read an event property: " +
                        win32_error_message(status);
        return std::nullopt;
    }
    return buffer;
}

template <typename Value>
std::optional<Value> integral_property(
    const EVENT_RECORD& record,
    const std::vector<std::byte>& metadata,
    const wchar_t* name,
    USHORT expected_type,
    std::string& error_message) {
    if (!has_property_type(metadata, name, expected_type)) {
        error_message = "ETW event metadata does not contain property '" +
                        property_name_for_error(name) +
                        "' with the expected type.";
        return std::nullopt;
    }
    const auto bytes = property_bytes(record, name, error_message);
    if (!bytes || bytes->size() != sizeof(Value)) {
        if (error_message.empty()) {
            error_message = "ETW property has an unexpected byte size.";
        }
        return std::nullopt;
    }
    Value result{};
    std::memcpy(&result, bytes->data(), sizeof(result));
    return result;
}

std::optional<std::string> utf16_to_utf8(
    std::wstring_view text,
    std::string& error_message) {
    if (text.empty()) {
        return std::string{};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        error_message = "An ETW Unicode property is too large to convert.";
        return std::nullopt;
    }
    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        text.data(),
        static_cast<int>(text.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        error_message = "Could not convert an ETW Unicode property to UTF-8: " +
                        win32_error_message(GetLastError());
        return std::nullopt;
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            required,
            nullptr,
            nullptr) != required) {
        error_message = "Could not convert an ETW Unicode property to UTF-8: " +
                        win32_error_message(GetLastError());
        return std::nullopt;
    }
    return result;
}

std::optional<std::string> unicode_property(
    const EVENT_RECORD& record,
    const std::vector<std::byte>& metadata,
    const wchar_t* name,
    std::string& error_message) {
    if (!has_property_type(metadata, name, TDH_INTYPE_UNICODESTRING)) {
        error_message = "ETW event metadata does not contain ImageName as a Unicode string.";
        return std::nullopt;
    }
    const auto bytes = property_bytes(record, name, error_message);
    if (!bytes || bytes->size() % sizeof(wchar_t) != 0) {
        if (error_message.empty()) {
            error_message = "ETW Unicode property has an invalid byte size.";
        }
        return std::nullopt;
    }
    const auto* text = reinterpret_cast<const wchar_t*>(bytes->data());
    std::size_t characters = bytes->size() / sizeof(wchar_t);
    while (characters != 0 && text[characters - 1] == L'\0') {
        --characters;
    }
    return utf16_to_utf8(std::wstring_view{text, characters}, error_message);
}

std::optional<telemetry::UtcTimestamp> filetime_to_utc(
    std::uint64_t filetime,
    std::string& error_message) {
    constexpr std::uint64_t kUnixEpochInFiletimeTicks = 116'444'736'000'000'000ULL;
    if (filetime < kUnixEpochInFiletimeTicks) {
        error_message = "ETW CreateTime predates the Unix epoch and is not supported.";
        return std::nullopt;
    }
    const std::uint64_t unix_ticks = filetime - kUnixEpochInFiletimeTicks;
    if (unix_ticks > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max() / 100)) {
        error_message = "ETW CreateTime exceeds the supported timestamp range.";
        return std::nullopt;
    }
    return telemetry::UtcTimestamp{
        std::chrono::nanoseconds{static_cast<std::int64_t>(unix_ticks * 100)}};
}

std::optional<telemetry::RawProcessEvent> decode_process_start(
    const EVENT_RECORD& record,
    std::string& error_message) {
    const auto metadata = event_information(record, error_message);
    if (!metadata) {
        return std::nullopt;
    }
    const auto pid = integral_property<std::uint32_t>(
        record, *metadata, L"ProcessID", TDH_INTYPE_UINT32, error_message);
    const auto create_time = integral_property<std::uint64_t>(
        record, *metadata, L"CreateTime", TDH_INTYPE_FILETIME, error_message);
    const auto parent_pid = integral_property<std::uint32_t>(
        record, *metadata, L"ParentProcessID", TDH_INTYPE_UINT32, error_message);
    const auto image = unicode_property(record, *metadata, L"ImageName", error_message);
    if (!pid || !create_time || !parent_pid || !image) {
        return std::nullopt;
    }
    const auto timestamp = filetime_to_utc(*create_time, error_message);
    if (!timestamp) {
        return std::nullopt;
    }

    telemetry::RawProcessEvent result;
    result.source.kind = telemetry::TelemetrySourceKind::etw;
    result.source.provider = "Microsoft-Windows-Kernel-Process";
    result.process_start_time = *timestamp;
    result.pid = *pid;
    result.parent_pid = *parent_pid;
    if (!image->empty()) {
        result.executable = *image;
    }
    return result;
}

}  // namespace

struct EtwProcessCollector::Impl {
    mutable std::mutex mutex;
    std::vector<std::byte> properties_buffer;
    EVENT_TRACE_LOGFILEW trace_logfile{};
    TRACEHANDLE session_handle{};
    PROCESSTRACE_HANDLE processing_handle{INVALID_PROCESSTRACE_HANDLE};
    RawEventSink event_sink;
    CollectorErrorSink error_sink;
    std::thread worker;
    std::atomic_bool is_running{false};
    std::atomic_bool stop_requested{false};

    EVENT_TRACE_PROPERTIES* properties() noexcept {
        return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer.data());
    }

    void report_error(std::string message) noexcept {
        try {
            if (error_sink) {
                error_sink("etw", std::move(message));
            }
        } catch (...) {
            // Exceptions must never cross an ETW callback boundary.
        }
    }

    void deliver(const EVENT_RECORD& record) noexcept {
        if (!IsEqualGUID(record.EventHeader.ProviderId, kKernelProcessProvider) ||
            record.EventHeader.EventDescriptor.Id != kProcessStartEventId) {
            return;
        }
        std::string error;
        const auto raw = decode_process_start(record, error);
        if (!raw) {
            report_error(std::move(error));
            return;
        }
        try {
            if (event_sink) {
                event_sink(telemetry::RawEvent{*raw});
            }
        } catch (const std::exception& exception) {
            report_error("Event sink failed: " + std::string{exception.what()});
        } catch (...) {
            report_error("Event sink failed with an unknown exception.");
        }
    }

    static void WINAPI event_record_callback(EVENT_RECORD* record) noexcept {
        if (record == nullptr || record->UserContext == nullptr) {
            return;
        }
        static_cast<Impl*>(record->UserContext)->deliver(*record);
    }

    void process() noexcept {
        PROCESSTRACE_HANDLE handle = INVALID_PROCESSTRACE_HANDLE;
        {
            std::scoped_lock lock{mutex};
            handle = processing_handle;
        }
        const ULONG status = ProcessTrace(&handle, 1, nullptr, nullptr);
        is_running.store(false);
        if (!stop_requested.load() && status != ERROR_SUCCESS &&
            status != ERROR_CANCELLED && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            report_error("ProcessTrace stopped unexpectedly: " +
                         win32_error_message(status));
        }
    }

    void stop_session_only() noexcept {
        if (session_handle != 0 && !properties_buffer.empty()) {
            EnableTraceEx2(
                session_handle,
                &kKernelProcessProvider,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                nullptr);
            ControlTraceW(
                session_handle,
                kSessionName,
                properties(),
                EVENT_TRACE_CONTROL_STOP);
            session_handle = 0;
        }
    }
};

EtwProcessCollector::EtwProcessCollector() : impl_(std::make_unique<Impl>()) {}

EtwProcessCollector::~EtwProcessCollector() {
    stop();
}

std::string_view EtwProcessCollector::name() const noexcept {
    return "etw";
}

bool EtwProcessCollector::start(
    RawEventSink event_sink,
    CollectorErrorSink error_sink,
    std::string& error_message) {
    error_message.clear();
    if (!event_sink) {
        error_message = "The ETW collector requires an event sink.";
        return false;
    }

    std::scoped_lock lock{impl_->mutex};
    if (impl_->session_handle != 0 || impl_->worker.joinable()) {
        error_message = "The ETW collector is already running.";
        return false;
    }
    impl_->event_sink = std::move(event_sink);
    impl_->error_sink = std::move(error_sink);
    impl_->stop_requested.store(false);

    constexpr std::size_t session_name_bytes = sizeof(kSessionName);
    impl_->properties_buffer.assign(
        sizeof(EVENT_TRACE_PROPERTIES) + session_name_bytes,
        std::byte{});
    auto* properties = impl_->properties();
    properties->Wnode.BufferSize = static_cast<ULONG>(impl_->properties_buffer.size());
    properties->Wnode.ClientContext = 1;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::memcpy(
        impl_->properties_buffer.data() + properties->LoggerNameOffset,
        kSessionName,
        session_name_bytes);

    ULONG status = StartTraceW(&impl_->session_handle, kSessionName, properties);
    if (status != ERROR_SUCCESS) {
        impl_->session_handle = 0;
        impl_->properties_buffer.clear();
        impl_->event_sink = {};
        impl_->error_sink = {};
        error_message = status == ERROR_ALREADY_EXISTS
                            ? "The Officer ETW session already exists. Another agent may be running, or a previous process terminated without cleanup."
                            : "StartTraceW failed: " + win32_error_message(status);
        return false;
    }

    ENABLE_TRACE_PARAMETERS enable_parameters{};
    enable_parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    status = EnableTraceEx2(
        impl_->session_handle,
        &kKernelProcessProvider,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        kProcessKeyword,
        0,
        0,
        &enable_parameters);
    if (status != ERROR_SUCCESS) {
        error_message = "EnableTraceEx2 failed for Microsoft-Windows-Kernel-Process: " +
                        win32_error_message(status);
        impl_->stop_session_only();
        impl_->properties_buffer.clear();
        impl_->event_sink = {};
        impl_->error_sink = {};
        return false;
    }

    impl_->trace_logfile = {};
    impl_->trace_logfile.LoggerName = const_cast<LPWSTR>(kSessionName);
    impl_->trace_logfile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    impl_->trace_logfile.EventRecordCallback = &Impl::event_record_callback;
    impl_->trace_logfile.Context = impl_.get();
    impl_->processing_handle = OpenTraceW(&impl_->trace_logfile);
    if (impl_->processing_handle == INVALID_PROCESSTRACE_HANDLE) {
        error_message = "OpenTraceW failed for the Officer ETW session: " +
                        win32_error_message(GetLastError());
        impl_->stop_session_only();
        impl_->properties_buffer.clear();
        impl_->event_sink = {};
        impl_->error_sink = {};
        return false;
    }

    impl_->is_running.store(true);
    try {
        impl_->worker = std::thread{[implementation = impl_.get()] {
            implementation->process();
        }};
    } catch (const std::exception& exception) {
        error_message = "Could not start the ETW consumer thread: " +
                        std::string{exception.what()};
        CloseTrace(impl_->processing_handle);
        impl_->processing_handle = INVALID_PROCESSTRACE_HANDLE;
        impl_->stop_session_only();
        impl_->is_running.store(false);
        impl_->properties_buffer.clear();
        impl_->event_sink = {};
        impl_->error_sink = {};
        return false;
    }
    return true;
}

void EtwProcessCollector::stop() noexcept {
    PROCESSTRACE_HANDLE processing_handle = INVALID_PROCESSTRACE_HANDLE;
    {
        std::scoped_lock lock{impl_->mutex};
        impl_->stop_requested.store(true);
        impl_->stop_session_only();
        processing_handle = impl_->processing_handle;
    }

    if (processing_handle != INVALID_PROCESSTRACE_HANDLE) {
        const ULONG status = CloseTrace(processing_handle);
        if (status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING) {
            impl_->report_error("CloseTrace failed: " + win32_error_message(status));
        }
    }
    if (impl_->worker.joinable() && impl_->worker.get_id() != std::this_thread::get_id()) {
        impl_->worker.join();
    }

    std::scoped_lock lock{impl_->mutex};
    impl_->processing_handle = INVALID_PROCESSTRACE_HANDLE;
    impl_->is_running.store(false);
    impl_->properties_buffer.clear();
    impl_->event_sink = {};
    impl_->error_sink = {};
}

bool EtwProcessCollector::running() const noexcept {
    return impl_->is_running.load();
}

}  // namespace panopticon::officer::collectors
