#include "panopticon/officer/collectors/sysmon_event_collector.hpp"

#include "panopticon/officer/collectors/sysmon_process_decoder.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winevt.h>

#include <condition_variable>
#include <cstdint>
#include <exception>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace panopticon::officer::collectors {
namespace {

constexpr wchar_t kSysmonChannel[] = L"Microsoft-Windows-Sysmon/Operational";
constexpr wchar_t kProcessCreateQuery[] = L"*[System[(EventID=1)]]";

std::string win32_error_message(DWORD error) {
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

std::optional<std::string> utf16_to_utf8(std::wstring_view text, std::string& error_message) {
    if (text.empty()) {
        return std::string{};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        error_message = "Windows Event Log returned an XML document that is too large.";
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
        error_message = "Could not convert Sysmon event XML from UTF-16 to UTF-8: " +
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
        error_message = "Could not convert Sysmon event XML from UTF-16 to UTF-8: " +
                        win32_error_message(GetLastError());
        return std::nullopt;
    }
    return result;
}

std::optional<std::string> render_event_xml(EVT_HANDLE event, std::string& error_message) {
    DWORD bytes_required = 0;
    DWORD property_count = 0;
    if (!EvtRender(
            nullptr,
            event,
            EvtRenderEventXml,
            0,
            nullptr,
            &bytes_required,
            &property_count)) {
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            error_message = "EvtRender could not size Sysmon XML: " +
                            win32_error_message(error);
            return std::nullopt;
        }
    }
    if (bytes_required < sizeof(wchar_t)) {
        error_message = "EvtRender reported an empty Sysmon event.";
        return std::nullopt;
    }

    std::vector<wchar_t> buffer(
        (static_cast<std::size_t>(bytes_required) + sizeof(wchar_t) - 1) /
        sizeof(wchar_t));
    if (!EvtRender(
            nullptr,
            event,
            EvtRenderEventXml,
            bytes_required,
            buffer.data(),
            &bytes_required,
            &property_count)) {
        error_message = "EvtRender could not render Sysmon XML: " +
                        win32_error_message(GetLastError());
        return std::nullopt;
    }

    std::size_t characters = buffer.size();
    while (characters != 0 && buffer[characters - 1] == L'\0') {
        --characters;
    }
    return utf16_to_utf8(std::wstring_view{buffer.data(), characters}, error_message);
}

}  // namespace

struct SysmonEventCollector::Impl {
    mutable std::mutex mutex;
    std::condition_variable callbacks_finished;
    EVT_HANDLE subscription{nullptr};
    RawEventSink event_sink;
    CollectorErrorSink error_sink;
    std::size_t active_callbacks{};
    bool accepting_callbacks{};

    bool begin_callback() {
        std::scoped_lock lock{mutex};
        if (!accepting_callbacks) {
            return false;
        }
        ++active_callbacks;
        return true;
    }

    void finish_callback() noexcept {
        std::scoped_lock lock{mutex};
        --active_callbacks;
        if (active_callbacks == 0) {
            callbacks_finished.notify_all();
        }
    }

    void report_error(std::string message) noexcept {
        try {
            if (error_sink) {
                error_sink("sysmon", std::move(message));
            }
        } catch (...) {
            // Exceptions must never cross the Windows Event Log callback boundary.
        }
    }

    void deliver(EVT_HANDLE event) noexcept {
        std::string error;
        const auto xml = render_event_xml(event, error);
        if (!xml) {
            report_error(std::move(error));
            return;
        }
        const auto raw = SysmonProcessDecoder::decode_xml(*xml, error);
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

    static DWORD WINAPI callback(
        EVT_SUBSCRIBE_NOTIFY_ACTION action,
        PVOID context,
        EVT_HANDLE event) noexcept {
        auto* self = static_cast<Impl*>(context);
        if (self == nullptr || !self->begin_callback()) {
            return ERROR_SUCCESS;
        }
        struct CallbackGuard {
            Impl* owner;
            ~CallbackGuard() { owner->finish_callback(); }
        } guard{self};

        if (action == EvtSubscribeActionDeliver) {
            self->deliver(event);
        } else if (action == EvtSubscribeActionError) {
            const auto error = static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(event));
            self->report_error("Subscription reported missing or unavailable events: " +
                               win32_error_message(error));
        }
        return ERROR_SUCCESS;
    }
};

SysmonEventCollector::SysmonEventCollector() : impl_(std::make_unique<Impl>()) {}

SysmonEventCollector::~SysmonEventCollector() {
    stop();
}

std::string_view SysmonEventCollector::name() const noexcept {
    return "sysmon";
}

bool SysmonEventCollector::start(
    RawEventSink event_sink,
    CollectorErrorSink error_sink,
    std::string& error_message) {
    error_message.clear();
    if (!event_sink) {
        error_message = "The Sysmon collector requires an event sink.";
        return false;
    }

    {
        std::scoped_lock lock{impl_->mutex};
        if (impl_->subscription != nullptr || impl_->accepting_callbacks) {
            error_message = "The Sysmon collector is already running.";
            return false;
        }
        impl_->event_sink = std::move(event_sink);
        impl_->error_sink = std::move(error_sink);
        impl_->accepting_callbacks = true;
    }

    EVT_HANDLE subscription = EvtSubscribe(
        nullptr,
        nullptr,
        kSysmonChannel,
        kProcessCreateQuery,
        nullptr,
        impl_.get(),
        &Impl::callback,
        EvtSubscribeToFutureEvents | EvtSubscribeStrict);
    if (subscription == nullptr) {
        const DWORD error = GetLastError();
        std::scoped_lock lock{impl_->mutex};
        impl_->accepting_callbacks = false;
        impl_->event_sink = {};
        impl_->error_sink = {};
        error_message = "EvtSubscribe failed for the Sysmon Operational channel: " +
                        win32_error_message(error);
        return false;
    }
    {
        std::scoped_lock lock{impl_->mutex};
        impl_->subscription = subscription;
    }
    return true;
}

void SysmonEventCollector::stop() noexcept {
    EVT_HANDLE subscription = nullptr;
    {
        std::scoped_lock lock{impl_->mutex};
        impl_->accepting_callbacks = false;
        subscription = std::exchange(impl_->subscription, nullptr);
    }
    if (subscription != nullptr) {
        EvtClose(subscription);
    }

    std::unique_lock lock{impl_->mutex};
    impl_->callbacks_finished.wait(lock, [this] { return impl_->active_callbacks == 0; });
    impl_->event_sink = {};
    impl_->error_sink = {};
}

bool SysmonEventCollector::running() const noexcept {
    std::scoped_lock lock{impl_->mutex};
    return impl_->subscription != nullptr && impl_->accepting_callbacks;
}

}  // namespace panopticon::officer::collectors
