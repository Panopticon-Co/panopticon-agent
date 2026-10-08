#include "panopticon/officer/collectors/windows_event_log.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winevt.h>
#include <algorithm>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
struct Evt {
    EVT_HANDLE value = nullptr;
    explicit Evt(EVT_HANDLE handle = nullptr) : value(handle) {}
    ~Evt() { if (value) EvtClose(value); }
    void close() { if (value) { EvtClose(value); value = nullptr; } }
    Evt(const Evt&) = delete;
    Evt& operator=(const Evt&) = delete;
};
struct Signal {
    HANDLE value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ~Signal() { if (value) CloseHandle(value); }
};
std::wstring widen(const std::string& input) {
    if (input.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (!size) throw std::runtime_error("invalid UTF-8 log configuration or checkpoint");
    std::wstring output(size, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), size) != size)
        throw std::runtime_error("UTF-8 log conversion failed");
    return output;
}
std::string narrow(const wchar_t* input, std::size_t count) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, static_cast<int>(count), nullptr, 0, nullptr, nullptr);
    if (!size && count) throw std::runtime_error("native log UTF-16 conversion failed");
    std::string output(size, '\0');
    if (size && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, static_cast<int>(count), output.data(), size, nullptr, nullptr) != size)
        throw std::runtime_error("native log UTF-16 conversion failed");
    return output;
}
struct NativeError : std::runtime_error {
    DWORD code;
    NativeError(const char* stage, DWORD value) : std::runtime_error(stage), code(value) {}
};
std::string render(EVT_HANDLE object, DWORD flags, DWORD bound) {
    DWORD required = 0, properties = 0;
    if (EvtRender(nullptr, object, flags, 0, nullptr, &required, &properties) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        throw NativeError("EvtRender sizing", GetLastError());
    if (!required || required > bound || required % sizeof(wchar_t)) throw NativeError("EvtRender size bound", ERROR_FILE_TOO_LARGE);
    std::vector<wchar_t> buffer(required / sizeof(wchar_t));
    const DWORD capacity = required;
    if (!EvtRender(nullptr, object, flags, capacity, buffer.data(), &required, &properties)) throw NativeError("EvtRender", GetLastError());
    if (!required || required > capacity || required % sizeof(wchar_t)) throw NativeError("EvtRender invalid length", ERROR_INVALID_DATA);
    const auto end = std::find(buffer.begin(), buffer.begin() + required / sizeof(wchar_t), L'\0');
    if (end == buffer.begin() + required / sizeof(wchar_t)) throw NativeError("EvtRender unterminated", ERROR_INVALID_DATA);
    try { return narrow(buffer.data(), static_cast<std::size_t>(end - buffer.begin())); }
    catch (const std::exception&) { throw NativeError("EvtRender invalid UTF-16", ERROR_NO_UNICODE_TRANSLATION); }
}
std::optional<bool> channel_enabled(const std::wstring& channel) {
    Evt config{EvtOpenChannelConfig(nullptr, channel.c_str(), 0)};
    if (!config.value) throw NativeError("EvtOpenChannelConfig", GetLastError());
    EVT_VARIANT enabled{}; DWORD required = 0;
    if (!EvtGetChannelConfigProperty(config.value, EvtChannelConfigEnabled, 0, sizeof(enabled), &enabled, &required))
        throw NativeError("EvtGetChannelConfigProperty", GetLastError());
    if (enabled.Type != EvtVarTypeBoolean) return std::nullopt;
    return enabled.BooleanVal != FALSE;
}
}
struct WindowsEventLog::Impl {
    struct Worker {
        std::string channel;
        mutable std::mutex mutex;
        Json health;
        std::jthread thread;
        explicit Worker(std::string value) : channel(std::move(value)), health{{"channel", channel}, {"state", "unavailable"},
            {"reason", "not subscribed"}, {"durable_records", "0"}, {"durable_gaps", "0"}, {"commit_refusals", "0"},
            {"checkpoint_revision", "0"}, {"pending_durable_acceptance", false}, {"continuity", "unverified"},
            {"audit_or_provider_policy_verified", false}, {"native_loss_count", nullptr}} {}
    };
    WindowsLogCallbacks callbacks;
    std::vector<std::unique_ptr<Worker>> workers;
    explicit Impl(WindowsLogCallbacks value, std::vector<std::string> channels) : callbacks(std::move(value)) {
        if (!callbacks.load || !callbacks.make_record || !callbacks.commit || channels.empty() || channels.size() > 16)
            throw std::invalid_argument("Windows log callbacks/channels invalid");
        std::set<std::string> unique;
        for (auto& channel : channels) {
            if (channel.empty() || channel.size() > 502 || channel.find_first_of("\r\n") != std::string::npos ||
                channel.find('\0') != std::string::npos || !unique.insert(channel).second)
                throw std::invalid_argument("Windows log channel invalid or duplicate");
            (void)widen(channel);
            workers.push_back(std::make_unique<Worker>(std::move(channel)));
        }
        try { for (auto& worker : workers) worker->thread = std::jthread([this, target = worker.get()](std::stop_token stop) { run(*target, stop); }); }
        catch (...) { stop(); throw; }
    }
    ~Impl() { stop(); }
    void stop() {
        for (auto& worker : workers) worker->thread.request_stop();
        for (auto& worker : workers) if (worker->thread.joinable()) worker->thread.join();
    }
    void notify() noexcept { try { if (callbacks.changed) callbacks.changed(); } catch (...) {} }
    void status(Worker& worker, const char* state, const std::string& reason, DWORD error = 0) {
        bool changed = false;
        { std::scoped_lock lock{worker.mutex}; changed = worker.health["state"] != state || worker.health["reason"] != reason || worker.health.value("native_error", 0ul) != error; }
        { std::scoped_lock lock{worker.mutex}; worker.health["state"] = state; worker.health["reason"] = reason;
          worker.health["native_error"] = error; worker.health["last_status_uptime_ms"] = std::to_string(GetTickCount64()); }
        if (changed) notify();
    }
    static void pause(std::stop_token stop, unsigned milliseconds) {
        for (unsigned waited = 0; waited < milliseconds && !stop.stop_requested(); waited += 50) Sleep(50);
    }
    bool accept(Worker& worker, std::stop_token stop, const DecodedWindowsEvent& event, bool gap,
        const std::string& source, const std::string& bookmark, std::uint64_t revision,
        std::uint64_t& records, std::uint64_t& gaps, std::uint64_t& refusals) {
        // Render one immutable record. Refusal retries the same bytes and never reads another event.
        const auto line = callbacks.make_record(worker.channel, event, gap);
        { std::scoped_lock lock{worker.mutex}; worker.health["pending_durable_acceptance"] = true; }
        while (!stop.stop_requested()) {
            bool accepted = false;
            try { accepted = callbacks.commit(line, source, bookmark, revision); } catch (...) {}
            if (accepted) {
                if (gap) ++gaps; else ++records;
                { std::scoped_lock lock{worker.mutex}; worker.health["pending_durable_acceptance"] = false;
                  worker.health["durable_records"] = std::to_string(records); worker.health["durable_gaps"] = std::to_string(gaps);
                  if (!bookmark.empty()) worker.health["checkpoint_revision"] = std::to_string(revision + 1);
                  worker.health["last_durable_acceptance_uptime_ms"] = std::to_string(GetTickCount64()); }
                return true;
            }
            ++refusals;
            { std::scoped_lock lock{worker.mutex}; worker.health["commit_refusals"] = std::to_string(refusals); }
            status(worker, "degraded", "durable acceptance refused; cursor unchanged, one immutable record pending");
            pause(stop, 1000);
        }
        return false;
    }
    void run(Worker& worker, std::stop_token stop) noexcept {
        const auto source = "winevt:v1:" + worker.channel;
        std::uint64_t records = 0, gaps = 0, refusals = 0, delivered = 0, unretained = 0, degraded = 0, source_failures = 0;
        bool startup_gap_accepted = false;
        while (!stop.stop_requested()) {
            bool has_checkpoint = false;
            try {
                auto checkpoint = callbacks.load(source);
                has_checkpoint = checkpoint.has_value();
                std::uint64_t revision = checkpoint ? checkpoint->revision : 0;
                { std::scoped_lock lock{worker.mutex}; worker.health["checkpoint_revision"] = std::to_string(revision); }
                const auto channel = widen(worker.channel);
                const auto enabled = channel_enabled(channel);
                { std::scoped_lock lock{worker.mutex}; worker.health["channel_enabled"] = enabled ? Json(*enabled) : Json(nullptr); }
                if (enabled && !*enabled) {
                    status(worker, "disabled", "native channel configuration disabled; not enabled by agent");
                    pause(stop, 30000); continue;
                }
                const auto xml = checkpoint ? widen(checkpoint->value) : std::wstring{};
                Evt prior{EvtCreateBookmark(checkpoint ? xml.c_str() : nullptr)};
                if (!prior.value) throw NativeError("EvtCreateBookmark saved cursor", GetLastError());
                Signal signal;
                if (!signal.value) throw NativeError("CreateEvent log signal", GetLastError());
                Evt subscription{EvtSubscribe(nullptr, signal.value, channel.c_str(), L"*", checkpoint ? prior.value : nullptr,
                    nullptr, nullptr, (checkpoint ? EvtSubscribeStartAfterBookmark : EvtSubscribeStartAtOldestRecord) | EvtSubscribeStrict)};
                if (!subscription.value) throw NativeError("EvtSubscribe strict", GetLastError());
                { std::scoped_lock lock{worker.mutex}; worker.health["resume_from_saved_checkpoint"] = checkpoint.has_value();
                  worker.health["replay_draining"] = true; worker.health["subscription_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                if (!startup_gap_accepted) {
                    DecodedWindowsEvent gap{{{"reason", checkpoint ? "bookmark_resumed_retention_continuity_unverified" : "history_before_oldest_retained_record_unknown"},
                        {"channel", worker.channel}, {"lost_native_events", nullptr}, {"checkpoint_revision", std::to_string(revision)}}, std::nullopt};
                    if (!accept(worker, stop, gap, true, source, "", revision, records, gaps, refusals)) break;
                    startup_gap_accepted = true;
                }
                status(worker, "degraded", "native pull subscription active; audit/provider policy and continuity unverified");
                while (!stop.stop_requested()) {
                    EVT_HANDLE native = nullptr; DWORD returned = 0;
                    { std::scoped_lock lock{worker.mutex}; worker.health["last_poll_uptime_ms"] = std::to_string(GetTickCount64()); }
                    if (!EvtNext(subscription.value, 1, &native, 250, 0, &returned)) {
                        const auto error = GetLastError();
                        if (error == ERROR_NO_MORE_ITEMS || error == ERROR_TIMEOUT) {
                            { std::scoped_lock lock{worker.mutex}; worker.health["replay_draining"] = false; }
                            ResetEvent(signal.value); WaitForSingleObject(signal.value, 500); continue;
                        }
                        throw NativeError("EvtNext", error);
                    }
                    Evt event{native};
                    if (returned != 1 || !event.value) throw NativeError("EvtNext invalid event count", ERROR_INVALID_DATA);
                    ++delivered;
                    { std::scoped_lock lock{worker.mutex}; worker.health["delivered_native_records"] = std::to_string(delivered);
                      worker.health["last_native_delivery_uptime_ms"] = std::to_string(GetTickCount64()); }
                    Evt next{EvtCreateBookmark(nullptr)};
                    if (!next.value || !EvtUpdateBookmark(next.value, event.value)) throw NativeError("EvtUpdateBookmark", GetLastError());
                    const auto next_xml = render(next.value, EvtRenderBookmark, 16384);
                    DecodedWindowsEvent decoded;
                    bool gap = false;
                    try { decoded = decode_windows_event_xml(render(event.value, EvtRenderEventXml, 131072), worker.channel); }
                    catch (const NativeError& error) {
                        ++unretained;
                        gap = true; decoded.data = {{"reason", "delivered_event_xml_not_retained"}, {"stage", error.what()},
                            {"native_error", error.code}, {"render_utf16_bound_bytes", 131072}, {"unretained_delivered_bodies", "1"}, {"lost_native_events", nullptr}};
                    }
                    if (!gap && decoded.data.value("decode_state", "degraded") != "healthy") ++degraded;
                    { std::scoped_lock lock{worker.mutex}; worker.health["xml_not_retained_records"] = std::to_string(unretained);
                      worker.health["decode_degraded_records"] = std::to_string(degraded);
                      worker.health["last_native_record_id"] = decoded.data.value("event_record_id", Json(nullptr)); }
                    decoded.data["source_checkpoint_revision"] = std::to_string(revision + 1);
                    event.close(); next.close(); // No native event retained through WAL/quota backpressure.
                    if (!accept(worker, stop, decoded, gap, source, next_xml, revision, records, gaps, refusals)) break;
                    ++revision;
                    status(worker, "degraded", "native pull subscription active; audit/provider policy and continuity unverified");
                }
            } catch (const NativeError& error) {
                { std::scoped_lock lock{worker.mutex}; worker.health["native_source_failures"] = std::to_string(++source_failures); }
                status(worker, has_checkpoint ? "blind" : "unavailable", error.what(), error.code);
                try {
                    DecodedWindowsEvent gap{{{"reason", "native_log_source_refused"}, {"stage", error.what()}, {"native_error", error.code},
                        {"saved_checkpoint_preserved", true}, {"lost_native_events", nullptr}}, std::nullopt};
                    (void)accept(worker, stop, gap, true, source, "", 0, records, gaps, refusals);
                    status(worker, has_checkpoint ? "blind" : "unavailable", error.what(), error.code);
                } catch (...) {}
                pause(stop, 30000);
            } catch (const std::exception& error) {
                status(worker, has_checkpoint ? "blind" : "unavailable", error.what()); pause(stop, 30000);
            } catch (...) {
                status(worker, "blind", "unclassified log worker failure"); pause(stop, 30000);
            }
        }
        { std::scoped_lock lock{worker.mutex}; worker.health["worker_stopped"] = true;
          worker.health["last_source_state"] = worker.health["state"];
          worker.health["last_source_reason"] = worker.health["reason"];
          worker.health["state"] = "disabled"; worker.health["reason"] = "collection stopped by endpoint shutdown"; }
        notify();
    }
};
WindowsEventLog::WindowsEventLog(WindowsLogCallbacks callbacks, std::vector<std::string> channels)
    : impl_(std::make_unique<Impl>(std::move(callbacks), std::move(channels))) {}
WindowsEventLog::~WindowsEventLog() = default;
void WindowsEventLog::stop() { impl_->stop(); }
nlohmann::json WindowsEventLog::snapshot() const {
    Json channels = Json::array();
    for (const auto& worker : impl_->workers) { std::scoped_lock lock{worker->mutex}; channels.push_back(worker->health); }
    return {{"state", "degraded"}, {"channels", std::move(channels)}, {"query", "*"}, {"checkpoint_namespace", "winevt:v1"},
        {"resume_mode", "strict_after_committed_bookmark_or_oldest_retained"}, {"channel_count", impl_->workers.size()},
        {"limitations", "retention continuity, audit/provider enablement, event semantics, attribution, deadlines and VM qualification pending"}};
}
std::vector<std::string> WindowsEventLog::default_channels() {
    return {"Security", "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell", "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-Windows Defender/Operational", "System", "Microsoft-Windows-DNS-Client/Operational"};
}
}
