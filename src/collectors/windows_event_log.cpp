#include "panopticon/officer/collectors/windows_event_log.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winevt.h>
#include <algorithm>
#include <charconv>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>
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
    Evt(Evt&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Evt& operator=(Evt&& other) noexcept {
        if (this != &other) { close(); value = std::exchange(other.value, nullptr); }
        return *this;
    }
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

std::uint64_t log_info_u64(EVT_HANDLE log, EVT_LOG_PROPERTY_ID property, EVT_VARIANT_TYPE expected) {
    EVT_VARIANT value{}; DWORD required = 0;
    if (!EvtGetLogInfo(log, property, sizeof(value), &value, &required))
        throw NativeError("EvtGetLogInfo", GetLastError());
    if (value.Type != expected) throw NativeError("EvtGetLogInfo unexpected property type", ERROR_INVALID_DATA);
    return expected == EvtVarTypeFileTime ? value.FileTimeVal : value.UInt64Val;
}

struct ChannelLogInfo {
    std::string generation;
    std::uint64_t oldest_record_id{};
    std::uint64_t record_count{};
    std::uint64_t newest_record_id{};
};
std::uint64_t native_event_record_id(EVT_HANDLE event);

ChannelLogInfo channel_log_info(const std::wstring& channel) {
    Evt log{EvtOpenLog(nullptr, channel.c_str(), EvtOpenChannelPath)};
    if (!log.value) throw NativeError("EvtOpenLog", GetLastError());
    const auto creation = log_info_u64(log.value, EvtLogCreationTime, EvtVarTypeFileTime);
    ChannelLogInfo result;
    result.generation = creation ? std::to_string(creation) : "unknown";
    result.record_count = log_info_u64(log.value, EvtLogNumberOfLogRecords, EvtVarTypeUInt64);
    result.oldest_record_id = log_info_u64(log.value, EvtLogOldestRecordNumber, EvtVarTypeUInt64);
    // Native record IDs can have holes: oldest + count - 1 is not the newest ID.
    // Using that estimate to detect regression falsely resets valid bookmarks.
    Evt query{EvtQuery(nullptr, channel.c_str(), L"*", EvtQueryChannelPath | EvtQueryReverseDirection)};
    if (!query.value) throw NativeError("EvtQuery newest record ID", GetLastError());
    EVT_HANDLE native = nullptr; DWORD count = 0;
    if (EvtNext(query.value, 1, &native, 1000, 0, &count)) {
        Evt event{native};
        if (count != 1 || !event.value) throw NativeError("EvtNext newest record count", ERROR_INVALID_DATA);
        result.newest_record_id = native_event_record_id(event.value);
    } else if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        throw NativeError("EvtNext newest record ID", GetLastError());
    }
    return result;
}

struct BookmarkCursor {
    bool versioned{};
    bool invalid{};
    std::string native_xml;
    std::string generation;
    std::uint64_t last_record_id{};
    bool last_record_id_known{};
};

BookmarkCursor decode_cursor(const std::string& value) {
    if (value.empty() || value.front() != '{') {
        BookmarkCursor legacy; legacy.native_xml = value; return legacy;
    }
    try {
        const auto json = Json::parse(value);
        if (!json.is_object() || json.value("format", std::string{}) != "panopticon_winevt_cursor_v2") {
            BookmarkCursor invalid; invalid.invalid = true; return invalid;
        }
        BookmarkCursor cursor;
        cursor.versioned = true;
        cursor.native_xml = json.at("bookmark_xml").get<std::string>();
        cursor.generation = json.at("log_generation").get<std::string>();
        cursor.last_record_id_known = json.at("last_record_id_known").get<bool>();
        if (cursor.last_record_id_known) {
            const auto& raw = json.at("last_record_id");
            const auto text = raw.get<std::string>();
            const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), cursor.last_record_id);
            if (error != std::errc{} || end != text.data() + text.size())
                throw std::runtime_error("invalid record ID in Event Log cursor");
        }
        return cursor;
    } catch (...) { BookmarkCursor invalid; invalid.invalid = true; return invalid; }
}

std::string encode_cursor(const std::string& bookmark, const ChannelLogInfo& log,
                          std::uint64_t last_record_id, bool last_record_id_known) {
    return Json{{"format", "panopticon_winevt_cursor_v2"}, {"bookmark_xml", bookmark},
        {"log_generation", log.generation}, {"oldest_record_id", std::to_string(log.oldest_record_id)},
        {"last_record_id", std::to_string(last_record_id)}, {"last_record_id_known", last_record_id_known}}.dump();
}

std::uint64_t native_event_record_id(EVT_HANDLE event) {
    // EventRecordID is an event value, not an EVT_EVENT_PROPERTY_ID.
    // Render only this scalar so the fixed buffer cannot contain string pointers.
    LPCWSTR paths[] = {L"Event/System/EventRecordID"};
    Evt context{EvtCreateRenderContext(1, paths, EvtRenderContextValues)};
    if (!context.value) throw NativeError("EvtCreateRenderContext record ID", GetLastError());
    EVT_VARIANT value{}; DWORD required = 0, count = 0;
    if (!EvtRender(context.value, event, EvtRenderEventValues, sizeof(value), &value, &required, &count))
        throw NativeError("EvtRender record ID", GetLastError());
    if (count != 1 || required != sizeof(value) || value.Type != EvtVarTypeUInt64)
        throw NativeError("EvtRender record ID type", ERROR_INVALID_DATA);
    return value.UInt64Val;
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
            {"audit_or_provider_policy_verified", false}, {"native_loss_count", nullptr},
            {"log_generation_gaps", "0"}, {"log_retention_gaps", "0"}, {"stale_bookmark_recoveries", "0"},
            {"legacy_cursor_migrations", "0"}, {"last_lifecycle_gap_reason", nullptr}} {}
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
        std::uint64_t generation_gaps = 0, retention_gaps = 0, stale_recoveries = 0, cursor_migrations = 0;
        bool startup_gap_accepted = false;
        bool force_reset_to_oldest = false;
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
                auto log_info = channel_log_info(channel);
                BookmarkCursor cursor = checkpoint ? decode_cursor(checkpoint->value) : BookmarkCursor{};
                const auto set_log_health = [&](const ChannelLogInfo& info) {
                    std::scoped_lock lock{worker.mutex};
                    worker.health["log_generation_id"] = info.generation;
                    worker.health["oldest_retained_record_id"] = info.oldest_record_id ? Json(std::to_string(info.oldest_record_id)) : Json(nullptr);
                    worker.health["retained_record_count"] = std::to_string(info.record_count);
                    worker.health["newest_retained_record_id"] = info.newest_record_id ? Json(std::to_string(info.newest_record_id)) : Json(nullptr);
                };
                set_log_health(log_info);
                const auto lifecycle_reason = [&](const BookmarkCursor& saved, const ChannelLogInfo& current) -> std::string {
                    if (force_reset_to_oldest) return "native_bookmark_stale_or_invalid";
                    if (saved.invalid) return "durable_cursor_invalid_reset_to_oldest";
                    if (!saved.versioned) return "legacy_bookmark_generation_unknown";
                    if (saved.generation != current.generation && saved.generation != "unknown" && current.generation != "unknown")
                        return "log_generation_changed_clear_or_recreate";
                    if (saved.generation != current.generation && (saved.generation == "unknown" || current.generation == "unknown"))
                        return "log_generation_identity_unavailable_or_changed";
                    if (saved.last_record_id_known && current.newest_record_id && current.newest_record_id < saved.last_record_id)
                        return "record_id_regressed_after_log_clear_or_recreate";
                    if (saved.last_record_id_known && current.oldest_record_id && saved.last_record_id <
                        std::numeric_limits<std::uint64_t>::max() && current.oldest_record_id > saved.last_record_id + 1)
                        return "retention_overwrote_records_after_checkpoint";
                    return {};
                };
                const auto commit_lifecycle_gap = [&](const std::string& reason, const ChannelLogInfo& current,
                                                       const BookmarkCursor& saved, bool preserve_bookmark) {
                    BookmarkCursor next;
                    next.versioned = true;
                    next.native_xml = preserve_bookmark ? saved.native_xml : std::string{};
                    next.generation = current.generation;
                    next.last_record_id = preserve_bookmark ? saved.last_record_id : 0;
                    next.last_record_id_known = preserve_bookmark && saved.last_record_id_known;
                    const auto next_cursor = encode_cursor(next.native_xml, current, next.last_record_id, next.last_record_id_known);
                    Json evidence{{"reason", reason}, {"channel", worker.channel},
                        {"previous_log_generation_id", saved.generation}, {"current_log_generation_id", current.generation},
                        {"previous_last_record_id", saved.last_record_id_known ? Json(std::to_string(saved.last_record_id)) : Json(nullptr)},
                        {"oldest_retained_record_id", current.oldest_record_id ? Json(std::to_string(current.oldest_record_id)) : Json(nullptr)},
                        {"newest_retained_record_id", current.newest_record_id ? Json(std::to_string(current.newest_record_id)) : Json(nullptr)},
                        {"retained_record_count", std::to_string(current.record_count)},
                        {"estimated_lost_record_ids", saved.last_record_id_known && saved.last_record_id < std::numeric_limits<std::uint64_t>::max() &&
                            current.oldest_record_id > saved.last_record_id + 1 ?
                            Json(std::to_string(current.oldest_record_id - saved.last_record_id - 1)) : Json(nullptr)},
                        {"lost_native_events", nullptr}, {"resume_policy", preserve_bookmark ? "strict_after_existing_native_bookmark" : "oldest_retained_record"},
                        {"checkpoint_revision", std::to_string(revision)}};
                    DecodedWindowsEvent lifecycle_gap{std::move(evidence), std::nullopt};
                    if (!accept(worker, stop, lifecycle_gap, true, source, next_cursor, revision, records, gaps, refusals)) return false;
                    ++revision;
                    checkpoint = delivery::SourceCheckpoint{revision, next_cursor};
                    cursor = std::move(next);
                    log_info = current;
                    force_reset_to_oldest = false;
                    startup_gap_accepted = true;
                    if (reason.find("retention") != std::string::npos) ++retention_gaps;
                    else if (reason == "legacy_bookmark_generation_unknown") ++cursor_migrations;
                    else if (reason.find("generation") != std::string::npos || reason.find("record_id_regressed") != std::string::npos) ++generation_gaps;
                    else ++stale_recoveries;
                    { std::scoped_lock lock{worker.mutex};
                      worker.health["log_generation_gaps"] = std::to_string(generation_gaps);
                      worker.health["log_retention_gaps"] = std::to_string(retention_gaps);
                      worker.health["stale_bookmark_recoveries"] = std::to_string(stale_recoveries);
                      worker.health["legacy_cursor_migrations"] = std::to_string(cursor_migrations);
                      worker.health["last_lifecycle_gap_reason"] = reason;
                        worker.health["continuity"] = reason == "legacy_bookmark_generation_unknown" ? "generation_bound" : "gap_recorded_and_resumed"; }
                    set_log_health(current);
                    return true;
                };
                if (checkpoint) {
                    const auto reason = lifecycle_reason(cursor, log_info);
                    if (!reason.empty() && !commit_lifecycle_gap(reason, log_info, cursor, reason == "legacy_bookmark_generation_unknown")) break;
                }

                Evt prior;
                if (!cursor.native_xml.empty()) {
                    const auto xml = widen(cursor.native_xml);
                    prior = Evt{EvtCreateBookmark(xml.c_str())};
                    if (!prior.value) throw NativeError("EvtCreateBookmark saved cursor", GetLastError());
                }
                Signal signal;
                if (!signal.value) throw NativeError("CreateEvent log signal", GetLastError());
                const bool resume_after_bookmark = !cursor.native_xml.empty();
                Evt subscription{EvtSubscribe(nullptr, signal.value, channel.c_str(), L"*", resume_after_bookmark ? prior.value : nullptr,
                    nullptr, nullptr, (resume_after_bookmark ? EvtSubscribeStartAfterBookmark : EvtSubscribeStartAtOldestRecord) | EvtSubscribeStrict)};
                if (!subscription.value) throw NativeError("EvtSubscribe strict", GetLastError());
                { std::scoped_lock lock{worker.mutex}; worker.health["resume_from_saved_checkpoint"] = checkpoint.has_value();
                  worker.health["resume_mode"] = resume_after_bookmark ? "strict_after_native_bookmark" : "oldest_retained_record";
                  worker.health["replay_draining"] = true; worker.health["subscription_started_uptime_ms"] = std::to_string(GetTickCount64()); }
                if (!startup_gap_accepted) {
                    DecodedWindowsEvent gap{{{"reason", checkpoint ? "bookmark_resumed_retention_continuity_unverified" : "history_before_oldest_retained_record_unknown"},
                        {"channel", worker.channel}, {"log_generation_id", log_info.generation},
                        {"oldest_retained_record_id", log_info.oldest_record_id ? Json(std::to_string(log_info.oldest_record_id)) : Json(nullptr)},
                        {"lost_native_events", nullptr}, {"checkpoint_revision", std::to_string(revision)}}, std::nullopt};
                    if (!accept(worker, stop, gap, true, source, "", revision, records, gaps, refusals)) break;
                    startup_gap_accepted = true;
                }
                status(worker, "degraded", "native pull subscription active; audit/provider policy and continuity unverified");
                auto next_log_check = GetTickCount64() + 5000;
                while (!stop.stop_requested()) {
                    if (GetTickCount64() >= next_log_check) {
                        const auto refreshed = channel_log_info(channel);
                        set_log_health(refreshed);
                        const auto reason = lifecycle_reason(cursor, refreshed);
                        if (!reason.empty()) {
                            if (!commit_lifecycle_gap(reason, refreshed, cursor, false)) break;
                            subscription.close();
                            break;
                        }
                        log_info = refreshed;
                        next_log_check = GetTickCount64() + 5000;
                    }
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
                    const auto record_id = native_event_record_id(event.value);
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
                    const bool record_id_regressed = cursor.last_record_id_known && record_id <= cursor.last_record_id;
                    if (record_id_regressed) {
                        decoded.data = {{"reason", "event_record_id_regressed_or_repeated_within_log_generation"},
                            {"channel", worker.channel}, {"log_generation_id", log_info.generation},
                            {"event_record_id", std::to_string(record_id)}, {"previous_record_id", std::to_string(cursor.last_record_id)},
                            {"unretained_delivered_bodies", "1"}, {"lost_native_events", nullptr}};
                        gap = true;
                    }
                    decoded.data["log_generation_id"] = log_info.generation;
                    decoded.data["event_record_id_native"] = std::to_string(record_id);
                    if (!gap && decoded.data.value("decode_state", "degraded") != "healthy") ++degraded;
                    { std::scoped_lock lock{worker.mutex}; worker.health["xml_not_retained_records"] = std::to_string(unretained);
                      worker.health["decode_degraded_records"] = std::to_string(degraded);
                      worker.health["last_native_record_id"] = decoded.data.value("event_record_id", Json(nullptr)); }
                    decoded.data["source_checkpoint_revision"] = std::to_string(revision + 1);
                    event.close(); next.close(); // No native event retained through WAL/quota backpressure.
                    const auto next_cursor = encode_cursor(next_xml, log_info, record_id, true);
                    if (!accept(worker, stop, decoded, gap, source, next_cursor, revision, records, gaps, refusals)) break;
                    ++revision;
                    cursor.versioned = true; cursor.invalid = false; cursor.native_xml = next_xml;
                    cursor.generation = log_info.generation; cursor.last_record_id = record_id; cursor.last_record_id_known = true;
                    checkpoint = delivery::SourceCheckpoint{revision, next_cursor};
                    status(worker, "degraded", "native pull subscription active; audit/provider policy and continuity unverified");
                }
            } catch (const NativeError& error) {
                { std::scoped_lock lock{worker.mutex}; worker.health["native_source_failures"] = std::to_string(++source_failures); }
                status(worker, has_checkpoint ? "blind" : "unavailable", error.what(), error.code);
                const bool stale_bookmark = error.code == ERROR_EVT_QUERY_RESULT_STALE || error.code == ERROR_EVT_QUERY_RESULT_INVALID_POSITION;
                if (stale_bookmark) {
                    force_reset_to_oldest = true;
                    { std::scoped_lock lock{worker.mutex}; worker.health["native_bookmark_stale"] = true; }
                    pause(stop, 1000);
                    continue;
                }
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
        {"limitations", "generation/retention discontinuities now emit durable gaps at source level; native loss ranges are estimates, and audit/provider enablement, event semantics, attribution, deadlines and VM qualification remain pending"}};
}
std::vector<std::string> WindowsEventLog::default_channels() {
    return {"Security", "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell", "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-Windows Defender/Operational", "System", "Microsoft-Windows-DNS-Client/Operational"};
}
}
