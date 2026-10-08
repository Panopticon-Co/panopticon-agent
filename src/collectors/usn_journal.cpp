#include "panopticon/officer/collectors/usn_journal.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <array>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
};
struct NativeError : std::runtime_error {
    DWORD code;
    NativeError(const char* api, DWORD error) : std::runtime_error(api), code(error) {}
};
std::string volume_name(std::string value) {
    if (value.size() != 49 || value.substr(0, 11) != "\\\\?\\Volume{" || value.substr(47) != "}\\")
        throw std::invalid_argument("USN source must be a native volume GUID path");
    for (std::size_t i = 11; i < 47; ++i) {
        const bool separator = i == 19 || i == 24 || i == 29 || i == 34;
        if (separator ? value[i] != '-' : !std::isxdigit(static_cast<unsigned char>(value[i])))
            throw std::invalid_argument("invalid USN volume GUID");
        value[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(value[i])));
    }
    return value;
}
std::wstring wide(const std::string& value) { return {value.begin(), value.end()}; }
std::string native_hex(std::span<const std::byte> data) {
    constexpr char digits[] = "0123456789abcdef"; std::string text;
    for (auto b : data) { const auto v = std::to_integer<unsigned>(b); text += digits[v >> 4]; text += digits[v & 15]; }
    return text;
}
USN_JOURNAL_DATA_V0 query(HANDLE volume) {
    USN_JOURNAL_DATA_V0 value{}; DWORD returned = 0;
    if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &value, sizeof(value), &returned, nullptr))
        throw NativeError("FSCTL_QUERY_USN_JOURNAL", GetLastError());
    if (returned < sizeof(value) || value.FirstUsn < 0 || value.LowestValidUsn < 0 || value.NextUsn < value.FirstUsn
        || value.NextUsn < value.LowestValidUsn) throw NativeError("invalid native USN journal bounds", ERROR_INVALID_DATA);
    return value;
}
Json journal_json(const USN_JOURNAL_DATA_V0& j) {
    return {{"journal_id", std::to_string(j.UsnJournalID)}, {"first_usn", std::to_string(j.FirstUsn)},
        {"lowest_valid_usn", std::to_string(j.LowestValidUsn)}, {"next_usn", std::to_string(j.NextUsn)},
        {"max_usn", std::to_string(j.MaxUsn)}, {"maximum_size", std::to_string(j.MaximumSize)},
        {"allocation_delta", std::to_string(j.AllocationDelta)}};
}
}
struct UsnJournal::Impl {
    struct Worker {
        std::string volume, source;
        mutable std::mutex mutex;
        Json health;
        std::jthread thread;
        explicit Worker(std::string name) : volume(std::move(name)), source("usn:v1:" + volume),
            health{{"volume", volume}, {"source", source}, {"state", "unavailable"}, {"reason", "not queried"},
                {"durable_batches", "0"}, {"durable_gaps", "0"}, {"commit_refusals", "0"},
                {"checkpoint_revision", "0"}, {"pending_durable_acceptance", false}, {"source_failures", "0"},
                {"counter_scope", "collector object lifetime; abrupt-exit unaccepted records unknown"}, {"lost_native_events", nullptr}} {}
    };
    UsnCallbacks callbacks;
    std::vector<std::unique_ptr<Worker>> workers;
    Json discovery{{"state", "degraded"}, {"scope", "at most 16 native volume GUIDs discovered at startup; hotplug rediscovery not implemented"},
        {"enumeration_complete", false}, {"bound_exceeded", false}, {"native_error", nullptr}};
    explicit Impl(UsnCallbacks cb, std::vector<std::string> volumes) : callbacks(std::move(cb)) {
        if (!callbacks.load || !callbacks.make_record || !callbacks.commit) throw std::invalid_argument("USN callbacks required");
        if (volumes.empty()) {
            std::array<wchar_t, 1024> name{};
            HANDLE search = FindFirstVolumeW(name.data(), static_cast<DWORD>(name.size()));
            if (search == INVALID_HANDLE_VALUE) { discovery["state"] = "unavailable"; discovery["native_error"] = std::to_string(GetLastError()); }
            else {
                try {
                    for (;;) {
                        const auto end = std::find(name.begin(), name.end(), L'\0');
                        if (end == name.end()) throw std::runtime_error("native volume name not terminated");
                        std::string ascii;
                        for (auto it = name.begin(); it != end; ++it) {
                            if (*it > 127) throw std::runtime_error("native volume GUID name is not ASCII");
                            ascii += static_cast<char>(*it);
                        }
                        volumes.push_back(std::move(ascii));
                        name.fill(L'\0');
                        if (!FindNextVolumeW(search, name.data(), static_cast<DWORD>(name.size()))) {
                            const auto error = GetLastError(); discovery["enumeration_complete"] = error == ERROR_NO_MORE_FILES;
                            if (error != ERROR_NO_MORE_FILES) discovery["native_error"] = std::to_string(error);
                            break;
                        }
                        if (volumes.size() == 16) { discovery["bound_exceeded"] = true; break; }
                    }
                } catch (...) { FindVolumeClose(search); throw; }
                FindVolumeClose(search);
            }
        } else { discovery["scope"] = "explicit selected native volume GUIDs; no all-volume coverage"; }
        if (volumes.size() > 16) throw std::invalid_argument("USN volume admission bound");
        std::set<std::string> unique;
        for (auto& volume : volumes) {
            auto normalized = volume_name(std::move(volume));
            if (!unique.insert(normalized).second) throw std::invalid_argument("duplicate USN volume source");
            workers.push_back(std::make_unique<Worker>(std::move(normalized)));
        }
        for (auto& item : workers) item->thread = std::jthread{[this, worker = item.get()](std::stop_token stop) { run(*worker, stop); }};
    }
    void notify() const { if (callbacks.changed) try { callbacks.changed(); } catch (...) {} }
    static void pause(std::stop_token stop, unsigned ms) {
        for (unsigned elapsed = 0; elapsed < ms && !stop.stop_requested(); elapsed += 50) Sleep(50);
    }
    void status(Worker& w, const char* state, const std::string& reason, DWORD error = 0) {
        bool changed;
        { std::scoped_lock lock{w.mutex}; changed = w.health["state"] != state || w.health["reason"] != reason || w.health.value("native_error", 0ul) != error;
          w.health["state"] = state; w.health["reason"] = reason; w.health["native_error"] = error;
          w.health["last_status_uptime_ms"] = std::to_string(GetTickCount64()); }
        if (changed) notify();
    }
    bool accept(Worker& w, std::stop_token stop, Json body, bool gap, UsnCursor cursor, std::uint64_t revision) {
        if (revision == UINT64_MAX) throw std::runtime_error("USN cursor revision exhausted");
        body["volume"] = w.volume; body["source"] = w.source;
        body["lost_native_events"] = nullptr; body["full_file_coverage_verified"] = false;
        const auto encoded = encode_usn_cursor(cursor);
        body["source_checkpoint_expected_revision"] = std::to_string(revision);
        body["source_checkpoint_next_cursor"] = Json::parse(encoded);
        const auto line = callbacks.make_record(w.volume, std::move(body), gap);
        const auto record_id = Json::parse(line).at("record_id").get<std::string>();
        { std::scoped_lock lock{w.mutex}; w.health["pending_durable_acceptance"] = true; }
        while (!stop.stop_requested()) {
            bool accepted = false;
            try { accepted = callbacks.commit(line, w.source, encoded, revision); } catch (...) {}
            if (accepted) {
                { std::scoped_lock lock{w.mutex}; w.health["pending_durable_acceptance"] = false;
                  const auto key = gap ? "durable_gaps" : "durable_batches";
                  w.health[key] = std::to_string(std::stoull(w.health[key].get<std::string>()) + 1);
                  w.health["checkpoint_revision"] = std::to_string(revision + 1);
                  w.health["committed_next_usn"] = std::to_string(cursor.next_usn);
                  w.health["journal_id"] = std::to_string(cursor.journal_id);
                  w.health["last_committed_record_id"] = record_id;
                  w.health["last_durable_acceptance_uptime_ms"] = std::to_string(GetTickCount64()); }
                notify(); return true;
            }
            { std::scoped_lock lock{w.mutex}; w.health["commit_refusals"] = std::to_string(std::stoull(w.health["commit_refusals"].get<std::string>()) + 1); }
            status(w, "blind", "durable acceptance refused; one immutable batch pending and source cursor unchanged");
            pause(stop, 1000);
        }
        return false;
    }
    void run(Worker& w, std::stop_token stop) noexcept {
        bool resumed = false;
        while (!stop.stop_requested()) {
            try {
                auto checkpoint = callbacks.load(w.source);
                auto revision = checkpoint ? checkpoint->revision : 0;
                UsnCursor cursor = checkpoint ? decode_usn_cursor(checkpoint->value) : UsnCursor{};
                auto native_volume = wide(w.volume); native_volume.pop_back();
                Handle volume{CreateFileW(native_volume.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, 0, nullptr)};
                if (volume.value == INVALID_HANDLE_VALUE) throw NativeError("CreateFile/native USN volume read", GetLastError());
                bool baseline = !checkpoint;
                while (!stop.stop_requested()) {
                    const auto current = query(volume.value);
                    { std::scoped_lock lock{w.mutex}; w.health["last_poll_uptime_ms"] = std::to_string(GetTickCount64());
                      w.health["native_journal"] = journal_json(current); w.health["checkpoint_revision"] = std::to_string(revision); }
                    std::string reason;
                    const auto first = std::max(current.FirstUsn, current.LowestValidUsn);
                    if (baseline) reason = "initial_cursor_at_current_tail_history_and_file_baseline_unobserved";
                    else if (cursor.journal_id != current.UsnJournalID) reason = "native_journal_instance_changed";
                    else if (cursor.next_usn < first) reason = "saved_cursor_before_retained_or_valid_journal_range";
                    else if (cursor.next_usn > current.NextUsn) reason = "saved_cursor_ahead_of_native_journal";
                    if (!reason.empty()) {
                        auto replacement = UsnCursor{current.UsnJournalID, baseline ? current.NextUsn : first};
                        Json gap{{"format", "windows_usn_gap_v1"}, {"reason", reason}, {"native_journal", journal_json(current)},
                            {"previous_cursor", baseline ? Json(nullptr) : Json::parse(encode_usn_cursor(cursor))},
                            {"replacement_cursor", Json::parse(encode_usn_cursor(replacement))}, {"event_boot_id", nullptr}};
                        if (!accept(w, stop, std::move(gap), true, replacement, revision)) break;
                        ++revision; cursor = replacement; baseline = false; resumed = true;
                    } else if (!resumed) {
                        Json gap{{"format", "windows_usn_gap_v1"}, {"reason", "saved_cursor_resumed_native_retention_and_volume_lifetime_unqualified"},
                            {"native_journal", journal_json(current)}, {"event_boot_id", nullptr}};
                        if (!accept(w, stop, std::move(gap), true, cursor, revision)) break;
                        ++revision; resumed = true;
                    }
                    READ_USN_JOURNAL_DATA_V1 request{};
                    request.StartUsn = cursor.next_usn; request.ReasonMask = UINT32_MAX;
                    request.UsnJournalID = cursor.journal_id; request.MinMajorVersion = 2; request.MaxMajorVersion = 3;
                    // Non-waiting journal read: BytesToWaitFor=0, Timeout=0,
                    // ReturnOnlyOnClose=0; no journal creation/policy mutation.
                    std::array<std::byte, 16384> buffer{}; DWORD returned = 0;
                    if (!DeviceIoControl(volume.value, FSCTL_READ_USN_JOURNAL, &request, sizeof(request), buffer.data(),
                        static_cast<DWORD>(buffer.size()), &returned, nullptr)) throw NativeError("FSCTL_READ_USN_JOURNAL", GetLastError());
                    if (returned < 8 || returned > buffer.size()) throw NativeError("USN native read length", ERROR_INVALID_DATA);
                    std::int64_t next = 0; std::memcpy(&next, buffer.data(), sizeof(next));
                    if (next < cursor.next_usn) throw NativeError("USN read cursor regression", ERROR_INVALID_DATA);
                    const auto span = std::span<const std::byte>{buffer}.first(returned);
                    Json data; bool decoded = true;
                    try {
                        data = decode_usn_buffer(span, cursor.next_usn);
                        decoded = data["uninterpreted_version_records"] == "0";
                        for (const auto& row : data["entries"]) decoded &= row["state"] == "healthy";
                    }
                    catch (const std::exception& error) {
                        decoded = false;
                        data = {{"format", "windows_usn_batch_v1"}, {"state", "blind"}, {"decoding_error", error.what()},
                            {"requested_start_usn", std::to_string(cursor.next_usn)}, {"next_usn", std::to_string(next)},
                            {"entries", Json::array()}, {"raw_native_buffer_hex", native_hex(span)}, {"full_native_buffer_retained", true},
                            {"native_buffer_bytes", returned}, {"process_attribution_verified", false}, {"event_boot_id", nullptr}};
                    }
                    const bool advanced = next != cursor.next_usn;
                    if (returned > 8 || advanced) {
                        data["journal_id"] = std::to_string(cursor.journal_id);
                        data["requested_record_versions"] = {2, 3}; data["other_native_versions_coverage"] = "unverified";
                        // Preserve a full native batch even when decoded expansion
                        // exceeds admission bounds; never silently advance/drop.
                        if (data.dump().size() > 512 * 1024) {
                            decoded = false; data.erase("entries"); data["entries"] = Json::array();
                            data["state"] = "blind"; data["decoding_error"] = "decoded_copy_bound_native_buffer_retained";
                        }
                        if (!accept(w, stop, std::move(data), false, {cursor.journal_id, next}, revision)) break;
                        ++revision; cursor.next_usn = next;
                    }
                    status(w, decoded ? "degraded" : "blind", decoded ?
                        "native USN fallback active; no actor/full-path/full-file/version-4/baseline coverage" : "native buffer retained; batch semantics uninterpreted");
                    pause(stop, 1000);
                }
            } catch (const NativeError& error) {
                { std::scoped_lock lock{w.mutex}; w.health["source_failures"] = std::to_string(std::stoull(w.health["source_failures"].get<std::string>()) + 1); }
                const char* state = error.code == ERROR_JOURNAL_NOT_ACTIVE ? "disabled" :
                    error.code == ERROR_INVALID_FUNCTION || error.code == ERROR_NOT_SUPPORTED ? "unsupported" : resumed ? "blind" : "unavailable";
                status(w, state, error.what(), error.code); pause(stop, 10000);
            } catch (const std::exception& error) {
                { std::scoped_lock lock{w.mutex}; w.health["source_failures"] = std::to_string(std::stoull(w.health["source_failures"].get<std::string>()) + 1); }
                status(w, "blind", error.what()); pause(stop, 10000);
            }
            catch (...) { status(w, "blind", "unknown USN worker failure"); pause(stop, 10000); }
        }
        status(w, "disabled", "endpoint_shutdown; historical checkpoints retained");
    }
};
UsnJournal::UsnJournal(UsnCallbacks cb, std::vector<std::string> volumes) : impl_(std::make_unique<Impl>(std::move(cb), std::move(volumes))) {}
UsnJournal::~UsnJournal() { stop(); }
void UsnJournal::stop() {
    for (auto& w : impl_->workers) w->thread.request_stop();
    for (auto& w : impl_->workers) if (w->thread.joinable()) w->thread.join();
}
nlohmann::json UsnJournal::snapshot() const {
    Json volumes = Json::array(); bool active = false, blind = false, disabled = !impl_->workers.empty();
    for (const auto& w : impl_->workers) {
        std::scoped_lock lock{w->mutex}; auto health = w->health;
        // A native call that stalls cannot leave its last sample apparently current.
        if (health["state"] == "degraded" && health.contains("last_poll_uptime_ms")
            && GetTickCount64() - std::stoull(health["last_poll_uptime_ms"].get<std::string>()) > 10000) {
            health["reported_state"] = health["state"]; health["state"] = "blind"; health["reason"] = "native USN source poll overdue";
        }
        active |= health["state"] == "degraded"; blind |= health["state"] == "blind";
        disabled &= health["state"] == "disabled";
        volumes.push_back(std::move(health));
    }
    return {{"state", active ? "degraded" : blind ? "blind" : disabled ? "disabled" : "unavailable"}, {"volumes", std::move(volumes)},
        {"discovery", impl_->discovery}, {"full_file_coverage_verified", false},
        {"resource_scope", "16 workers; 16 KiB native buffers; bounded application copies; native calls and stop joins lack a hard deadline"}};
}
}
