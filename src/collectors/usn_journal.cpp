#include "panopticon/officer/collectors/usn_journal.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <array>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <atomic>
#include <iterator>
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

constexpr std::size_t kMaximumVolumes = 16;
constexpr char kDiscoverySource[] = "usn:volume-discovery:v1";
constexpr char kDiscoveryChannel[] = "Windows-Volume-Discovery";
struct VolumeDiscovery {
    std::vector<std::string> volumes;
    bool complete = false;
    bool bound_exceeded = false;
    DWORD error = ERROR_SUCCESS;
};
struct DiscoveryCheckpoint {
    std::uint64_t sequence = 0;
    bool initialized = false;
    bool blind = false;
    std::vector<std::string> volumes;
    std::string blind_start_record_id;
};
VolumeDiscovery discover_volumes() {
    VolumeDiscovery result;
    std::array<wchar_t, 1024> name{};
    HANDLE search = FindFirstVolumeW(name.data(), static_cast<DWORD>(name.size()));
    if (search == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }
    try {
        for (;;) {
            const auto end = std::find(name.begin(), name.end(), L'\0');
            if (end == name.end()) { result.error = ERROR_INVALID_DATA; break; }
            std::string ascii;
            for (auto it = name.begin(); it != end; ++it) {
                if (*it > 127) { result.error = ERROR_INVALID_DATA; break; }
                ascii += static_cast<char>(*it);
            }
            if (result.error != ERROR_SUCCESS) break;
            result.volumes.push_back(volume_name(std::move(ascii)));
            if (result.volumes.size() > kMaximumVolumes) {
                result.volumes.pop_back(); result.bound_exceeded = true; result.error = ERROR_MORE_DATA; break;
            }
            name.fill(L'\0');
            if (!FindNextVolumeW(search, name.data(), static_cast<DWORD>(name.size()))) {
                const auto error = GetLastError();
                result.complete = error == ERROR_NO_MORE_FILES;
                if (!result.complete) result.error = error;
                break;
            }
        }
    } catch (...) { FindVolumeClose(search); throw; }
    FindVolumeClose(search);
    std::sort(result.volumes.begin(), result.volumes.end());
    return result;
}
Json discovery_checkpoint_json(const DiscoveryCheckpoint& checkpoint) {
    return {{"format", "windows_usn_discovery_checkpoint_v1"},
        {"sequence", std::to_string(checkpoint.sequence)}, {"initialized", checkpoint.initialized},
        {"blind", checkpoint.blind}, {"volumes", checkpoint.volumes},
        {"blind_start_record_id", checkpoint.blind_start_record_id.empty() ? Json(nullptr) : Json(checkpoint.blind_start_record_id)}};
}
std::uint64_t canonical_u64(const Json& value, const char* name) {
    if (!value.is_string()) throw std::invalid_argument(std::string("discovery checkpoint ") + name + " must be a string");
    const auto& text = value.get_ref<const std::string&>();
    std::uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (text.empty() || (text.size() > 1 && text.front() == '0') || error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument(std::string("invalid discovery checkpoint ") + name);
    return parsed;
}
DiscoveryCheckpoint decode_discovery_checkpoint(const std::string& encoded) {
    if (encoded.size() > 8192) throw std::invalid_argument("USN discovery checkpoint bound exceeded");
    const auto data = Json::parse(encoded);
    if (!data.is_object() || data.size() != 6 || data.value("format", "") != "windows_usn_discovery_checkpoint_v1" ||
        !data.at("initialized").is_boolean() || !data.at("blind").is_boolean() || !data.at("volumes").is_array() || data.at("volumes").size() > kMaximumVolumes)
        throw std::invalid_argument("unsupported USN discovery checkpoint shape");
    DiscoveryCheckpoint result;
    result.sequence = canonical_u64(data.at("sequence"), "sequence");
    result.initialized = data.at("initialized").get<bool>(); result.blind = data.at("blind").get<bool>();
    for (const auto& item : data.at("volumes")) {
        if (!item.is_string()) throw std::invalid_argument("USN discovery checkpoint volume is not a string");
        auto normalized = volume_name(item.get<std::string>());
        if (!result.volumes.empty() && normalized <= result.volumes.back()) throw std::invalid_argument("USN discovery checkpoint volumes are not strictly ordered");
        result.volumes.push_back(std::move(normalized));
    }
    const auto& marker = data.at("blind_start_record_id");
    if (!marker.is_null()) {
        if (!marker.is_string() || marker.get_ref<const std::string&>().size() > 256) throw std::invalid_argument("invalid USN discovery blind marker");
        result.blind_start_record_id = marker.get<std::string>();
    }
    if (!result.blind && !result.blind_start_record_id.empty()) throw std::invalid_argument("non-blind checkpoint retains a blind marker");
    return result;
}
}
struct UsnJournal::Impl {
    struct Worker {
        std::string volume, source;
        std::atomic_bool removal_requested{false};
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
    mutable std::mutex workers_mutex;
    mutable std::mutex discovery_mutex;
    Json discovery{{"state", "unavailable"}, {"scope", "bounded native volume GUID rediscovery every 30 seconds"},
        {"enumeration_complete", false}, {"bound_exceeded", false}, {"native_error", nullptr},
        {"last_successful_enumeration_uptime_ms", nullptr}, {"unknown_interval_start_record_id", nullptr},
        {"durable_transition_sequence", "0"}, {"active_volume_count", "0"}};
    std::jthread discovery_thread;
    std::atomic_bool stopped{false};
    bool automatic_discovery = false;
    explicit Impl(UsnCallbacks cb, std::vector<std::string> volumes) : callbacks(std::move(cb)) {
        if (!callbacks.load || !callbacks.make_record || !callbacks.commit) throw std::invalid_argument("USN callbacks required");
        automatic_discovery = volumes.empty();
        if (automatic_discovery) {
            discovery_thread = std::jthread{[this](std::stop_token stop) { rediscover(stop); }};
            return;
        }
        if (volumes.size() > kMaximumVolumes) throw std::invalid_argument("USN volume admission bound");
        discovery["scope"] = "explicit selected native volume GUIDs; no all-volume coverage or hotplug rediscovery";
        discovery["state"] = "degraded";
        discovery["enumeration_complete"] = false;
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
    bool publish_discovery(const VolumeDiscovery& scan, std::stop_token stop) {
        std::optional<delivery::SourceCheckpoint> stored;
        try { stored = callbacks.load(kDiscoverySource); }
        catch (...) { return false; }
        DiscoveryCheckpoint previous;
        try { if (stored) previous = decode_discovery_checkpoint(stored->value); }
        catch (...) {
            { std::scoped_lock lock{discovery_mutex};
              discovery["state"] = "blind"; discovery["reason"] = "durable discovery checkpoint malformed; no volume set changes applied"; }
            notify(); return false;
        }
        DiscoveryCheckpoint next = previous;
        Json added = Json::array(), removed = Json::array();
        const bool failed = !scan.complete || scan.bound_exceeded;
        std::string transition;
        std::string reason;
        if (failed) {
            if (!previous.blind) {
                transition = "discovery_unavailable_interval_started";
                reason = scan.bound_exceeded ? "native volume enumeration exceeded the 16-volume admission bound" : "native volume enumeration failed; current set is unknown";
                next.blind = true;
            }
        } else if (previous.blind) {
            transition = "discovery_recovered_after_unknown_interval";
            reason = "volume presence and changes during the recorded discovery-blind interval are unknown";
            std::set_difference(scan.volumes.begin(), scan.volumes.end(), previous.volumes.begin(), previous.volumes.end(), std::back_inserter(added));
            std::set_difference(previous.volumes.begin(), previous.volumes.end(), scan.volumes.begin(), scan.volumes.end(), std::back_inserter(removed));
            next.initialized = true; next.blind = false; next.volumes = scan.volumes; next.blind_start_record_id.clear();
        } else if (!previous.initialized) {
            transition = "initial_volume_set_observed";
            reason = "no prior durable volume inventory; historical volume presence and changes are unknown";
            next.initialized = true; next.blind = false; next.volumes = scan.volumes; next.blind_start_record_id.clear();
            for (const auto& volume : scan.volumes) added.push_back(volume);
        } else if (scan.volumes != previous.volumes) {
            transition = "volume_set_changed";
            reason = "bounded native volume GUID set changed between complete enumerations";
            std::set_difference(scan.volumes.begin(), scan.volumes.end(), previous.volumes.begin(), previous.volumes.end(), std::back_inserter(added));
            std::set_difference(previous.volumes.begin(), previous.volumes.end(), scan.volumes.begin(), scan.volumes.end(), std::back_inserter(removed));
            next.volumes = scan.volumes;
        }
        if (transition.empty()) return true;
        if (previous.sequence == UINT64_MAX || (stored && stored->revision == UINT64_MAX)) {
            { std::scoped_lock lock{discovery_mutex};
              discovery["state"] = "blind"; discovery["reason"] = "durable discovery sequence or revision exhausted"; }
            notify(); return false;
        }
        next.sequence = previous.sequence + 1;
        const auto expected_revision = stored ? stored->revision : 0;
        Json body{{"format", "windows_usn_volume_discovery_v1"}, {"transition", transition}, {"reason", reason},
            {"source", kDiscoverySource}, {"sequence", std::to_string(next.sequence)},
            {"previous_volume_set", previous.volumes}, {"current_volume_set", failed ? Json(nullptr) : Json(scan.volumes)},
            {"added_volume_guids", std::move(added)}, {"removed_volume_guids", std::move(removed)},
            {"unknown_interval_start_record_id", previous.blind_start_record_id.empty() ? Json(nullptr) : Json(previous.blind_start_record_id)},
            {"native_error", failed ? Json(std::to_string(scan.error ? scan.error : ERROR_MORE_DATA)) : Json(nullptr)},
            {"enumeration_complete", scan.complete}, {"bound_exceeded", scan.bound_exceeded},
            {"maximum_volume_count", kMaximumVolumes}, {"observed_uptime_ms", std::to_string(GetTickCount64())},
            {"per_volume_checkpoints_reset", false}, {"source_state", "volume presence during unknown intervals is not reconstructable"}};
        const auto line = callbacks.make_record(kDiscoveryChannel, std::move(body), true);
        const auto record_id = Json::parse(line).at("record_id").get<std::string>();
        if (failed && !previous.blind_start_record_id.size()) next.blind_start_record_id = record_id;
        const auto encoded = discovery_checkpoint_json(next).dump();
        while (!stop.stop_requested()) {
            bool accepted = false;
            try { accepted = callbacks.commit(line, kDiscoverySource, encoded, expected_revision); } catch (...) {}
            if (accepted) {
                std::scoped_lock lock{discovery_mutex};
                discovery["durable_transition_sequence"] = std::to_string(next.sequence);
                discovery["last_transition_record_id"] = record_id;
                discovery["unknown_interval_start_record_id"] = next.blind_start_record_id.empty() ? Json(nullptr) : Json(next.blind_start_record_id);
                return true;
            }
            { std::scoped_lock lock{discovery_mutex}; discovery["pending_durable_acceptance"] = true; discovery["state"] = "blind"; }
            notify(); pause(stop, 1000);
        }
        return false;
    }
    void update_discovery_snapshot(const VolumeDiscovery& scan, bool durable, const char* reason = nullptr) {
        std::scoped_lock lock{discovery_mutex};
        discovery["enumeration_complete"] = scan.complete;
        discovery["bound_exceeded"] = scan.bound_exceeded;
        discovery["native_error"] = scan.error == ERROR_SUCCESS ? Json(nullptr) : Json(std::to_string(scan.error));
        discovery["last_attempt_uptime_ms"] = std::to_string(GetTickCount64());
        if (scan.complete && !scan.bound_exceeded && durable) {
            discovery["state"] = "degraded"; // Any inventory-only source is less than continuous file coverage.
            discovery["reason"] = "volume enumeration durable; each admitted volume has an independent journal worker";
            discovery["last_successful_enumeration_uptime_ms"] = std::to_string(GetTickCount64());
            discovery["active_volume_count"] = std::to_string(scan.volumes.size());
            discovery["observed_volume_guids"] = scan.volumes;
            discovery["pending_durable_acceptance"] = false;
        } else {
            discovery["state"] = "blind";
            discovery["reason"] = reason ? reason : (scan.bound_exceeded ? "native volume discovery bound exceeded; volume set is incomplete" : "native volume enumeration unavailable or discovery transition not durable");
            discovery["pending_durable_acceptance"] = !durable;
        }
        notify();
    }
    void sync_workers(const std::vector<std::string>& volumes) {
        const std::set<std::string> present(volumes.begin(), volumes.end());
        std::vector<Worker*> stopping;
        {
            std::scoped_lock lock{workers_mutex};
            for (auto& worker : workers) if (!present.contains(worker->volume) && worker->thread.joinable()) {
                worker->removal_requested.store(true);
                worker->thread.request_stop(); stopping.push_back(worker.get());
            }
        }
        for (auto* worker : stopping) if (worker->thread.joinable()) worker->thread.join();
        {
            std::scoped_lock lock{workers_mutex};
            workers.erase(std::remove_if(workers.begin(), workers.end(), [&](const auto& worker) { return !present.contains(worker->volume); }), workers.end());
            for (const auto& volume : volumes) {
                const auto found = std::find_if(workers.begin(), workers.end(), [&](const auto& worker) { return worker->volume == volume; });
                if (found != workers.end()) continue;
                auto worker = std::make_unique<Worker>(volume);
                auto* raw = worker.get();
                raw->thread = std::jthread{[this, raw](std::stop_token token) { run(*raw, token); }};
                workers.push_back(std::move(worker));
            }
        }
    }
    void rediscover(std::stop_token stop) noexcept {
        while (!stop.stop_requested()) {
            try {
                auto scan = discover_volumes();
                if (scan.complete && !scan.bound_exceeded) {
                    const auto durable = publish_discovery(scan, stop);
                    update_discovery_snapshot(scan, durable, durable ? nullptr : "discovery transition could not be durably accepted");
                    if (durable) sync_workers(scan.volumes);
                } else {
                    const auto durable = publish_discovery(scan, stop);
                    update_discovery_snapshot(scan, durable, "native volume enumeration incomplete; prior workers/checkpoints retained and current set unknown");
                }
            } catch (const std::exception& error) {
                VolumeDiscovery failed; failed.error = ERROR_INVALID_DATA;
                const auto durable = publish_discovery(failed, stop);
                update_discovery_snapshot(failed, durable, error.what());
            } catch (...) {
                VolumeDiscovery failed; failed.error = ERROR_GEN_FAILURE;
                const auto durable = publish_discovery(failed, stop);
                update_discovery_snapshot(failed, durable, "unknown native volume discovery failure");
            }
            pause(stop, 30000);
        }
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
        status(w, "disabled", w.removal_requested.load() ?
            "volume_removed_by_native_rediscovery; durable per-volume checkpoint retained; changes during absence/unknown discovery interval may be missed" :
            "endpoint_shutdown; historical checkpoints retained");
    }
};
UsnJournal::UsnJournal(UsnCallbacks cb, std::vector<std::string> volumes) : impl_(std::make_unique<Impl>(std::move(cb), std::move(volumes))) {}
UsnJournal::~UsnJournal() { stop(); }
void UsnJournal::stop() {
    if (impl_->stopped.exchange(true)) return;
    if (impl_->discovery_thread.joinable()) {
        impl_->discovery_thread.request_stop();
        impl_->discovery_thread.join();
    }
    std::vector<Impl::Worker*> workers;
    {
        std::scoped_lock lock{impl_->workers_mutex};
        for (auto& worker : impl_->workers) {
            worker->thread.request_stop(); workers.push_back(worker.get());
        }
    }
    for (auto* worker : workers) if (worker->thread.joinable()) worker->thread.join();
}
nlohmann::json UsnJournal::snapshot() const {
    Json volumes = Json::array(); bool active = false, blind = false, disabled = false;
    std::scoped_lock workers_lock{impl_->workers_mutex};
    disabled = !impl_->workers.empty();
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
    Json discovery;
    { std::scoped_lock lock{impl_->discovery_mutex}; discovery = impl_->discovery; }
    const auto discovery_state = discovery.value("state", std::string("unavailable"));
    return {{"state", (discovery_state == "blind" || discovery_state == "unavailable") ? "blind" :
            (active ? "degraded" : blind ? "blind" : disabled ? "disabled" : "unavailable")},
        {"volumes", std::move(volumes)}, {"discovery", std::move(discovery)}, {"full_file_coverage_verified", false},
        {"resource_scope", "at most 16 workers; native volume discovery every 30 seconds; 16 KiB USN buffers; bounded application copies; native calls, discovery commit retry and worker joins lack a hard deadline"}};
}
}
