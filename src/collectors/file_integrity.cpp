#include "panopticon/officer/collectors/file_integrity.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <mutex>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>

namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;

class FimHandle {
public:
    explicit FimHandle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value) {}
    ~FimHandle() { if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_); }
    FimHandle(const FimHandle&) = delete;
    FimHandle& operator=(const FimHandle&) = delete;
    FimHandle(FimHandle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    FimHandle& operator=(FimHandle&& other) noexcept {
        if (this != &other) { if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_); value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE); }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] bool valid() const noexcept { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
private:
    HANDLE value_;
};

class FimFindHandle {
public:
    explicit FimFindHandle(HANDLE value) noexcept : value_(value) {}
    ~FimFindHandle() { if (value_ != INVALID_HANDLE_VALUE) FindClose(value_); }
    FimFindHandle(const FimFindHandle&) = delete;
    [[nodiscard]] HANDLE value() const noexcept { return value_; }
    [[nodiscard]] bool invalid() const noexcept { return value_ == INVALID_HANDLE_VALUE; }
private:
    HANDLE value_;
};

class FimSha256 {
public:
    FimSha256() {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA256) failed");
        try {
            DWORD object_bytes = 0, returned = 0;
            status = BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &returned, 0);
            if (status < 0 || returned != sizeof(object_bytes) || object_bytes == 0) throw std::runtime_error("BCrypt SHA256 object size unavailable");
            object_.resize(object_bytes);
            status = BCryptCreateHash(algorithm_, &hash_, reinterpret_cast<PUCHAR>(object_.data()), object_bytes, nullptr, 0, 0);
            if (status < 0) throw std::runtime_error("BCryptCreateHash(SHA256) failed");
        } catch (...) { if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0); algorithm_ = nullptr; throw; }
    }
    ~FimSha256() { if (hash_) BCryptDestroyHash(hash_); if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0); }
    FimSha256(const FimSha256&) = delete;
    void update(const std::byte* bytes, ULONG count) {
        if (BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes)), count, 0) < 0)
            throw std::runtime_error("BCryptHashData(SHA256) failed");
    }
    [[nodiscard]] std::string finish() {
        std::array<unsigned char, 32> digest{};
        if (BCryptFinishHash(hash_, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
            throw std::runtime_error("BCryptFinishHash(SHA256) failed");
        constexpr char hex[] = "0123456789abcdef";
        std::string result; result.reserve(digest.size() * 2);
        for (auto b : digest) { result.push_back(hex[b >> 4]); result.push_back(hex[b & 15]); }
        return result;
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<unsigned char> object_;
};

[[nodiscard]] std::string fim_sha256_text(std::string_view text) {
    FimSha256 hash;
    hash.update(reinterpret_cast<const std::byte*>(text.data()), static_cast<ULONG>(text.size()));
    return hash.finish();
}

[[nodiscard]] std::wstring fim_wide(std::string_view value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) throw std::invalid_argument("configured FIM path is not valid UTF-8");
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), length) != length)
        throw std::invalid_argument("configured FIM path UTF-8 conversion failed");
    return result;
}

[[nodiscard]] std::string fim_utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) throw std::runtime_error("native path is not valid UTF-16");
    std::string result(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), length, nullptr, nullptr) != length)
        throw std::runtime_error("native path UTF-16 conversion failed");
    return result;
}

[[nodiscard]] std::wstring fim_full_path(const std::wstring& input) {
    if (input.size() < 3 || input[1] != L':' || (input[2] != L'\\' && input[2] != L'/'))
        throw std::invalid_argument("FIM roots must be absolute drive paths (for example C:\\Data)");
    const DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (!needed || needed > 32767) throw std::invalid_argument("FIM root path cannot be normalized");
    std::wstring result(needed, L'\0');
    const DWORD written = GetFullPathNameW(input.c_str(), needed, result.data(), nullptr);
    if (!written || written >= needed) throw std::invalid_argument("FIM root path normalization failed");
    result.resize(written);
    std::replace(result.begin(), result.end(), L'/', L'\\');
    while (result.size() > 3 && result.back() == L'\\') result.pop_back();
    return result;
}

[[nodiscard]] FimHandle fim_open_directory_no_reparse(const std::wstring& path) {
    return FimHandle{CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
}

[[nodiscard]] BY_HANDLE_FILE_INFORMATION fim_information(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) throw std::runtime_error("GetFileInformationByHandle failed");
    return info;
}

[[nodiscard]] bool fim_is_reparse(const BY_HANDLE_FILE_INFORMATION& info) noexcept {
    return (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

[[nodiscard]] std::string fim_identity(const BY_HANDLE_FILE_INFORMATION& info) {
    const auto index = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    return std::to_string(info.dwVolumeSerialNumber) + ":" + std::to_string(index);
}

[[nodiscard]] std::wstring fim_final_path(HANDLE handle) {
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0, flags);
    if (!needed || needed > 32767) throw std::runtime_error("GetFinalPathNameByHandleW size query failed");
    std::wstring result(needed, L'\0');
    const DWORD written = GetFinalPathNameByHandleW(handle, result.data(), needed, flags);
    if (!written || written >= needed) throw std::runtime_error("GetFinalPathNameByHandleW failed");
    result.resize(written);
    while (result.size() > 1 && result.back() == L'\\') result.pop_back();
    return result;
}

[[nodiscard]] bool fim_path_equal(std::wstring_view left, std::wstring_view right) noexcept {
    return left.size() == right.size() && CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
        right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

[[nodiscard]] bool fim_is_direct_child_path(std::wstring_view root, std::wstring_view candidate) noexcept {
    if (candidate.size() <= root.size() + 1 || !fim_path_equal(candidate.substr(0, root.size()), root)
        || candidate[root.size()] != L'\\') return false;
    return candidate.substr(root.size() + 1).find_first_of(L"\\/") == std::wstring_view::npos;
}

[[nodiscard]] bool fim_root_matches(HANDLE root, const std::string& expected_identity, std::wstring_view expected_path) {
    const auto info = fim_information(root);
    return (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && !fim_is_reparse(info)
        && fim_identity(info) == expected_identity && fim_path_equal(fim_final_path(root), expected_path);
}

[[nodiscard]] std::uint64_t fim_file_size(const BY_HANDLE_FILE_INFORMATION& info) noexcept {
    return (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
}

[[nodiscard]] std::uint64_t fim_filetime(const FILETIME& value) noexcept {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

// Verify each configured-root component by opening it itself, with the final
// object opened as a reparse point. This prevents root admission from silently
// crossing a junction/symlink in the path supplied by configuration.
[[nodiscard]] std::tuple<FimHandle, std::string, std::wstring> fim_validate_root(const std::wstring& root) {
    std::wstring current = root.substr(0, 3);
    auto drive = fim_open_directory_no_reparse(current);
    if (!drive.valid()) throw std::runtime_error("configured FIM drive root cannot be opened");
    auto drive_info = fim_information(drive.get());
    if ((drive_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || fim_is_reparse(drive_info))
        throw std::runtime_error("configured FIM drive root is not a plain directory");
    FimHandle latest = std::move(drive);
    if (root.size() > 3) {
        std::size_t begin = 3;
        while (begin < root.size()) {
            const auto end = root.find(L'\\', begin);
            const auto part_end = end == std::wstring::npos ? root.size() : end;
            if (part_end == begin) throw std::invalid_argument("configured FIM root contains an empty path component");
            current = current + root.substr(begin, part_end - begin);
            auto component = fim_open_directory_no_reparse(current);
            if (!component.valid()) throw std::runtime_error("configured FIM root component cannot be opened");
            const auto info = fim_information(component.get());
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || fim_is_reparse(info))
                throw std::runtime_error("configured FIM root crosses a reparse point or non-directory");
            latest = std::move(component);
            if (end == std::wstring::npos) break;
            current.push_back(L'\\');
            begin = end + 1;
        }
    }
    const auto root_info = fim_information(latest.get());
    auto final_path = fim_final_path(latest.get());
    return {std::move(latest), fim_identity(root_info), std::move(final_path)};
}

[[nodiscard]] bool fim_safe_relative(std::wstring_view value, std::size_t max_bytes) {
    if (value.empty() || value.front() == L'\\' || value.front() == L'/') return false;
    if (value.find_first_of(L"\\/") != std::wstring_view::npos) return false;
    try { if (fim_utf8(value).size() > max_bytes) return false; } catch (...) { return false; }
    std::size_t begin = 0;
    while (begin <= value.size()) {
        const auto end = value.find_first_of(L"\\/", begin);
        const auto stop = end == std::wstring_view::npos ? value.size() : end;
        const auto part = value.substr(begin, stop - begin);
        if (part.empty() || part == L"." || part == L".." || part.find(L':') != std::wstring_view::npos) return false;
        if (end == std::wstring_view::npos) break;
        begin = end + 1;
    }
    return true;
}

[[nodiscard]] Json fim_file_observation(HANDLE root_handle, const std::string& root_identity,
    std::wstring_view root_final_path, HANDLE file_handle, std::uint64_t& hash_budget,
    const FileIntegrityLimits& limits) {
    if (!fim_root_matches(root_handle, root_identity, root_final_path))
        return {{"state", "degraded"}, {"reason", "configured_root_identity_or_path_changed"}, {"path_refused", true}};
    const auto candidate_final = fim_final_path(file_handle);
    if (!fim_is_direct_child_path(root_final_path, candidate_final))
        return {{"state", "degraded"}, {"reason", "candidate_resolved_outside_configured_root"}, {"path_refused", true}};
    const auto current = fim_information(file_handle);
    if (fim_is_reparse(current)) return {{"state", "degraded"}, {"reason", "reparse_point_skipped"}, {"file_identity", fim_identity(current)}};
    const auto size = fim_file_size(current);
    Json result{{"state", "healthy"}, {"file_identity", fim_identity(current)},
        {"attributes", std::to_string(current.dwFileAttributes)}, {"size_bytes", std::to_string(size)},
        {"last_write_filetime", std::to_string(fim_filetime(current.ftLastWriteTime))},
        {"directory", (current.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0}, {"sha256", nullptr},
        {"hash_state", "not_attempted"}, {"hash_bytes_read", "0"}};
    if ((current.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) { result["hash_state"] = "directory"; return result; }
    if (size > limits.maximum_file_hash_bytes) { result["hash_state"] = "file_size_bound_exceeded"; return result; }
    if (size > hash_budget) { result["hash_state"] = "total_hash_byte_budget_exceeded"; return result; }
    try {
        FimSha256 hash;
        std::array<std::byte, 64 * 1024> buffer{};
        std::uint64_t remaining = size;
        while (remaining != 0) {
            if (!fim_root_matches(root_handle, root_identity, root_final_path)
                || !fim_is_direct_child_path(root_final_path, fim_final_path(file_handle))) {
                result["state"] = "degraded"; result["hash_state"] = "root_or_candidate_path_changed_before_read";
                result["path_refused"] = true;
                return result;
            }
            const auto want = static_cast<DWORD>(std::min<std::uint64_t>(buffer.size(), remaining));
            DWORD received = 0;
            if (!ReadFile(file_handle, buffer.data(), want, &received, nullptr) || received == 0)
                throw std::runtime_error("bounded file read failed or ended early");
            hash.update(buffer.data(), received); remaining -= received; hash_budget -= received;
            result["hash_bytes_read"] = std::to_string(std::stoull(result["hash_bytes_read"].get<std::string>()) + received);
        }
        const auto after = fim_information(file_handle);
        if (fim_identity(after) != fim_identity(current) || fim_file_size(after) != size
            || fim_filetime(after.ftLastWriteTime) != fim_filetime(current.ftLastWriteTime)
            || !fim_root_matches(root_handle, root_identity, root_final_path)
            || !fim_is_direct_child_path(root_final_path, fim_final_path(file_handle))) {
            result["state"] = "degraded"; result["hash_state"] = "file_or_path_changed_during_hash";
            if (!fim_root_matches(root_handle, root_identity, root_final_path)
                || !fim_is_direct_child_path(root_final_path, fim_final_path(file_handle))) result["path_refused"] = true;
        } else {
            result["sha256"] = hash.finish(); result["hash_state"] = "sha256_complete";
        }
    } catch (const std::exception& error) {
        result["state"] = "degraded"; result["hash_state"] = "unavailable"; result["hash_error"] = error.what();
    }
    return result;
}

[[nodiscard]] std::wstring fim_join(const std::wstring& root, std::wstring_view relative) {
    return root + L"\\" + std::wstring(relative);
}
}

struct FileIntegritySensor::Impl {
    struct Worker {
        std::wstring root_wide;
        std::wstring root_final_path;
        std::string root_utf8;
        std::string root_identity;
        std::string source;
        FimHandle root_handle;
        mutable std::mutex mutex;
        Json health;
        std::jthread thread;
        Worker(std::wstring root, std::wstring final_path, std::string utf8, std::string identity, FimHandle handle)
            : root_wide(std::move(root)), root_final_path(std::move(final_path)), root_utf8(std::move(utf8)), root_identity(std::move(identity)),
              source("file-integrity:v1:" + fim_sha256_text(root_utf8)), root_handle(std::move(handle)),
              health{{"root", root_utf8}, {"root_identity", root_identity}, {"source", source},
                  {"state", "unavailable"}, {"reason", "not_started"}, {"baseline_candidates", "0"},
                  {"notification_batches", "0"}, {"notification_candidates", "0"}, {"gaps", "0"},
                  {"malformed_buffers", "0"}, {"overflow_buffers", "0"}, {"commit_refusals", "0"},
                  {"path_refusals", "0"},
                  {"hash_bytes", "0"}, {"source_failures", "0"}, {"checkpoint_revision", "0"},
                  {"pending_durable_acceptance", false}, {"lost_native_events", nullptr},
                  {"full_file_coverage_verified", false},
                  {"counter_scope", "collector object lifetime; interrupted or pre-acceptance candidates are unknown"}}
        {}
    };

    FileIntegrityCallbacks callbacks;
    FileIntegrityLimits limits;
    std::vector<std::unique_ptr<Worker>> workers;
    bool disabled = false;
    Json configuration;

    Impl(std::vector<std::string> roots, FileIntegrityCallbacks cb, FileIntegrityLimits bounds)
        : callbacks(std::move(cb)), limits(bounds), disabled(roots.empty()),
          configuration{{"configured_roots", roots.size()}, {"state", roots.empty() ? "disabled" : "degraded"},
              {"reason", roots.empty() ? "no_roots_configured" : "validating_explicit_roots"},
              {"maximum_roots", limits.maximum_roots}} {
        if (roots.empty()) return;
        if (!callbacks.load || !callbacks.make_record || !callbacks.commit)
            throw std::invalid_argument("FIM durable acceptance callbacks are required when roots are configured");
        if (roots.size() > limits.maximum_roots || limits.maximum_roots == 0 || limits.maximum_baseline_candidates == 0
            || limits.maximum_candidates_per_batch == 0 || limits.maximum_relative_path_bytes == 0
            || limits.maximum_relative_path_bytes > 32767 || limits.native_buffer_bytes < 4096
            || limits.native_buffer_bytes > 64 * 1024 || limits.maximum_file_hash_bytes == 0
            || limits.maximum_total_hash_bytes == 0)
            throw std::invalid_argument("invalid FIM resource bounds");
        std::set<std::wstring> unique;
        for (const auto& raw : roots) {
            auto root = fim_full_path(fim_wide(raw));
            if (!unique.insert(root).second) throw std::invalid_argument("duplicate configured FIM root");
            auto [handle, identity, final_path] = fim_validate_root(root);
            const auto utf8 = fim_utf8(root);
            workers.push_back(std::make_unique<Worker>(std::move(root), std::move(final_path), utf8, identity, std::move(handle)));
        }
        configuration["state"] = "degraded";
        configuration["reason"] = "explicit_roots_validated; per-root baseline and watcher starting";
        for (auto& worker : workers)
            worker->thread = std::jthread{[this, item = worker.get()](std::stop_token stop) { run(*item, stop); }};
    }

    void notify() const noexcept { if (callbacks.changed) try { callbacks.changed(); } catch (...) {} }
    static void pause(std::stop_token stop, unsigned milliseconds) noexcept {
        for (unsigned elapsed = 0; elapsed < milliseconds && !stop.stop_requested(); elapsed += 50) Sleep(50);
    }

    void update(Worker& worker, const char* state, std::string reason, DWORD error = 0) noexcept {
        bool changed = false;
        try {
            std::scoped_lock lock{worker.mutex};
            changed = worker.health["state"] != state || worker.health["reason"] != reason
                || worker.health.value("native_error", 0u) != error;
            worker.health["state"] = state; worker.health["reason"] = std::move(reason);
            worker.health["native_error"] = error; worker.health["last_status_uptime_ms"] = std::to_string(GetTickCount64());
        } catch (...) {}
        if (changed) notify();
    }

    bool accept(Worker& worker, std::stop_token stop, Json body, bool gap,
        std::uint64_t& revision, std::uint64_t& sequence) {
        if (revision == UINT64_MAX || sequence == UINT64_MAX) throw std::runtime_error("FIM checkpoint counter exhausted");
        const auto next_sequence = sequence + 1;
        body["format"] = "windows_file_integrity_v1";
        body["root"] = worker.root_utf8; body["root_identity"] = worker.root_identity;
        body["source"] = worker.source; body["sequence"] = std::to_string(next_sequence);
        body["lost_native_events"] = gap ? Json(nullptr) : Json("not_reported_by_source");
        body["full_file_coverage_verified"] = false;
        Json cursor{{"format", "windows_file_integrity_cursor_v1"}, {"version", 1},
            {"root_identity", worker.root_identity}, {"sequence", std::to_string(next_sequence)}};
        const auto encoded = cursor.dump();
        body["source_checkpoint_expected_revision"] = std::to_string(revision);
        body["source_checkpoint_next_cursor"] = cursor;
        const auto immutable_record = callbacks.make_record(worker.root_utf8, std::move(body), gap);
        (void)Json::parse(immutable_record).at("record_id").get<std::string>();
        { std::scoped_lock lock{worker.mutex}; worker.health["pending_durable_acceptance"] = true; }
        while (!stop.stop_requested()) {
            bool accepted = false;
            try { accepted = callbacks.commit(immutable_record, worker.source, encoded, revision); } catch (...) {}
            if (accepted) {
                ++revision; sequence = next_sequence;
                { std::scoped_lock lock{worker.mutex}; worker.health["pending_durable_acceptance"] = false;
                  worker.health["checkpoint_revision"] = std::to_string(revision);
                  worker.health["accepted_sequence"] = std::to_string(sequence);
                  worker.health["last_durable_acceptance_uptime_ms"] = std::to_string(GetTickCount64());
                  if (gap) worker.health["gaps"] = std::to_string(std::stoull(worker.health["gaps"].get<std::string>()) + 1); }
                notify(); return true;
            }
            { std::scoped_lock lock{worker.mutex}; worker.health["commit_refusals"] = std::to_string(std::stoull(worker.health["commit_refusals"].get<std::string>()) + 1); }
            update(worker, "blind", "durable acceptance refused; immutable record pending and source sequence unchanged");
            pause(stop, 1000);
        }
        return false;
    }

    void process_batch(Worker& worker, std::stop_token stop, std::span<const std::byte> bytes,
        std::uint64_t& revision, std::uint64_t& sequence, std::uint64_t& hash_budget) {
        Json candidates = Json::array();
        std::size_t offset = 0, parsed = 0;
        std::uint64_t hash_bytes = 0;
        bool malformed = false, bound_exceeded = false;
        while (offset < bytes.size()) {
            if (++parsed > limits.maximum_candidates_per_batch) { bound_exceeded = true; break; }
            if (bytes.size() - offset < sizeof(FILE_NOTIFY_INFORMATION)) { malformed = true; break; }
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(bytes.data() + offset);
            if ((info->FileNameLength % sizeof(wchar_t)) != 0
                || info->FileNameLength > bytes.size() - offset - offsetof(FILE_NOTIFY_INFORMATION, FileName)) { malformed = true; break; }
            const std::wstring_view relative{info->FileName, info->FileNameLength / sizeof(wchar_t)};
            if (!fim_safe_relative(relative, limits.maximum_relative_path_bytes)) { malformed = true; break; }
            Json item{{"action", info->Action}, {"relative_path", fim_utf8(relative)},
                {"rename_pairing", info->Action == FILE_ACTION_RENAMED_OLD_NAME || info->Action == FILE_ACTION_RENAMED_NEW_NAME
                    ? "unresolved_native_old_or_new_name" : "not_applicable"},
                {"actor", nullptr}, {"process_attribution_verified", false}};
            if (!fim_root_matches(worker.root_handle.get(), worker.root_identity, worker.root_final_path))
                throw std::runtime_error("configured FIM root identity or final path changed before change capture");
            const auto full = fim_join(worker.root_wide, relative);
            FimHandle candidate{CreateFileW(full.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
            if (!candidate.valid()) item["current_object"] = {{"state", "degraded"}, {"reason", "candidate_open_failed"}, {"native_error", GetLastError()}};
            else {
                item["current_object"] = fim_file_observation(worker.root_handle.get(), worker.root_identity,
                    worker.root_final_path, candidate.get(), hash_budget, limits);
            }
            if (item.contains("current_object") && item["current_object"].is_object()
                && item["current_object"].value("path_refused", false)) {
                std::scoped_lock lock{worker.mutex}; worker.health["path_refusals"] = std::to_string(std::stoull(worker.health["path_refusals"].get<std::string>()) + 1);
            }
            if (item.contains("current_object") && item["current_object"].is_object() && item["current_object"].contains("hash_bytes_read"))
                hash_bytes += std::stoull(item["current_object"]["hash_bytes_read"].get<std::string>());
            candidates.push_back(std::move(item));
            if (info->NextEntryOffset == 0) { offset = bytes.size(); break; }
            if ((info->NextEntryOffset % alignof(DWORD)) != 0 || info->NextEntryOffset < offsetof(FILE_NOTIFY_INFORMATION, FileName)
                || info->NextEntryOffset > bytes.size() - offset) { malformed = true; break; }
            offset += info->NextEntryOffset;
        }
        const auto candidate_count = candidates.size();
        Json body{{"phase", "change_batch"}, {"candidates", std::move(candidates)},
            {"candidate_count", parsed > 0 ? parsed - (malformed ? 1 : 0) : 0}, {"native_buffer_bytes", bytes.size()},
            {"candidate_bound_exceeded", bound_exceeded}, {"malformed_buffer", malformed},
            {"rename_semantics", "old_and_new names are reported independently; pairing is uncertain"}};
        if (malformed) {
            std::scoped_lock lock{worker.mutex}; worker.health["malformed_buffers"] = std::to_string(std::stoull(worker.health["malformed_buffers"].get<std::string>()) + 1);
        }
        { std::scoped_lock lock{worker.mutex}; worker.health["hash_bytes"] = std::to_string(std::stoull(worker.health["hash_bytes"].get<std::string>()) + hash_bytes); }
        if (bound_exceeded || malformed) body["loss_reason"] = bound_exceeded ? "candidate_count_bound_exceeded; remainder_unknown" : "malformed_notification_buffer; remainder_unknown";
        if (!body["candidates"].empty() || bound_exceeded || malformed) {
            if (!accept(worker, stop, std::move(body), bound_exceeded || malformed, revision, sequence)) return;
            std::scoped_lock lock{worker.mutex};
            worker.health["notification_batches"] = std::to_string(std::stoull(worker.health["notification_batches"].get<std::string>()) + 1);
            worker.health["notification_candidates"] = std::to_string(std::stoull(worker.health["notification_candidates"].get<std::string>()) + candidate_count);
        }
    }

    bool baseline(Worker& worker, std::stop_token stop, std::uint64_t& revision, std::uint64_t& sequence,
        std::uint64_t& hash_budget) {
        struct Dir { std::wstring path; std::wstring relative; };
        std::vector<Dir> stack{{worker.root_wide, L""}};
        std::size_t candidates = 0;
        while (!stack.empty() && !stop.stop_requested()) {
            auto current_dir = std::move(stack.back()); stack.pop_back();
            if (!fim_root_matches(worker.root_handle.get(), worker.root_identity, worker.root_final_path))
                throw std::runtime_error("configured FIM root identity or final path changed before baseline enumeration");
            const auto search_path = current_dir.path + L"\\*";
            WIN32_FIND_DATAW found{};
            FimFindHandle find{FindFirstFileW(search_path.c_str(), &found)};
            if (find_handle_invalid(find)) {
                const DWORD error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) continue;
                throw std::runtime_error("bounded FIM baseline directory enumeration failed");
            }
            do {
                if (stop.stop_requested()) return false;
                if (wcscmp(found.cFileName, L".") == 0 || wcscmp(found.cFileName, L"..") == 0) continue;
                if ((found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
                const std::wstring relative = current_dir.relative.empty() ? found.cFileName : current_dir.relative + L"\\" + found.cFileName;
                if (!fim_safe_relative(relative, limits.maximum_relative_path_bytes)) {
                    Json refused{{"phase", "baseline_candidate"}, {"relative_path", nullptr}, {"state", "degraded"},
                        {"reason", "relative_path_bound_or_format_refused"}, {"full_file_coverage_verified", false}};
                    if (!accept(worker, stop, std::move(refused), true, revision, sequence)) return false;
                    continue;
                }
                if (++candidates > limits.maximum_baseline_candidates) {
                    Json gap{{"phase", "baseline_gap"}, {"reason", "baseline_candidate_count_bound_exceeded"},
                        {"candidates_seen", std::to_string(candidates - 1)}, {"remaining_root_candidates_unknown", true}};
                    if (!accept(worker, stop, std::move(gap), true, revision, sequence)) return false;
                    return true;
                }
                const auto child_path = current_dir.path + L"\\" + found.cFileName;
                if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    auto directory_check = fim_open_directory_no_reparse(child_path);
                    if (!directory_check.valid()) continue;
                    const auto directory_info = fim_information(directory_check.get());
                    if (fim_is_reparse(directory_info) || (directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
                }
                FimHandle child{CreateFileW(child_path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
                if (!child.valid()) {
                    Json failed{{"phase", "baseline_candidate"}, {"relative_path", fim_utf8(relative)},
                        {"state", "degraded"}, {"reason", "candidate_open_failed"}, {"native_error", GetLastError()}};
                    if (!accept(worker, stop, std::move(failed), false, revision, sequence)) return false;
                    continue;
                }
                Json row{{"phase", "baseline_candidate"}, {"relative_path", fim_utf8(relative)},
                    {"current_object", fim_file_observation(worker.root_handle.get(), worker.root_identity,
                        worker.root_final_path, child.get(), hash_budget, limits)},
                    {"baseline_is_atomic", false}};
                if (row["current_object"].is_object() && row["current_object"].value("path_refused", false)) {
                    std::scoped_lock lock{worker.mutex}; worker.health["path_refusals"] = std::to_string(std::stoull(worker.health["path_refusals"].get<std::string>()) + 1);
                }
                { std::scoped_lock lock{worker.mutex}; worker.health["hash_bytes"] = std::to_string(std::stoull(worker.health["hash_bytes"].get<std::string>())
                    + std::stoull(row["current_object"].value("hash_bytes_read", std::string{"0"}))); }
                if (!accept(worker, stop, std::move(row), false, revision, sequence)) return false;
                { std::scoped_lock lock{worker.mutex}; worker.health["baseline_candidates"] = std::to_string(candidates); }
            } while (FindNextFileW(find_handle_value(find), &found));
            const auto error = GetLastError();
            if (error != ERROR_NO_MORE_FILES && error != ERROR_FILE_NOT_FOUND)
                throw std::runtime_error("FIM baseline iteration did not finish cleanly");
        }
        return !stop.stop_requested();
    }

    // Accessors kept private to this translation unit to make the RAII handle
    // non-copyable and avoid leaking the raw FindFirstFile handle into callers.
    static HANDLE find_handle_value(const FimFindHandle& handle) noexcept { return handle.value(); }
    static bool find_handle_invalid(const FimFindHandle& handle) noexcept { return handle.invalid(); }

    void run(Worker& worker, std::stop_token stop) noexcept {
        FimHandle change_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        // Reopen the already validated directory object by handle so a path
        // replacement cannot redirect the watcher after root admission.
        FimHandle watch{ReOpenFile(worker.root_handle.get(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED)};
        if (!change_event.valid() || !watch.valid()) {
            update(worker, "unavailable", "ReadDirectoryChangesW source could not be opened", GetLastError());
            return;
        }
        try {
            if (fim_identity(fim_information(watch.get())) != worker.root_identity
                || !fim_root_matches(worker.root_handle.get(), worker.root_identity, worker.root_final_path))
                throw std::runtime_error("configured FIM root identity changed before watcher opened");
        } catch (const std::exception& error) { update(worker, "blind", error.what(), GetLastError()); return; }
        std::uint64_t revision = 0, sequence = 0;
        std::vector<std::byte> buffer;
        OVERLAPPED overlapped{}; overlapped.hEvent = change_event.get();
        bool request_pending = false;
        auto drain_request = [&]() noexcept {
            if (!request_pending) return;
            (void)CancelIoEx(watch.get(), &overlapped);
            DWORD ignored = 0;
            (void)GetOverlappedResult(watch.get(), &overlapped, &ignored, TRUE);
            request_pending = false;
        };
        try {
            const auto saved = callbacks.load(worker.source);
            if (saved) {
                revision = saved->revision;
                const auto previous = Json::parse(saved->value);
                if (!previous.is_object() || previous.value("format", std::string{}) != "windows_file_integrity_cursor_v1"
                    || previous.value("version", 0) != 1 || !previous.contains("root_identity")
                    || !previous["root_identity"].is_string())
                    throw std::runtime_error("invalid FIM checkpoint format or version");
                const bool same_root = previous["root_identity"].get<std::string>() == worker.root_identity;
                if (same_root) {
                    if (!previous.contains("sequence") || !previous["sequence"].is_string())
                        throw std::runtime_error("invalid FIM checkpoint sequence");
                    const auto encoded_sequence = previous["sequence"].get<std::string>();
                    if (encoded_sequence.empty() || encoded_sequence.find_first_not_of("0123456789") != std::string::npos)
                        throw std::runtime_error("invalid FIM checkpoint sequence encoding");
                    sequence = std::stoull(encoded_sequence);
                }
                Json gap{{"phase", "source_gap"}, {"reason", same_root ? "worker_restart_changes_may_have_been_missed" : "configured_root_identity_changed"},
                    {"previous_checkpoint", saved->value}, {"native_overflow_or_restart_loss", nullptr}, {"current_root_identity", worker.root_identity}};
                if (!accept(worker, stop, std::move(gap), true, revision, sequence)) return;
            }

            buffer.resize(limits.native_buffer_bytes);
            auto arm = [&]() -> bool {
                if (request_pending) return false;
                ResetEvent(change_event.get());
                overlapped.Offset = 0; overlapped.OffsetHigh = 0; overlapped.Internal = 0; overlapped.InternalHigh = 0;
                if (ReadDirectoryChangesW(watch.get(), buffer.data(), static_cast<DWORD>(buffer.size()), FALSE,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
                    nullptr, &overlapped, nullptr)) { request_pending = true; return true; }
                const DWORD error = GetLastError();
                if (error == ERROR_IO_PENDING) { request_pending = true; return true; }
                update(worker, "blind", "ReadDirectoryChangesW request failed", error);
                return false;
            };
            if (!arm()) throw std::runtime_error("ReadDirectoryChangesW could not arm");
            update(worker, "degraded", "direct-child watcher armed; bounded baseline is non-atomic and may reveal gaps");
            auto hash_budget = limits.maximum_total_hash_bytes;
            if (!baseline(worker, stop, revision, sequence, hash_budget)) {
                drain_request();
                update(worker, "disabled", "endpoint_shutdown_during_baseline; unaccepted candidates remain unknown");
                return;
            }
            while (!stop.stop_requested()) {
                const DWORD wait = WaitForSingleObject(change_event.get(), 1000);
                if (wait == WAIT_TIMEOUT) continue;
                if (wait != WAIT_OBJECT_0) throw std::runtime_error("ReadDirectoryChangesW wait failed");
                DWORD returned = 0;
                const BOOL completed_ok = GetOverlappedResult(watch.get(), &overlapped, &returned, FALSE);
                request_pending = false; // The signaled request is terminal, on success or error.
                if (!completed_ok) {
                    const DWORD error = GetLastError();
                    if (error == ERROR_OPERATION_ABORTED && stop.stop_requested()) break;
                    if (error != ERROR_NOTIFY_ENUM_DIR) throw std::runtime_error("ReadDirectoryChangesW completion failed");
                    if (!arm()) throw std::runtime_error("ReadDirectoryChangesW rearm after overflow failed");
                    { std::scoped_lock lock{worker.mutex}; worker.health["overflow_buffers"] = std::to_string(std::stoull(worker.health["overflow_buffers"].get<std::string>()) + 1); }
                    Json gap{{"phase", "source_gap"}, {"reason", "ReadDirectoryChangesW_native_buffer_overflow"},
                        {"lost_native_events", nullptr}, {"buffer_bytes", limits.native_buffer_bytes}, {"rescan_started", true}};
                    if (!accept(worker, stop, std::move(gap), true, revision, sequence)) break;
                    hash_budget = limits.maximum_total_hash_bytes;
                    if (!baseline(worker, stop, revision, sequence, hash_budget)) break;
                    continue;
                } else if (returned == 0) {
                    if (!arm()) throw std::runtime_error("ReadDirectoryChangesW rearm after empty completion failed");
                    { std::scoped_lock lock{worker.mutex}; worker.health["overflow_buffers"] = std::to_string(std::stoull(worker.health["overflow_buffers"].get<std::string>()) + 1); }
                    Json gap{{"phase", "source_gap"}, {"reason", "ReadDirectoryChangesW_zero_byte_completion_overflow_or_unknown_loss"},
                        {"lost_native_events", nullptr}, {"buffer_bytes", limits.native_buffer_bytes}, {"rescan_started", true}};
                    if (!accept(worker, stop, std::move(gap), true, revision, sequence)) break;
                    hash_budget = limits.maximum_total_hash_bytes;
                    if (!baseline(worker, stop, revision, sequence, hash_budget)) break;
                    continue;
                } else {
                    { std::scoped_lock lock{worker.mutex}; worker.health["last_notification_uptime_ms"] = std::to_string(GetTickCount64()); }
                    // Copy the bounded native buffer, then rearm before any
                    // file reads or durable callback can stall the worker.
                    std::vector<std::byte> completed(buffer.begin(), buffer.begin() + std::min<std::size_t>(returned, buffer.size()));
                    request_pending = false;
                    if (!arm()) throw std::runtime_error("ReadDirectoryChangesW rearm failed");
                    hash_budget = limits.maximum_total_hash_bytes;
                    process_batch(worker, stop, std::span<const std::byte>{completed}, revision, sequence, hash_budget);
                }
            }
        } catch (const std::exception& error) {
            { std::scoped_lock lock{worker.mutex}; worker.health["source_failures"] = std::to_string(std::stoull(worker.health["source_failures"].get<std::string>()) + 1); }
            update(worker, "blind", error.what(), GetLastError());
        } catch (...) { update(worker, "blind", "unknown file integrity worker failure"); }
        // Keep OVERLAPPED and its buffer alive through cancellation completion
        // on normal stop, callback exceptions, and native source failures.
        drain_request();
        update(worker, stop.stop_requested() ? "disabled" : "blind",
            stop.stop_requested() ? "endpoint_shutdown; unaccepted candidates remain unknown" : "worker_stopped_after_source_failure");
    }
};

FileIntegritySensor::FileIntegritySensor(std::vector<std::string> roots, FileIntegrityCallbacks callbacks, FileIntegrityLimits limits)
    : impl_(std::make_unique<Impl>(std::move(roots), std::move(callbacks), limits)) {}
FileIntegritySensor::~FileIntegritySensor() { stop(); }
void FileIntegritySensor::stop() noexcept {
    if (!impl_) return;
    for (auto& worker : impl_->workers) if (worker->thread.joinable()) worker->thread.request_stop();
    for (auto& worker : impl_->workers) if (worker->thread.joinable()) worker->thread.join();
}
nlohmann::json FileIntegritySensor::snapshot() const {
    Json roots = Json::array(); bool active = false, blind = false, all_disabled = !impl_->workers.empty();
    for (const auto& worker : impl_->workers) {
        std::scoped_lock lock{worker->mutex}; auto health = worker->health;
        active |= health.value("state", "") == "degraded"; blind |= health.value("state", "") == "blind";
        all_disabled &= health.value("state", "") == "disabled";
        roots.push_back(std::move(health));
    }
    const char* state = impl_->disabled ? "disabled" : active ? "degraded" : blind ? "blind" : all_disabled ? "disabled" : "unavailable";
    return {{"state", state}, {"configuration", impl_->configuration}, {"roots", std::move(roots)},
        {"full_file_coverage_verified", false},
        {"scope", "only direct children of configured drive roots; nested directories are not traversed; reparse points skipped"},
        {"resource_scope", "at most configured roots workers; 64 KiB maximum native notification buffer per worker; bounded baseline candidates and hash reads; Win32 calls, hashing and stop joins have no hard deadline"}};
}

} // namespace panopticon::officer::collectors
