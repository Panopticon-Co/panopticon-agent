#include "panopticon/officer/response/file_evidence.hpp"
#include "panopticon/officer/core/entity_id.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <string_view>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace panopticon::officer::response {

namespace {

using nlohmann::json;

class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value) {}
    ~UniqueHandle() { if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
private:
    HANDLE value_;
};

std::optional<std::wstring> final_path(HANDLE handle) {
    const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (needed == 0 || needed > 32768) return std::nullopt;
    std::wstring path(static_cast<std::size_t>(needed), L'\0');
    const DWORD written = GetFinalPathNameByHandleW(handle, path.data(), needed, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (written == 0 || written >= needed) return std::nullopt;
    path.resize(written);
    return path;
}

bool path_is_within(std::wstring_view root, std::wstring_view candidate) {
    while (root.size() > 4 && (root.back() == L'\\' || root.back() == L'/')) root.remove_suffix(1);
    if (candidate.size() <= root.size() ||
        CompareStringOrdinal(root.data(), static_cast<int>(root.size()), candidate.data(),
                             static_cast<int>(root.size()), TRUE) != CSTR_EQUAL) return false;
    return candidate[root.size()] == L'\\' || candidate[root.size()] == L'/';
}

bool same_file_version(const BY_HANDLE_FILE_INFORMATION& left, const BY_HANDLE_FILE_INFORMATION& right) {
    return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
        left.nFileIndexHigh == right.nFileIndexHigh && left.nFileIndexLow == right.nFileIndexLow &&
        left.nFileSizeHigh == right.nFileSizeHigh && left.nFileSizeLow == right.nFileSizeLow &&
        left.ftLastWriteTime.dwHighDateTime == right.ftLastWriteTime.dwHighDateTime &&
        left.ftLastWriteTime.dwLowDateTime == right.ftLastWriteTime.dwLowDateTime;
}

class StringWiper {
public:
    explicit StringWiper(std::string& value) noexcept : value_(&value) {}
    ~StringWiper() {
        if (value_ && !value_->empty()) SecureZeroMemory(value_->data(), value_->size());
    }
    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;
    void release() noexcept { value_ = nullptr; }
private:
    std::string* value_;
};

std::optional<std::string> read_stable_file_under_root(const std::filesystem::path& root_path,
                                                       const std::filesystem::path& source_path,
                                                       std::uint64_t maximum_size,
                                                       std::string& evidence_path,
                                                       std::string& error) {
    UniqueHandle root{CreateFileW(root_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (root.get() == INVALID_HANDLE_VALUE) { error = "cannot hold allow-listed root"; return std::nullopt; }
    BY_HANDLE_FILE_INFORMATION root_info{};
    if (!GetFileInformationByHandle(root.get(), &root_info) ||
        (root_info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY) {
        error = "allow-listed root identity or type cannot be verified"; return std::nullopt;
    }
    const auto root_final = final_path(root.get());
    if (!root_final) { error = "cannot resolve held allow-listed root"; return std::nullopt; }

    UniqueHandle source{CreateFileW(source_path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (source.get() == INVALID_HANDLE_VALUE) { error = "cannot open requested file without write/delete sharing"; return std::nullopt; }
    BY_HANDLE_FILE_INFORMATION before{};
    if (!GetFileInformationByHandle(source.get(), &before) ||
        (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        error = "opened target is not a verifiable regular non-reparse file"; return std::nullopt;
    }
    if (before.nFileIndexHigh == 0 && before.nFileIndexLow == 0) {
        error = "filesystem did not provide a stable file identity"; return std::nullopt;
    }
    const auto opened_path = final_path(source.get());
    if (!opened_path || !path_is_within(*root_final, *opened_path)) {
        error = "opened file handle resolves outside the held allow-listed root"; return std::nullopt;
    }
    const int path_bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, opened_path->data(),
        static_cast<int>(opened_path->size()), nullptr, 0, nullptr, nullptr);
    if (path_bytes <= 0) { error = "opened file path is not valid Unicode"; return std::nullopt; }
    evidence_path.resize(static_cast<std::size_t>(path_bytes));
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, opened_path->data(), static_cast<int>(opened_path->size()),
                            evidence_path.data(), path_bytes, nullptr, nullptr) != path_bytes) {
        error = "cannot encode opened file path"; return std::nullopt;
    }
    const std::uint64_t size = (static_cast<std::uint64_t>(before.nFileSizeHigh) << 32U) | before.nFileSizeLow;
    if (size > maximum_size || size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        error = "file is too large to collect"; return std::nullopt;
    }
    std::string contents(static_cast<std::size_t>(size), '\0');
    StringWiper wipe_contents{contents};
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD request = static_cast<DWORD>(std::min<std::size_t>(contents.size() - offset, 1024U * 1024U));
        DWORD received = 0;
        if (!ReadFile(source.get(), contents.data() + offset, request, &received, nullptr) || received == 0) {
            error = "file changed or became unreadable during bounded handle read"; return std::nullopt;
        }
        offset += received;
    }
    char extra = 0;
    DWORD extra_bytes = 0;
    if (!ReadFile(source.get(), &extra, 1, &extra_bytes, nullptr) || extra_bytes != 0) {
        error = "file length changed during bounded handle read"; return std::nullopt;
    }
    BY_HANDLE_FILE_INFORMATION after{};
    const auto path_after = final_path(source.get());
    const auto root_path_after = final_path(root.get());
    if (!GetFileInformationByHandle(source.get(), &after) || !same_file_version(before, after) ||
        !path_after || *path_after != *opened_path || !root_path_after || *root_path_after != *root_final) {
        error = "file or root path, file identity, size, or modification time changed during handle read";
        return std::nullopt;
    }
    wipe_contents.release();
    return contents;
}

bool is_lexically_within(const std::filesystem::path& root, const std::filesystem::path& candidate) {
    auto root_it = root.begin();
    auto candidate_it = candidate.begin();
    for (; root_it != root.end(); ++root_it, ++candidate_it) {
        if (candidate_it == candidate.end() || *candidate_it != *root_it) return false;
    }
    return true;
}

}  // namespace

std::optional<std::filesystem::path> resolve_within_allowed_root(const std::filesystem::path& allowed_root,
                                                                   const std::filesystem::path& requested_path,
                                                                   std::string& error_message) {
    if (allowed_root.empty()) {
        error_message = "file collection root is not configured";
        return std::nullopt;
    }
    if (requested_path.empty() || requested_path.is_absolute()) {
        // The Manager-side contract only ever sends a path meant to be
        // interpreted relative to this agent's configured allow-listed
        // root -- an absolute path (which could point anywhere on the
        // filesystem) is rejected outright rather than "helpfully"
        // resolved.
        error_message = "requested path must be relative to the allow-listed root";
        return std::nullopt;
    }
    std::error_code root_error;
    const auto canonical_root = std::filesystem::weakly_canonical(allowed_root, root_error);
    if (root_error) {
        error_message = "allow-listed root cannot be resolved";
        return std::nullopt;
    }
    std::error_code candidate_error;
    const auto candidate = std::filesystem::weakly_canonical(canonical_root / requested_path, candidate_error);
    if (candidate_error || !is_lexically_within(canonical_root, candidate)) {
        error_message = "requested path escapes the allow-listed root";
        return std::nullopt;
    }
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(candidate, status_error);
    if (status_error || !std::filesystem::is_regular_file(status)) {
        error_message = "requested path is not a regular file";
        return std::nullopt;
    }
    return candidate;
}

std::optional<std::string> collect_file_evidence(const std::filesystem::path& allowed_root,
                                                   const std::filesystem::path& requested_path,
                                                   const std::size_t maximum_bytes, std::string& error_message) {
    const auto resolved = resolve_within_allowed_root(allowed_root, requested_path, error_message);
    if (!resolved) return std::nullopt;
    constexpr std::uintmax_t maximum_hashed_bytes = 16ULL * 1024ULL * 1024ULL;
    std::error_code canonical_root_error;
    const auto canonical_root = std::filesystem::weakly_canonical(allowed_root, canonical_root_error);
    if (canonical_root_error) {
        error_message = "allow-listed root cannot be resolved";
        return std::nullopt;
    }
    std::string evidence_path;
    auto contents = read_stable_file_under_root(canonical_root, *resolved,
                                                maximum_hashed_bytes, evidence_path, error_message);
    if (!contents) return std::nullopt;
    StringWiper wipe_contents{*contents};
    std::string hash_error;
    const auto hash = core::sha256_hex(*contents, hash_error);
    // contents (raw bytes) goes out of scope here and is never included
    // below -- only path/size/hash are evidence.
    if (!hash) {
        error_message = "cannot hash requested file: " + hash_error;
        return std::nullopt;
    }
    json document = {
        {"path", evidence_path},
        {"size", static_cast<std::uint64_t>(contents->size())},
        {"sha256", *hash},
    };
    auto serialized = document.dump();
    if (serialized.size() > maximum_bytes) {
        error_message = "file evidence exceeds limit";
        return std::nullopt;
    }
    return serialized;
}

namespace {

bool wide_to_utf8(const std::wstring_view value, std::string& output) {
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return false;
    output.resize(static_cast<std::size_t>(required));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                               output.data(), required, nullptr, nullptr) == required;
}

std::wstring append_leaf(std::wstring root, const std::wstring_view leaf) {
    if (!root.empty() && root.back() != L'\\' && root.back() != L'/') root.push_back(L'\\');
    root.append(leaf);
    return root;
}

bool destination_exists(const std::wstring& path, std::string& error) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    const DWORD failure = GetLastError();
    if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) return false;
    error = "cannot safely inspect quarantine destination (Windows error " + std::to_string(failure) + ")";
    return true;
}

bool lock_down_quarantined_handle(HANDLE file, std::string& error) {
    PSID owner = nullptr;
    PACL old_acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD query = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &old_acl, nullptr, &descriptor);
    if (query != ERROR_SUCCESS) {
        if (descriptor) LocalFree(descriptor);
        error = "cannot read owner and DACL from the held handle (Windows error " + std::to_string(query) + ")";
        return false;
    }
    if (!descriptor || !owner || !IsValidSid(owner)) {
        if (descriptor) LocalFree(descriptor);
        error = "held handle has no valid owner security descriptor";
        return false;
    }
    std::array<std::byte, SECURITY_MAX_SID_SIZE> everyone_storage{};
    std::array<std::byte, SECURITY_MAX_SID_SIZE> system_storage{};
    DWORD everyone_size = static_cast<DWORD>(everyone_storage.size());
    DWORD system_size = static_cast<DWORD>(system_storage.size());
    const bool sids_ok = CreateWellKnownSid(WinWorldSid, nullptr, everyone_storage.data(), &everyone_size) &&
                         CreateWellKnownSid(WinLocalSystemSid, nullptr, system_storage.data(), &system_size);
    if (!sids_ok) {
        LocalFree(descriptor);
        error = "cannot create quarantine security principals";
        return false;
    }
    const DWORD owner_size = GetLengthSid(owner);
    const DWORD everyone_sid_size = GetLengthSid(everyone_storage.data());
    const DWORD system_sid_size = GetLengthSid(system_storage.data());
    const std::size_t acl_bytes = sizeof(ACL) + (sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD)) + everyone_sid_size +
        2U * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + system_sid_size + owner_size;
    std::vector<std::byte> acl_storage(acl_bytes);
    auto* acl = reinterpret_cast<PACL>(acl_storage.data());
    bool built = InitializeAcl(acl, static_cast<DWORD>(acl_storage.size()), ACL_REVISION) &&
        AddAccessDeniedAceEx(acl, ACL_REVISION, NO_INHERITANCE,
            FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | WRITE_DAC | WRITE_OWNER, everyone_storage.data()) &&
        AddAccessAllowedAceEx(acl, ACL_REVISION, NO_INHERITANCE, FILE_GENERIC_READ, system_storage.data()) &&
        AddAccessAllowedAceEx(acl, ACL_REVISION, NO_INHERITANCE, FILE_GENERIC_READ, owner);
    if (!built) {
        const DWORD failure = GetLastError();
        LocalFree(descriptor);
        error = "cannot construct protected quarantine DACL (Windows error " + std::to_string(failure) + ")";
        return false;
    }
    const DWORD applied = SetSecurityInfo(file, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    LocalFree(descriptor);
    if (applied != ERROR_SUCCESS) {
        error = "cannot apply protected quarantine DACL to held source (Windows error " + std::to_string(applied) + ")";
        return false;
    }
    return true;
}

bool rename_handle_no_replace(HANDLE file, HANDLE destination_directory, const std::wstring_view leaf,
                              std::string& error) {
    const std::size_t name_bytes = leaf.size() * sizeof(wchar_t);
    const std::size_t total_bytes = offsetof(FILE_RENAME_INFO, FileName) + name_bytes;
    if (leaf.empty() || name_bytes > std::numeric_limits<DWORD>::max() || total_bytes > std::numeric_limits<DWORD>::max()) {
        error = "quarantine destination name is invalid or too long";
        return false;
    }
    std::vector<std::byte> storage(total_bytes);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    rename->RootDirectory = destination_directory;
    rename->FileNameLength = static_cast<DWORD>(name_bytes);
    std::memcpy(rename->FileName, leaf.data(), name_bytes);
    if (!SetFileInformationByHandle(file, FileRenameInfo, rename, static_cast<DWORD>(total_bytes))) {
        const DWORD failure = GetLastError();
        error = "same-volume no-clobber rename failed (Windows error " + std::to_string(failure) + ")";
        return false;
    }
    return true;
}

bool write_durable_file(HANDLE file, const std::string_view contents, std::string& error) {
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD amount = static_cast<DWORD>(std::min<std::size_t>(contents.size() - offset,
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD written = 0;
        if (!WriteFile(file, contents.data() + offset, amount, &written, nullptr) || written == 0) {
            const DWORD failure = GetLastError();
            error = "cannot write quarantine metadata (Windows error " + std::to_string(failure) + ")";
            return false;
        }
        offset += written;
    }
    if (!FlushFileBuffers(file)) {
        const DWORD failure = GetLastError();
        error = "cannot flush quarantine metadata (Windows error " + std::to_string(failure) + ")";
        return false;
    }
    return true;
}

bool delete_by_handle(HANDLE file) {
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    return SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
}

}  // namespace

std::optional<std::string> quarantine_file_and_serialize(const std::filesystem::path& allowed_root,
                                                           const std::filesystem::path& requested_path,
                                                           const std::filesystem::path& quarantine_root,
                                                           const std::size_t maximum_bytes,
                                                           std::string& error_message,
                                                           QuarantineOutcome* outcome) {
    if (outcome) *outcome = QuarantineOutcome{};
    error_message.clear();
    if (quarantine_root.empty()) {
        error_message = "quarantine root is not configured";
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }
    const auto resolved = resolve_within_allowed_root(allowed_root, requested_path, error_message);
    if (!resolved) {
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }

    std::error_code create_error;
    std::filesystem::create_directories(quarantine_root, create_error);
    if (create_error) {
        error_message = "cannot create quarantine root";
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }

    UniqueHandle source{CreateFileW(resolved->c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL |
        WRITE_DAC | DELETE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (source.get() == INVALID_HANDLE_VALUE) {
        const DWORD failure = GetLastError();
        error_message = "cannot hold source for safe quarantine (Windows error " + std::to_string(failure) + ")";
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }
    BY_HANDLE_FILE_INFORMATION source_info{};
    if (!GetFileInformationByHandle(source.get(), &source_info) ||
        (source_info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        (source_info.nFileIndexHigh == 0 && source_info.nFileIndexLow == 0)) {
        error_message = "held source is not a verifiable regular file with a stable identity";
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }
    const auto source_path = final_path(source.get());
    if (!source_path) {
        error_message = "cannot resolve held source path";
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }
    UniqueHandle collection_directory{CreateFileW(allowed_root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    BY_HANDLE_FILE_INFORMATION collection_info{};
    const auto collection_path = collection_directory.get() == INVALID_HANDLE_VALUE ? std::nullopt : final_path(collection_directory.get());
    if (collection_directory.get() == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(collection_directory.get(), &collection_info) ||
        (collection_info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY ||
        !collection_path || !path_is_within(*collection_path, *source_path)) {
        error_message = "held source or collection root failed reparse/path containment checks";
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }
    UniqueHandle destination_directory{CreateFileW(quarantine_root.c_str(), FILE_ADD_FILE | FILE_LIST_DIRECTORY |
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    BY_HANDLE_FILE_INFORMATION destination_info{};
    const auto destination_root_path = destination_directory.get() == INVALID_HANDLE_VALUE ? std::nullopt : final_path(destination_directory.get());
    if (destination_directory.get() == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(destination_directory.get(), &destination_info) ||
        (destination_info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY ||
        !destination_root_path) {
        const DWORD failure = GetLastError();
        error_message = "quarantine root is inaccessible, redirected, or a reparse point (Windows error " + std::to_string(failure) + ")";
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }
    if (source_info.dwVolumeSerialNumber != destination_info.dwVolumeSerialNumber) {
        error_message = "source and quarantine root are on different volumes; cross-volume quarantine is refused";
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }

    std::string source_utf8;
    if (!wide_to_utf8(*source_path, source_utf8)) {
        error_message = "held source path is not valid UTF-8";
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }
    const std::string identity_material = std::to_string(source_info.dwVolumeSerialNumber) + ":" +
        std::to_string(source_info.nFileIndexHigh) + ":" + std::to_string(source_info.nFileIndexLow);
    std::string name_error;
    const auto stored_name = core::sha256_hex(identity_material, name_error);
    if (!stored_name) {
        error_message = "cannot derive stable quarantine name: " + name_error;
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }
    const std::wstring stored_leaf = std::wstring(stored_name->begin(), stored_name->end()) + L".quarantined";
    const std::wstring metadata_leaf = std::wstring(stored_name->begin(), stored_name->end()) + L".json";
    const std::wstring pending_leaf = std::wstring(stored_name->begin(), stored_name->end()) + L".json.pending";
    const std::wstring stored_wide = append_leaf(*destination_root_path, stored_leaf);
    const std::wstring metadata_wide = append_leaf(*destination_root_path, metadata_leaf);
    const std::wstring pending_wide = append_leaf(*destination_root_path, pending_leaf);
    std::string stored_utf8;
    std::string metadata_utf8;
    if (!wide_to_utf8(stored_wide, stored_utf8) || !wide_to_utf8(metadata_wide, metadata_utf8)) {
        error_message = "quarantine destination path is not valid UTF-8";
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }
    if (outcome) {
        outcome->stored_path = stored_utf8;
        outcome->metadata_path = metadata_utf8;
    }
    std::string inspect_error;
    if (destination_exists(stored_wide, inspect_error) || destination_exists(metadata_wide, inspect_error) ||
        destination_exists(pending_wide, inspect_error)) {
        error_message = inspect_error.empty() ? "a no-clobber quarantine destination already exists" : inspect_error;
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }

    json metadata = {
        {"state", "quarantine_attempt"},
        {"original_path", source_utf8},
        {"stored_path", stored_utf8},
        {"source_volume_serial", source_info.dwVolumeSerialNumber},
        {"source_file_id", std::to_string(source_info.nFileIndexHigh) + ":" + std::to_string(source_info.nFileIndexLow)},
    };
    const std::string metadata_bytes = metadata.dump();
    json document = {
        {"state", "completed"},
        {"source_removed", true},
        {"destination_protected", true},
        {"stored_path", stored_utf8},
        {"metadata_path", metadata_utf8},
    };
    std::string serialized = document.dump();
    if (serialized.size() > maximum_bytes) {
        error_message = "quarantine result exceeds limit; no source mutation was made";
        if (outcome) { outcome->state = QuarantineState::refused; outcome->detail = error_message; }
        return std::nullopt;
    }

    UniqueHandle pending_metadata{CreateFileW(pending_wide.c_str(), GENERIC_WRITE | READ_CONTROL | WRITE_DAC | DELETE,
        FILE_SHARE_READ, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr)};
    if (pending_metadata.get() == INVALID_HANDLE_VALUE) {
        const DWORD failure = GetLastError();
        error_message = "cannot create unique quarantine metadata staging file (Windows error " + std::to_string(failure) + ")";
        if (outcome) { outcome->state = QuarantineState::failed; outcome->detail = error_message; }
        return std::nullopt;
    }
    if (!lock_down_quarantined_handle(pending_metadata.get(), error_message)) {
        const bool removed = delete_by_handle(pending_metadata.get());
        if (outcome) {
            outcome->state = removed ? QuarantineState::failed : QuarantineState::partial;
            outcome->detail = error_message;
        }
        return std::nullopt;
    }
    if (!write_durable_file(pending_metadata.get(), metadata_bytes, error_message)) {
        const bool removed = delete_by_handle(pending_metadata.get());
        if (outcome) {
            outcome->state = removed ? QuarantineState::failed : QuarantineState::partial;
            outcome->detail = error_message;
        }
        return std::nullopt;
    }
    if (!lock_down_quarantined_handle(source.get(), error_message)) {
        const bool removed = delete_by_handle(pending_metadata.get());
        if (outcome) {
            outcome->state = removed ? QuarantineState::failed : QuarantineState::partial;
            outcome->detail = error_message;
        }
        return std::nullopt;
    }
    if (outcome) {
        outcome->source_security_changed = true;
    }
    BY_HANDLE_FILE_INFORMATION source_after_acl{};
    const auto source_path_after_acl = final_path(source.get());
    if (!GetFileInformationByHandle(source.get(), &source_after_acl) ||
        !same_file_version(source_info, source_after_acl) || !source_path_after_acl || *source_path_after_acl != *source_path) {
        error_message = "source identity or path changed after quarantine protection; source remains at its original path";
        if (outcome) { outcome->state = QuarantineState::partial; outcome->detail = error_message; }
        delete_by_handle(pending_metadata.get());
        return std::nullopt;
    }
    if (!rename_handle_no_replace(source.get(), destination_directory.get(), stored_leaf, error_message)) {
        if (outcome) { outcome->state = QuarantineState::partial; outcome->detail = error_message; }
        delete_by_handle(pending_metadata.get());
        return std::nullopt;
    }
    if (outcome) {
        outcome->source_removed = true;
        outcome->destination_protected = true;
    }
    if (!rename_handle_no_replace(pending_metadata.get(), destination_directory.get(), metadata_leaf, error_message)) {
        if (outcome) { outcome->state = QuarantineState::partial; outcome->detail = error_message; }
        return std::nullopt;
    }
    if (outcome) {
        outcome->state = QuarantineState::completed;
        outcome->source_security_changed = true;
        outcome->source_removed = true;
        outcome->destination_protected = true;
        outcome->metadata_durable = true;
        outcome->stored_path = stored_utf8;
        outcome->metadata_path = metadata_utf8;
        outcome->detail = "source atomically renamed on the same volume; protected DACL and flushed metadata are present";
    }
    return serialized;
}

}  // namespace panopticon::officer::response
