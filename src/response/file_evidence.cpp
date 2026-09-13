#include "panopticon/officer/response/file_evidence.hpp"
#include "panopticon/officer/core/entity_id.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>

#include <nlohmann/json.hpp>

#include <fstream>

#pragma comment(lib, "advapi32.lib")

namespace panopticon::officer::response {

namespace {

using nlohmann::json;

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
    std::error_code size_error;
    const auto file_size = std::filesystem::file_size(*resolved, size_error);
    constexpr std::uintmax_t maximum_hashed_bytes = 16ULL * 1024ULL * 1024ULL;
    if (size_error || file_size > maximum_hashed_bytes) {
        error_message = "file is too large to collect";
        return std::nullopt;
    }
    std::ifstream input{*resolved, std::ios::binary};
    if (!input) {
        error_message = "cannot open requested file for hashing";
        return std::nullopt;
    }
    std::string contents(static_cast<std::size_t>(file_size), '\0');
    if (file_size != 0 && !input.read(contents.data(), static_cast<std::streamsize>(file_size))) {
        error_message = "cannot read requested file for hashing";
        return std::nullopt;
    }
    std::string hash_error;
    const auto hash = core::sha256_hex(contents, hash_error);
    // contents (raw bytes) goes out of scope here and is never included
    // below -- only path/size/hash are evidence.
    if (!hash) {
        error_message = "cannot hash requested file: " + hash_error;
        return std::nullopt;
    }
    json document = {
        {"path", resolved->generic_string()},
        {"size", static_cast<std::uint64_t>(file_size)},
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

// Denies Everyone execute/write/delete on the quarantined file so it cannot
// be re-run or tampered with in place -- the Windows-specific hardening
// step beyond a plain restrictive move.
bool lock_down_quarantined_file(const std::filesystem::path& path, std::string& error_message) {
    PSID everyone_sid = nullptr;
    SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&world_authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid)) {
        error_message = "cannot build Everyone SID for quarantine ACL";
        return false;
    }
    EXPLICIT_ACCESSW deny{};
    deny.grfAccessPermissions = FILE_GENERIC_EXECUTE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE;
    deny.grfAccessMode = DENY_ACCESS;
    deny.grfInheritance = NO_INHERITANCE;
    deny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    deny.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    deny.Trustee.ptstrName = reinterpret_cast<LPWSTR>(everyone_sid);

    PACL new_acl = nullptr;
    const DWORD build_result = SetEntriesInAclW(1, &deny, nullptr, &new_acl);
    if (build_result != ERROR_SUCCESS || new_acl == nullptr) {
        FreeSid(everyone_sid);
        error_message = "cannot build quarantine deny-ACL";
        return false;
    }
    const DWORD applied = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                                 DACL_SECURITY_INFORMATION, nullptr, nullptr, new_acl, nullptr);
    LocalFree(new_acl);
    FreeSid(everyone_sid);
    if (applied != ERROR_SUCCESS) {
        error_message = "cannot apply quarantine deny-ACL";
        return false;
    }
    return true;
}

}  // namespace

std::optional<std::string> quarantine_file_and_serialize(const std::filesystem::path& allowed_root,
                                                           const std::filesystem::path& requested_path,
                                                           const std::filesystem::path& quarantine_root,
                                                           const std::size_t maximum_bytes,
                                                           std::string& error_message) {
    if (quarantine_root.empty()) {
        error_message = "quarantine root is not configured";
        return std::nullopt;
    }
    const auto resolved = resolve_within_allowed_root(allowed_root, requested_path, error_message);
    if (!resolved) return std::nullopt;

    std::error_code create_error;
    std::filesystem::create_directories(quarantine_root, create_error);
    if (create_error) {
        error_message = "cannot create quarantine root";
        return std::nullopt;
    }
    std::string name_error;
    const auto stored_name = core::sha256_hex(resolved->generic_string(), name_error);
    if (!stored_name) {
        error_message = "cannot derive quarantine file name";
        return std::nullopt;
    }
    const auto stored_path = quarantine_root / (*stored_name + ".quarantined");
    const auto metadata_path = quarantine_root / (*stored_name + ".json");

    // MoveFileExW performs an atomic rename when both paths are on the same
    // volume (the common case for a configured allow-listed root and
    // quarantine root) and otherwise falls back to a non-atomic copy+delete
    // internally; MOVEFILE_COPY_ALLOWED opts into that fallback rather than
    // failing outright across volumes.
    if (!MoveFileExW(resolved->c_str(), stored_path.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        error_message = "cannot move requested file into quarantine";
        return std::nullopt;
    }
    std::string acl_error;
    if (!lock_down_quarantined_file(stored_path, acl_error)) {
        // The move already happened (the file is out of its original
        // location, which is the primary security property); a failed ACL
        // lockdown is reported but does not roll the move back, matching
        // the general Windows pattern of "best effort past the point of no
        // return" used elsewhere in this module.
        error_message = acl_error;
    }
    json metadata = {
        {"original_path", resolved->generic_string()},
        {"stored_path", stored_path.generic_string()},
    };
    std::ofstream metadata_file{metadata_path, std::ios::trunc};
    if (metadata_file) {
        metadata_file << metadata.dump();
    }
    json document = {
        {"stored_path", stored_path.generic_string()},
        {"metadata_path", metadata_path.generic_string()},
    };
    auto serialized = document.dump();
    if (serialized.size() > maximum_bytes) {
        error_message = "quarantine result exceeds limit";
        return std::nullopt;
    }
    return serialized;
}

}  // namespace panopticon::officer::response
