#include "panopticon/officer/state/browser_inventory.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "persistence_native.hpp"
#include <shlobj.h>
#include <userenv.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <stdexcept>
#include <string_view>

namespace panopticon::officer::state {
namespace {
using namespace native_persistence;

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct FindHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~FindHandle() { if (value != INVALID_HANDLE_VALUE) FindClose(value); }
};
struct KnownPath {
    std::wstring value;
    HRESULT status = E_FAIL;
};
struct ProfilesDirectoryPath {
    std::wstring value;
    DWORD error = ERROR_SUCCESS;
};

Json wide(const std::wstring& value) { return text(value.data(), value.size()); }
KnownPath known_folder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    KnownPath result; result.status = SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr, &raw);
    std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> owned(raw, CoTaskMemFree);
    if (SUCCEEDED(result.status) && raw) result.value = raw;
    else if (SUCCEEDED(result.status)) result.status = E_UNEXPECTED;
    return result;
}

ProfilesDirectoryPath profiles_directory() {
    ProfilesDirectoryPath result;
    DWORD required = 0;
    (void)GetProfilesDirectoryW(nullptr, &required);
    auto error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER || required < 2 || required > 32768) {
        result.error = error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error;
        return result;
    }
    std::vector<wchar_t> buffer(required, L'\0');
    if (!GetProfilesDirectoryW(buffer.data(), &required)) {
        result.error = GetLastError();
        return result;
    }
    if (required == 0 || required > buffer.size() || buffer[0] == L'\0') {
        result.error = ERROR_INVALID_DATA;
        return result;
    }
    result.value.assign(buffer.data(), required - (buffer[required - 1] == L'\0' ? 1 : 0));
    return result;
}

bool final_path(HANDLE handle, std::wstring& path, DWORD& error) {
    std::vector<wchar_t> buffer(32768);
    const auto count = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!count || count >= buffer.size()) { error = count ? ERROR_INSUFFICIENT_BUFFER : GetLastError(); return false; }
    path.assign(buffer.data(), count); error = ERROR_SUCCESS; return true;
}
bool under_root(std::wstring path, std::wstring root) {
    auto strip = [](std::wstring& s) { while (s.size() > 4 && (s.back() == L'\\' || s.back() == L'/')) s.pop_back(); };
    strip(path); strip(root);
    if (path.size() <= root.size()) return false;
    if (_wcsnicmp(path.c_str(), root.c_str(), root.size()) != 0) return false;
    return path[root.size()] == L'\\' || path[root.size()] == L'/';
}
Json query_failure(const char* api, DWORD error) { return failure(api, error, "Win32"); }

struct Inventory {
    BrowserInventoryLimits bounds;
    std::function<bool(Json)> privacy_consumer;
    std::array<std::byte, 32> privacy_salt{};
    bool privacy_salt_ready = false;
    bool redact_profile_paths = false;
    std::string active_scope_token;
    std::string active_user_scope_token;
    Pager pager;
    std::size_t directories = 0, manifests = 0, profiles = 0;
    std::size_t user_profile_entries_examined = 0, user_profile_candidates = 0, user_profiles_scanned = 0, user_profiles_skipped = 0;
    std::size_t user_profile_refusals = 0, user_profile_candidates_omitted = 0;
    std::string user_profile_discovery_state = "not_attempted";
    std::string user_profile_dedup_state = "unknown";
    bool complete = true;
    Inventory(const std::function<bool(Json)>& consumer, BrowserInventoryLimits limits, const std::function<bool()>& cancel)
        : bounds(limits), privacy_consumer([this, sink = consumer](Json row) mutable { return deliver_row(std::move(row), sink); }),
          redact_profile_paths(limits.owned_inert_fixture_roots.empty()),
          pager(limits.pages, "browser_extension_inventory", privacy_consumer, cancel, "browser_inventory_state_version") {
        privacy_salt_ready = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(privacy_salt.data()),
            static_cast<ULONG>(privacy_salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    std::string token_for_path(std::string_view path) const {
        if (!privacy_salt_ready || path.empty()) return {};
        std::string material(reinterpret_cast<const char*>(privacy_salt.data()), privacy_salt.size());
        material.append(path);
        std::string error;
        const auto digest = core::sha256_hex(material, error);
        return digest ? digest->substr(0, 32) : std::string{};
    }

    std::string token_for_path(const std::wstring& path) const {
        const auto encoded = wide(path);
        if (!encoded.is_string()) return {};
        return token_for_path(encoded.get_ref<const std::string&>());
    }

    void redact_row_paths(Json& value) const {
        if (value.is_object()) {
            for (auto it = value.begin(); it != value.end(); ++it) {
                const auto& key = it.key();
                if ((key == "profile_path" || key == "manifest_path" || key == "metadata_index_path" || key == "path" || key == "root_path") && it->is_string())
                    *it = nullptr;
                else redact_row_paths(*it);
            }
        } else if (value.is_array()) {
            for (auto& child : value) redact_row_paths(child);
        }
    }

    bool deliver_row(Json row, const std::function<bool(Json)>& sink) {
        if (!redact_profile_paths) return sink(std::move(row));
        std::string token = active_scope_token;
        if (row.is_object() && row.contains("profile_path") && row["profile_path"].is_string())
            token = token_for_path(row["profile_path"].get_ref<const std::string&>());
        redact_row_paths(row);
        if (row.is_object()) {
            row["profile_scope_token"] = token.empty() ? Json(nullptr) : Json(token);
            row["profile_path_retained"] = false;
            row["profile_path_token_scope"] = "per-capture salted SHA-256; not stable across captures";
            row["profile_path_token_available"] = !token.empty();
            row["user_profile_scope_token"] = active_user_scope_token.empty() ? Json(nullptr) : Json(active_user_scope_token);
            row["user_profile_scope_token_available"] = !active_user_scope_token.empty();
        }
        return sink(std::move(row));
    }

    void refusal(const char* kind, const char* api, DWORD error, const std::wstring& path, bool missing_is_absent = false) {
        const bool missing = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_NOT_FOUND;
        Json query = missing && missing_is_absent ? Json{{"state", "healthy"}, {"source", api}, {"absent", true}, {"error_code", std::to_string(error)}} : query_failure(api, error);
        if (!missing || !missing_is_absent) { ++pager.failures; complete = false; }
        pager.add({{"entry_kind", kind}, {"path", wide(path)}, {"query", std::move(query)}, {"content_read", false}});
    }

    bool open_directory(const std::wstring& path, const std::wstring& root_final, Handle& held, DWORD& error) {
        held.value = CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (held.value == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(held.value, FileAttributeTagInfo, &tag, sizeof(tag))) { error = GetLastError(); return false; }
        if (!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) { error = ERROR_REPARSE_TAG_INVALID; return false; }
        std::wstring resolved;
        if (!final_path(held.value, resolved, error)) return false;
        if (!root_final.empty() && resolved != root_final && !under_root(resolved, root_final)) { error = ERROR_ACCESS_DENIED; return false; }
        return true;
    }

    bool read_file(const std::wstring& path, const std::wstring& root_final, Json& metadata,
        const std::string& browser, const std::wstring& profile, const std::wstring& extension_id) {
        ++manifests;
        Handle file{CreateFileW(path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
        if (file.value == INVALID_HANDLE_VALUE) { refusal("manifest_refusal", "CreateFileW/manifest", GetLastError(), path); return false; }
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &tag, sizeof(tag))) { refusal("manifest_refusal", "GetFileInformationByHandleEx/FileAttributeTagInfo", GetLastError(), path); return false; }
        if ((tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            refusal("manifest_refusal", "manifest must be a regular non-reparse file", ERROR_REPARSE_TAG_INVALID, path); return false;
        }
        std::wstring resolved; DWORD error = ERROR_SUCCESS;
        if (!final_path(file.value, resolved, error)) { refusal("manifest_refusal", "GetFinalPathNameByHandleW", error, path); return false; }
        if (!under_root(resolved, root_final)) { refusal("manifest_refusal", "manifest resolved outside browser data root", ERROR_ACCESS_DENIED, path); return false; }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.value, &size)) { refusal("manifest_refusal", "GetFileSizeEx", GetLastError(), path); return false; }
        if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > bounds.file_bytes) {
            ++pager.fields_refused; complete = false;
            pager.add({{"entry_kind", "manifest_refusal"}, {"path", wide(path)}, {"query", {{"state", "degraded"}, {"bound_exceeded", true}, {"reason", "manifest_byte_limit"}, {"reported_bytes", size.QuadPart < 0 ? "negative" : std::to_string(size.QuadPart)}, {"limit_bytes", bounds.file_bytes}}}, {"content_read", false}});
            return false;
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file.value, &info)) { refusal("manifest_refusal", "GetFileInformationByHandle", GetLastError(), path); return false; }
        FILE_BASIC_INFO before_basic{}; Json before_write = nullptr, before_creation = nullptr;
        if (GetFileInformationByHandleEx(file.value, FileBasicInfo, &before_basic, sizeof(before_basic))) {
            before_write = std::to_string(before_basic.LastWriteTime.QuadPart);
            before_creation = std::to_string(before_basic.CreationTime.QuadPart);
        } else { ++pager.failures; complete = false; }
        FILE_ID_INFO id{}; Json identity = nullptr;
        if (GetFileInformationByHandleEx(file.value, FileIdInfo, &id, sizeof(id))) {
            identity = {{"volume_serial_number", std::to_string(id.VolumeSerialNumber)}, {"file_id_hex", hex({reinterpret_cast<const std::byte*>(id.FileId.Identifier), sizeof(id.FileId.Identifier)})}};
        } else { ++pager.failures; complete = false; identity = {{"state", "unavailable"}, {"query", query_failure("GetFileInformationByHandleEx/FileIdInfo/before_read", GetLastError())}}; }
        std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
        std::size_t offset = 0;
        while (offset < bytes.size() && pager.active()) {
            DWORD got = 0; const auto chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 64 * 1024));
            if (!ReadFile(file.value, bytes.data() + offset, chunk, &got, nullptr)) { refusal("manifest_refusal", "ReadFile", GetLastError(), path); return false; }
            if (!got) { refusal("manifest_refusal", "ReadFile/short file", ERROR_HANDLE_EOF, path); return false; }
            offset += got;
        }
        if (offset != bytes.size()) { complete = false; return false; }
        LARGE_INTEGER after_size{}; Json after_write = nullptr;
        const bool size_after_ok = GetFileSizeEx(file.value, &after_size) != FALSE;
        if (!size_after_ok) { ++pager.failures; complete = false; }
        FILE_BASIC_INFO after_basic{};
        const bool time_after_ok = GetFileInformationByHandleEx(file.value, FileBasicInfo, &after_basic, sizeof(after_basic)) != FALSE;
        if (time_after_ok) after_write = std::to_string(after_basic.LastWriteTime.QuadPart);
        else { ++pager.failures; complete = false; }
        Json changed_during_read = nullptr;
        if (size_after_ok && time_after_ok && !before_write.is_null())
            changed_during_read = size.QuadPart != after_size.QuadPart || before_write != after_write;
        Json file_observation{{"creation_filetime_before_read", before_creation},
            {"last_write_filetime_before_read", before_write}, {"last_write_filetime_after_read", after_write},
            {"reported_size_bytes_before_read", std::to_string(size.QuadPart)},
            {"reported_size_bytes_after_read", size_after_ok ? Json(std::to_string(after_size.QuadPart)) : Json(nullptr)},
            {"changed_during_read", changed_during_read}, {"stable_file_version_verified", false},
            {"consistency", "non_atomic_same_handle observations; hash covers only the exact bytes read between observations"}};
        std::string hash_error;
        const auto hash = core::sha256_hex(bytes, hash_error);
        if (!hash) {
            ++pager.failures; complete = false;
            pager.add({{"entry_kind", "manifest_hash_refusal"}, {"path", wide(path)}, {"query", {{"state", "unavailable"}, {"reason", "sha256_failed"}, {"detail", hash_error}}}});
            return false;
        }
        bool depth_exceeded = false;
        Json parsed;
        try {
            std::size_t depth = 0;
            auto callback = [&](int, Json::parse_event_t event, Json&) {
                if (event == Json::parse_event_t::object_start || event == Json::parse_event_t::array_start) {
                    if (++depth > bounds.parse_depth) { depth_exceeded = true; throw std::runtime_error("maximum parse depth exceeded"); }
                } else if ((event == Json::parse_event_t::object_end || event == Json::parse_event_t::array_end) && depth) --depth;
                return true;
            };
            parsed = Json::parse(bytes, callback);
        } catch (const std::exception&) {
            ++pager.failures; complete = false;
            pager.add({{"entry_kind", "manifest_parse_refusal"}, {"path", wide(path)}, {"browser", browser},
                {"query", {{"state", "degraded"}, {"reason", depth_exceeded ? "json_parse_depth_limit" : "invalid_json"}, {"parse_depth_limit", bounds.parse_depth}}},
                {"manifest_sha256", *hash}, {"manifest_bytes", bytes.size()}, {"file_identity", identity},
                {"file_observation", file_observation}, {"content_read", true}});
            return false;
        }
        std::size_t omitted_fields = 0, overlong_strings = 0;
        auto selected_string = [&](const Json& object, const char* key) -> Json {
            if (object.is_null()) return nullptr;
            if (!object.is_object()) { ++omitted_fields; return nullptr; }
            if (!object.contains(key)) return nullptr;
            if (!object[key].is_string()) { ++omitted_fields; return nullptr; }
            const auto value = object[key].get<std::string>();
            if (value.size() > bounds.metadata_string_bytes) { ++omitted_fields; ++overlong_strings; return nullptr; }
            return value;
        };
        Json name = selected_string(parsed, "name"), version = selected_string(parsed, "version"), description = selected_string(parsed, "description");
        auto copy_string_array = [&](const char* key) {
            Json values = Json::array(); std::size_t omitted = 0;
            if (!parsed.is_object() || !parsed.contains(key)) return std::pair<Json, std::size_t>{std::move(values), omitted};
            if (!parsed[key].is_array()) { ++omitted_fields; return std::pair<Json, std::size_t>{std::move(values), omitted}; }
            constexpr std::size_t max_items = 64;
            const auto& source = parsed[key];
            for (std::size_t i = 0; i < source.size(); ++i) {
                if (i >= max_items || !source[i].is_string() || source[i].get_ref<const std::string&>().size() > bounds.metadata_string_bytes) {
                    ++omitted; if (source[i].is_string() && source[i].get_ref<const std::string&>().size() > bounds.metadata_string_bytes) ++overlong_strings;
                    continue;
                }
                values.push_back(source[i]);
            }
            return std::pair<Json, std::size_t>{std::move(values), omitted};
        };
        auto [permissions, omitted_permissions] = copy_string_array("permissions");
        auto [host_permissions, omitted_host_permissions] = copy_string_array("host_permissions");
        Json gecko_id = nullptr;
        if (parsed.is_object() && parsed.contains("browser_specific_settings") && parsed["browser_specific_settings"].is_object() &&
            parsed["browser_specific_settings"].contains("gecko"))
            gecko_id = selected_string(parsed["browser_specific_settings"]["gecko"], "id");
        if (gecko_id.is_null() && parsed.is_object() && parsed.contains("applications") && parsed["applications"].is_object() && parsed["applications"].contains("gecko"))
            gecko_id = selected_string(parsed["applications"]["gecko"], "id");
        Json manifest_version = nullptr;
        if (parsed.is_object() && parsed.contains("manifest_version")) {
            const auto& raw = parsed["manifest_version"];
            if ((raw.is_number_integer() || raw.is_number_unsigned()) &&
                ((raw.is_number_unsigned() && raw.get<std::uint64_t>() >= 1 && raw.get<std::uint64_t>() <= 3) ||
                 (raw.is_number_integer() && !raw.is_number_unsigned() && raw.get<std::int64_t>() >= 1 && raw.get<std::int64_t>() <= 3)))
                manifest_version = raw.is_number_unsigned() ? Json(raw.get<std::uint64_t>()) : Json(raw.get<std::int64_t>());
            else { ++omitted_fields; manifest_version = {{"state", "degraded"}, {"reason", "manifest_version_requires_integer_1_to_3"}}; }
        }
        metadata = {{"entry_kind", "browser_extension_manifest"}, {"browser", browser}, {"profile_path", wide(profile)},
            {"extension_id_path_component", wide(extension_id)}, {"manifest_path", wide(path)}, {"manifest_bytes", std::to_string(bytes.size())},
            {"manifest_sha256", *hash}, {"file_identity", std::move(identity)}, {"file_observation", std::move(file_observation)},
            {"name", std::move(name)}, {"version", std::move(version)}, {"description", std::move(description)},
            {"manifest_version", std::move(manifest_version)}, {"permissions", std::move(permissions)}, {"host_permissions", std::move(host_permissions)},
            {"gecko_id", std::move(gecko_id)}, {"metadata_omission_counts", {{"selected_fields", omitted_fields},
                {"permission_elements", omitted_permissions}, {"host_permission_elements", omitted_host_permissions}, {"overlong_strings", overlong_strings}}},
            {"metadata_complete", omitted_fields == 0 && omitted_permissions == 0 && omitted_host_permissions == 0},
            {"metadata_parse", {{"state", "healthy"}, {"format", "JSON"}, {"parse_depth_limit", bounds.parse_depth}, {"input_bytes", bytes.size()}}},
            {"claims", {{"installed", "unverified"}, {"running", "unverified"}, {"signer_verified", false}, {"coverage_complete", false}}},
            {"content_read", true}};
        if (omitted_fields || omitted_permissions || omitted_host_permissions) { ++pager.fields_refused; complete = false; }
        return pager.add(std::move(metadata));
    }

    bool enumerate_children(const std::wstring& dir, const std::wstring& root_final, std::vector<std::wstring>& names,
        const char* kind) {
        Handle verified; DWORD verify_error = ERROR_SUCCESS;
        if (!open_directory(dir, root_final, verified, verify_error)) { refusal(kind, "open/verify directory before enumeration", verify_error, dir); return false; }
        const auto pattern = dir + L"\\*";
        WIN32_FIND_DATAW data{}; FindHandle find; find.value = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (find.value == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return true;
            refusal(kind, "FindFirstFileExW", error, dir); return false;
        }
        bool ok = true;
        for (;;) {
            if (!pager.active()) return false;
            const std::wstring name(data.cFileName);
            if (name != L"." && name != L"..") {
                if (++directories > bounds.directories) { complete = false; ++pager.fields_refused; pager.add({{"entry_kind", "browser_directory_bound"}, {"bound", bounds.directories}, {"path", wide(dir)}}); return false; }
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    const auto child = dir + L"\\" + name;
                    Handle held; DWORD error = ERROR_SUCCESS;
                    if (!open_directory(child, root_final, held, error)) { refusal("browser_directory_refusal", "open/verify child directory", error, child); ok = false; }
                    else names.push_back(name);
                } else if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                    pager.add({{"entry_kind", "browser_reparse_skip"}, {"path", wide(dir + L"\\" + name)}, {"content_read", false}, {"reason", "reparse_entry_not_followed"}});
                }
            }
            if (!FindNextFileW(find.value, &data)) {
                const auto error = GetLastError();
                if (error != ERROR_NO_MORE_FILES) { refusal(kind, "FindNextFileW", error, dir); ok = false; }
                break;
            }
        }
        return ok;
    }

    bool scan_chromium_profile(const std::wstring& profile, const std::wstring& root_final, const char* browser) {
        if (profiles >= bounds.profiles) { complete = false; ++pager.fields_refused; pager.add({{"entry_kind", "browser_profile_bound"}, {"browser", browser}, {"profile_path", wide(profile)}, {"bound", bounds.profiles}}); return false; }
        ++profiles;
        if (bounds.directory_depth < 3) { complete = false; ++pager.fields_refused; pager.add({{"entry_kind", "browser_directory_depth_refusal"}, {"browser", browser}, {"profile_path", wide(profile)}, {"required_depth", 3}, {"configured_depth", bounds.directory_depth}}); return false; }
        const auto ext_dir = profile + L"\\Extensions";
        Handle held; DWORD error = ERROR_SUCCESS;
        if (!open_directory(ext_dir, root_final, held, error)) {
            const bool missing = error == ERROR_PATH_NOT_FOUND || error == ERROR_FILE_NOT_FOUND;
            if (missing) pager.add({{"entry_kind", "browser_profile_extensions"}, {"browser", browser}, {"profile_path", wide(profile)}, {"state", "healthy"}, {"extension_directory_absent", true}});
            else refusal("browser_profile_refusal", "open Extensions directory", error, ext_dir);
            return missing;
        }
        std::vector<std::wstring> extension_ids; bool complete_ids = enumerate_children(ext_dir, root_final, extension_ids, "browser_extension_enumeration");
        std::sort(extension_ids.begin(), extension_ids.end());
        for (const auto& extension_id : extension_ids) {
            if (!pager.active()) return false;
            const auto id_dir = ext_dir + L"\\" + extension_id;
            std::vector<std::wstring> versions;
            if (!enumerate_children(id_dir, root_final, versions, "browser_extension_version_enumeration")) complete_ids = false;
            std::sort(versions.begin(), versions.end());
            for (const auto& version : versions) {
                if (manifests >= bounds.manifests) { complete = false; ++pager.fields_refused; pager.add({{"entry_kind", "browser_manifest_bound"}, {"browser", browser}, {"profile_path", wide(profile)}, {"bound", bounds.manifests}}); break; }
                const auto manifest = id_dir + L"\\" + version + L"\\manifest.json";
                Json ignored;
                if (!read_file(manifest, root_final, ignored, browser, profile, extension_id)) complete_ids = false;
            }
        }
        pager.add({{"entry_kind", "browser_profile_extensions"}, {"browser", browser}, {"profile_path", wide(profile)}, {"extension_candidate_directories", extension_ids.size()}, {"enumeration_complete", complete_ids}});
        return complete_ids;
    }

    bool scan_firefox_profile(const std::wstring& profile, const std::wstring& root_final) {
        if (profiles >= bounds.profiles) { complete = false; ++pager.fields_refused; return false; }
        ++profiles;
        const auto path = profile + L"\\extensions.json";
        // Firefox's single bounded metadata index is parsed as JSON below and
        // each add-on entry is emitted independently without reading its code.
        Handle file{CreateFileW(path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
        if (file.value == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError(); const bool missing = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
            if (missing) pager.add({{"entry_kind", "firefox_profile_metadata"}, {"profile_path", wide(profile)}, {"state", "healthy"}, {"metadata_index_absent", true}});
            else refusal("firefox_metadata_refusal", "CreateFileW/extensions.json", error, path);
            return missing;
        }
        FILE_ATTRIBUTE_TAG_INFO tag{}; std::wstring resolved; DWORD error = ERROR_SUCCESS;
        if (!GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &tag, sizeof(tag))) { refusal("firefox_metadata_refusal", "GetFileInformationByHandleEx/FileAttributeTagInfo", GetLastError(), path); return false; }
        if (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { refusal("firefox_metadata_refusal", "extensions.json must be a regular non-reparse file", ERROR_REPARSE_TAG_INVALID, path); return false; }
        if (!final_path(file.value, resolved, error)) { refusal("firefox_metadata_refusal", "GetFinalPathNameByHandleW", error, path); return false; }
        if (!under_root(resolved, root_final)) { refusal("firefox_metadata_refusal", "extensions.json resolved outside profile root", ERROR_ACCESS_DENIED, path); return false; }
        LARGE_INTEGER size{}; if (!GetFileSizeEx(file.value, &size)) { refusal("firefox_metadata_refusal", "GetFileSizeEx", GetLastError(), path); return false; }
        if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > bounds.file_bytes) {
            ++pager.fields_refused; complete = false; pager.add({{"entry_kind", "firefox_metadata_refusal"}, {"path", wide(path)}, {"query", {{"state", "degraded"}, {"reason", "metadata_index_byte_limit"}, {"reported_bytes", size.QuadPart < 0 ? "negative" : std::to_string(size.QuadPart)}, {"limit_bytes", bounds.file_bytes}}}}); return false;
        }
        FILE_ID_INFO file_id{}; Json identity = nullptr;
        if (GetFileInformationByHandleEx(file.value, FileIdInfo, &file_id, sizeof(file_id)))
            identity = {{"volume_serial_number", std::to_string(file_id.VolumeSerialNumber)}, {"file_id_hex", hex({reinterpret_cast<const std::byte*>(file_id.FileId.Identifier), sizeof(file_id.FileId.Identifier)})}};
        else { ++pager.failures; complete = false; identity = {{"state", "unavailable"}, {"query", query_failure("GetFileInformationByHandleEx/FileIdInfo/before_read", GetLastError())}}; }
        FILE_BASIC_INFO before_basic{}; Json before_write = nullptr, before_creation = nullptr;
        if (GetFileInformationByHandleEx(file.value, FileBasicInfo, &before_basic, sizeof(before_basic))) {
            before_write = std::to_string(before_basic.LastWriteTime.QuadPart);
            before_creation = std::to_string(before_basic.CreationTime.QuadPart);
        } else { ++pager.failures; complete = false; }
        std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0'); DWORD got = 0;
        if (!bytes.empty()) {
            if (!ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr)) { refusal("firefox_metadata_refusal", "ReadFile/extensions.json", GetLastError(), path); return false; }
            if (got != bytes.size()) { refusal("firefox_metadata_refusal", "ReadFile/extensions.json/short file", ERROR_HANDLE_EOF, path); return false; }
        }
        LARGE_INTEGER after_size{}; Json after_write = nullptr;
        const bool size_after_ok = GetFileSizeEx(file.value, &after_size) != FALSE;
        if (!size_after_ok) { ++pager.failures; complete = false; }
        FILE_BASIC_INFO after_basic{};
        const bool time_after_ok = GetFileInformationByHandleEx(file.value, FileBasicInfo, &after_basic, sizeof(after_basic)) != FALSE;
        if (time_after_ok) after_write = std::to_string(after_basic.LastWriteTime.QuadPart);
        else { ++pager.failures; complete = false; }
        Json changed_during_read = nullptr;
        if (size_after_ok && time_after_ok && !before_write.is_null()) changed_during_read = size.QuadPart != after_size.QuadPart || before_write != after_write;
        Json file_observation{{"creation_filetime_before_read", before_creation}, {"last_write_filetime_before_read", before_write},
            {"last_write_filetime_after_read", after_write}, {"reported_size_bytes_before_read", std::to_string(size.QuadPart)},
            {"reported_size_bytes_after_read", size_after_ok ? Json(std::to_string(after_size.QuadPart)) : Json(nullptr)},
            {"changed_during_read", changed_during_read}, {"stable_file_version_verified", false},
            {"consistency", "non_atomic same-handle observations; index hash covers the exact bytes read between observations"}};
        std::string hash_error; const auto hash = core::sha256_hex(bytes, hash_error);
        if (!hash) { ++pager.failures; complete = false; return false; }
        Json parsed;
        try {
            std::size_t depth = 0; auto callback = [&](int, Json::parse_event_t event, Json&) {
                if (event == Json::parse_event_t::object_start || event == Json::parse_event_t::array_start) { if (++depth > bounds.parse_depth) throw std::runtime_error("depth"); }
                else if ((event == Json::parse_event_t::object_end || event == Json::parse_event_t::array_end) && depth) --depth;
                return true;
            };
            parsed = Json::parse(bytes, callback);
        } catch (const std::exception&) { ++pager.failures; complete = false; pager.add({{"entry_kind", "firefox_metadata_parse_refusal"}, {"path", wide(path)}, {"metadata_index_sha256", *hash}, {"file_identity", identity}, {"file_observation", file_observation}, {"metadata_parse", {{"state", "degraded"}, {"reason", "invalid_or_overdepth_json"}, {"parse_depth_limit", bounds.parse_depth}, {"input_bytes", bytes.size()}}}}); return false; }
        if (!parsed.is_object() || !parsed.contains("addons") || !parsed["addons"].is_array()) {
            ++pager.failures; complete = false; pager.add({{"entry_kind", "firefox_metadata_parse_refusal"}, {"path", wide(path)}, {"metadata_index_sha256", *hash}, {"file_identity", identity}, {"file_observation", file_observation}, {"metadata_parse", {{"state", "degraded"}, {"reason", "addons_array_missing"}, {"parse_depth_limit", bounds.parse_depth}, {"input_bytes", bytes.size()}}}}); return false;
        }
        std::size_t count = 0, omitted_fields = 0, overlong_strings = 0;
        for (const auto& addon : parsed["addons"]) {
            if (!pager.active()) return false;
            if (manifests >= bounds.manifests) { ++pager.fields_refused; complete = false; break; }
            ++count; ++manifests;
            auto field = [&](const char* key) -> Json {
                if (!addon.is_object()) { ++omitted_fields; return nullptr; }
                if (!addon.contains(key)) return nullptr;
                if (!addon[key].is_string()) { ++omitted_fields; return nullptr; }
                const auto v = addon[key].get<std::string>();
                if (v.size() > bounds.metadata_string_bytes) { ++omitted_fields; ++overlong_strings; return nullptr; }
                return v;
            };
            auto boolean_field = [&](const char* key) -> Json {
                if (!addon.is_object()) { ++omitted_fields; return nullptr; }
                if (!addon.contains(key)) return nullptr;
                if (!addon[key].is_boolean()) { ++omitted_fields; return nullptr; }
                return addon[key];
            };
            const auto before_omitted_fields = omitted_fields;
            const auto before_overlong_strings = overlong_strings;
            Json id = field("id"), name = field("name"), version = field("version"), type = field("type");
            Json active = boolean_field("active"), user_disabled = boolean_field("userDisabled"), app_disabled = boolean_field("appDisabled");
            const auto row_omitted_fields = omitted_fields - before_omitted_fields;
            const auto row_overlong_strings = overlong_strings - before_overlong_strings;
            if (row_omitted_fields) { ++pager.fields_refused; complete = false; }
            Json row{{"entry_kind", "firefox_extension_metadata"}, {"browser", "Firefox"}, {"profile_path", wide(profile)},
                {"metadata_index_path", wide(path)}, {"metadata_index_bytes", std::to_string(bytes.size())}, {"metadata_index_sha256", *hash},
                {"file_identity", identity}, {"file_observation", file_observation},
                {"id", std::move(id)}, {"name", std::move(name)}, {"version", std::move(version)}, {"type", std::move(type)},
                {"active", std::move(active)}, {"user_disabled", std::move(user_disabled)}, {"app_disabled", std::move(app_disabled)},
                {"metadata_parse", {{"state", "healthy"}, {"format", "JSON"}, {"addons_array", "present"}, {"parse_depth_limit", bounds.parse_depth}}},
                {"metadata_omission_counts", {{"selected_fields", row_omitted_fields}, {"overlong_strings", row_overlong_strings},
                    {"addons_omitted_by_global_manifest_limit", parsed["addons"].size() > count ? parsed["addons"].size() - count : 0}}},
                {"metadata_complete", row_omitted_fields == 0 && parsed["addons"].size() <= count},
                {"claims", {{"installed", "unverified"}, {"running", "unverified"}, {"signer_verified", false}, {"coverage_complete", false}}}, {"content_read", true}};
            if (!pager.add(std::move(row))) return false;
        }
        const auto omitted_addons = parsed["addons"].size() > count ? parsed["addons"].size() - count : 0;
        pager.add({{"entry_kind", "firefox_profile_extensions"}, {"profile_path", wide(profile)}, {"metadata_entries_emitted", count},
            {"metadata_entries_omitted", omitted_addons}, {"metadata_omission_counts", {{"addon_elements", omitted_addons}}},
            {"metadata_parse", {{"state", "healthy"}, {"format", "JSON"}, {"addons_array", "present"}, {"input_bytes", bytes.size()}}},
            {"metadata_index_sha256", *hash}, {"file_identity", identity}, {"file_observation", file_observation},
            {"metadata_complete", omitted_addons == 0}, {"enumeration_complete", omitted_addons == 0}});
        return omitted_addons == 0;
    }

    bool scan_root(const char* browser, const std::wstring& root, bool firefox, const std::wstring& expected_profile_final = L"") {
        if (!pager.active()) return false;
        Handle root_handle; DWORD error = ERROR_SUCCESS;
        if (!open_directory(root, L"", root_handle, error)) {
            refusal("browser_root", "open known-folder-derived browser data root", error, root, true);
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        }
        std::wstring root_final;
        if (!final_path(root_handle.value, root_final, error)) { refusal("browser_root_refusal", "GetFinalPathNameByHandleW/root", error, root); return false; }
        if (!expected_profile_final.empty() && !under_root(root_final, expected_profile_final)) {
            refusal("browser_root_refusal", "browser data root escaped verified profile directory", ERROR_ACCESS_DENIED, root);
            return false;
        }
        std::vector<std::wstring> profile_names;
        bool enumerated = enumerate_children(root, root_final, profile_names, "browser_profile_enumeration");
        std::sort(profile_names.begin(), profile_names.end());
        bool local_complete = enumerated;
        for (const auto& profile_name : profile_names) {
            if (!pager.active()) return false;
            const auto profile = root + L"\\" + profile_name;
            const auto previous_scope = active_scope_token;
            active_scope_token = token_for_path(profile);
            const bool ok = firefox ? scan_firefox_profile(profile, root_final) : scan_chromium_profile(profile, root_final, browser);
            active_scope_token = previous_scope;
            local_complete = ok && local_complete;
        }
        pager.add({{"entry_kind", "browser_root_summary"}, {"browser", browser}, {"root_path", wide(root)}, {"profile_candidates", profile_names.size()},
            {"enumeration_complete", local_complete}, {"inventory_complete", false}});
        return local_complete;
    }

    bool scan_all_profile_directories(const KnownPath& current_profile) {
        const auto profiles_root = profiles_directory();
        if (profiles_root.value.empty()) {
            user_profile_discovery_state = "unavailable";
            ++user_profile_refusals; complete = false;
            pager.add({{"entry_kind", "browser_profiles_root_refusal"},
                {"query", failure("GetProfilesDirectoryW", profiles_root.error, "Win32")},
                {"profile_path_retained", false}, {"scope", "configured Windows profile root unavailable"}});
            return false;
        }
        Handle root_handle; DWORD error = ERROR_SUCCESS;
        if (!open_directory(profiles_root.value, L"", root_handle, error)) {
            user_profile_discovery_state = "unavailable"; ++user_profile_refusals; complete = false;
            refusal("browser_profiles_root_refusal", "open configured Windows profiles directory", error, profiles_root.value);
            return false;
        }
        std::wstring profiles_final;
        if (!final_path(root_handle.value, profiles_final, error)) {
            user_profile_discovery_state = "unavailable"; ++user_profile_refusals; complete = false;
            refusal("browser_profiles_root_refusal", "GetFinalPathNameByHandleW/profiles root", error, profiles_root.value);
            return false;
        }

        std::wstring current_final;
        if (SUCCEEDED(current_profile.status)) {
            Handle current_handle;
            if (!open_directory(current_profile.value, L"", current_handle, error) || !final_path(current_handle.value, current_final, error)) {
                user_profile_dedup_state = "unavailable";
                complete = false;
                pager.add({{"entry_kind", "browser_current_profile_dedup_refusal"},
                    {"query", failure("open/resolve FOLDERID_Profile", error, "Win32")},
                    {"profile_path_retained", false}, {"duplicate_discovery_possible", true}});
            } else user_profile_dedup_state = "resolved";
        } else {
            user_profile_dedup_state = "unavailable";
            complete = false;
            pager.add({{"entry_kind", "browser_current_profile_dedup_refusal"},
                {"query", failure("SHGetKnownFolderPath/FOLDERID_Profile", static_cast<std::uint32_t>(current_profile.status), "HRESULT")},
                {"profile_path_retained", false}, {"duplicate_discovery_possible", true}});
        }

        std::vector<std::wstring> names;
        const bool enumerated = enumerate_children(profiles_root.value, profiles_final, names, "browser_user_profile_enumeration");
        std::sort(names.begin(), names.end());
        user_profile_discovery_state = "partial";
        bool local_complete = enumerated && user_profile_dedup_state == "resolved";
        if (names.size() > bounds.user_profile_candidates) {
            user_profile_candidates_omitted = names.size() - bounds.user_profile_candidates;
            names.resize(bounds.user_profile_candidates);
            ++pager.fields_refused; local_complete = false; complete = false;
            pager.add({{"entry_kind", "browser_user_profile_bound"},
                {"candidate_limit", bounds.user_profile_candidates},
                {"omitted_candidate_count", user_profile_candidates_omitted},
                {"profile_path_retained", false}, {"state", "degraded"}});
        }

        for (const auto& name : names) {
            if (!pager.active()) { local_complete = false; break; }
            ++user_profile_entries_examined;
            if (_wcsicmp(name.c_str(), L"Default") == 0 || _wcsicmp(name.c_str(), L"Default User") == 0 ||
                _wcsicmp(name.c_str(), L"All Users") == 0 || _wcsicmp(name.c_str(), L"Public") == 0) {
                ++user_profiles_skipped;
                continue;
            }
            const auto profile_path = profiles_root.value + L"\\" + name;
            Handle profile_handle; DWORD profile_error = ERROR_SUCCESS;
            if (!open_directory(profile_path, profiles_final, profile_handle, profile_error)) {
                ++user_profile_candidates; ++user_profile_refusals;
                local_complete = false; complete = false;
                refusal("browser_user_profile_refusal", "open/verify profile directory candidate", profile_error, profile_path);
                continue;
            }
            std::wstring profile_final;
            if (!final_path(profile_handle.value, profile_final, profile_error)) {
                ++user_profile_candidates; ++user_profile_refusals;
                local_complete = false; complete = false;
                refusal("browser_user_profile_refusal", "GetFinalPathNameByHandleW/profile candidate", profile_error, profile_path);
                continue;
            }
            if (!current_final.empty() && _wcsicmp(profile_final.c_str(), current_final.c_str()) == 0) {
                ++user_profiles_skipped;
                pager.add({{"entry_kind", "browser_user_profile_candidate"}, {"profile_path", wide(profile_path)},
                    {"candidate_state", "current_caller_covered_by_known_folders"}, {"account_identity_verified", false},
                    {"account_sid", nullptr}, {"profile_path_retained", false}});
                continue;
            }
            if (++user_profile_candidates > bounds.user_profile_candidates) {
                --user_profile_candidates;
                ++user_profile_candidates_omitted; ++pager.fields_refused;
                local_complete = false; complete = false;
                continue;
            }
            pager.add({{"entry_kind", "browser_user_profile_candidate"}, {"profile_path", wide(profile_path)},
                {"candidate_index", user_profile_candidates}, {"candidate_state", "directory_observed"},
                {"account_identity_verified", false}, {"account_sid", nullptr}, {"loaded_user_hive_required", false},
                {"profile_path_retained", false}});
            ++user_profiles_scanned;
            const auto prior_scope = active_scope_token;
            const auto prior_user_scope = active_user_scope_token;
            active_scope_token = token_for_path(profile_path);
            active_user_scope_token = active_scope_token;
            const std::array<std::pair<const wchar_t*, const char*>, 3> chromium_roots{{
                {L"AppData\\Local\\Google\\Chrome\\User Data", "Chrome"},
                {L"AppData\\Local\\Microsoft\\Edge\\User Data", "Edge"},
                {L"AppData\\Local\\Chromium\\User Data", "Chromium"}}};
            for (const auto& browser : chromium_roots) {
                if (!pager.active()) { local_complete = false; break; }
                local_complete = scan_root(browser.second, profile_path + L"\\" + browser.first, false, profile_final) && local_complete;
            }
            if (pager.active())
                local_complete = scan_root("Firefox", profile_path + L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", true, profile_final) && local_complete;
            active_scope_token = prior_scope;
            active_user_scope_token = prior_user_scope;
        }
        pager.add({{"entry_kind", "browser_user_profile_discovery_summary"},
            {"source", "GetProfilesDirectoryW plus direct non-reparse directories"},
            {"profile_directory_entries_examined", user_profile_entries_examined},
            {"noncurrent_profile_candidates", user_profile_candidates}, {"profile_directories_scanned", user_profiles_scanned},
            {"built_in_or_current_directories_skipped", user_profiles_skipped}, {"profile_directory_refusals", user_profile_refusals},
            {"candidate_limit_omitted", user_profile_candidates_omitted}, {"current_profile_dedup_state", user_profile_dedup_state},
            {"account_sid_mapping", "not performed"}, {"profile_path_retained", false},
            {"enumeration_complete", local_complete}});
        user_profile_discovery_state = local_complete ? "observed_with_limits" : "partial";
        return local_complete;
    }
};

} // namespace

Json collect_browser_inventory_pages(const std::function<bool(Json)>& consumer, BrowserInventoryLimits limits,
    const std::function<bool()>& cancelled) {
    const auto& p = limits.pages;
    if (!consumer || !p.page_entries || p.page_entries > 4096 || p.encoded_bytes < 4096 || p.encoded_bytes > 512 * 1024 ||
        !p.total_entries || p.total_entries > 65536 || !p.pages || p.pages > 1024 || !p.soft_budget_ms || p.soft_budget_ms > 300000 ||
        !limits.profiles || limits.profiles > 256 || !limits.user_profile_candidates || limits.user_profile_candidates > 256 ||
        !limits.directories || limits.directories > 65536 || !limits.manifests || limits.manifests > 65536 ||
        !limits.directory_depth || limits.directory_depth > 16 || !limits.file_bytes || limits.file_bytes > 4 * 1024 * 1024 ||
        !limits.parse_depth || limits.parse_depth > 128 || !limits.metadata_string_bytes || limits.metadata_string_bytes > 64 * 1024 ||
        limits.owned_inert_fixture_roots.size() > 16)
        throw std::invalid_argument("invalid native browser inventory scope/bounds");

    Inventory inventory{consumer, limits, cancelled};
    if (!limits.owned_inert_fixture_roots.empty()) {
        for (const auto& fixture : limits.owned_inert_fixture_roots) {
            const bool known_name = fixture.browser == "Chrome" || fixture.browser == "Edge" || fixture.browser == "Chromium" || fixture.browser == "Firefox";
            if (!fixture.caller_owned_inert_fixture || !known_name || fixture.root_path.empty() || !std::filesystem::path(fixture.root_path).is_absolute())
                throw std::invalid_argument("browser fixture roots must be explicitly caller-owned absolute inert paths with a known browser label");
        }
        for (const auto& fixture : limits.owned_inert_fixture_roots) {
            if (!inventory.pager.active()) break;
            inventory.complete = inventory.scan_root(fixture.browser.c_str(), fixture.root_path, fixture.browser == "Firefox") && inventory.complete;
        }
    } else {
    const auto local = known_folder(FOLDERID_LocalAppData);
    const auto roaming = known_folder(FOLDERID_RoamingAppData);
    const auto current_profile = known_folder(FOLDERID_Profile);
    if (SUCCEEDED(current_profile.status))
        inventory.active_user_scope_token = inventory.token_for_path(current_profile.value);
    auto record_folder_failure = [&](const char* label, const KnownPath& folder) {
        if (SUCCEEDED(folder.status)) return;
        ++inventory.pager.failures; inventory.complete = false;
        inventory.pager.add({{"entry_kind", "browser_known_folder_refusal"}, {"folder", label},
            {"query", failure("SHGetKnownFolderPath", static_cast<std::uint32_t>(folder.status))}});
    };
    record_folder_failure("FOLDERID_LocalAppData", local);
    record_folder_failure("FOLDERID_RoamingAppData", roaming);
    if (SUCCEEDED(local.status)) {
        for (const auto& browser : std::array<std::pair<const wchar_t*, const char*>, 3>{{
                 {L"Google\\Chrome\\User Data", "Chrome"}, {L"Microsoft\\Edge\\User Data", "Edge"}, {L"Chromium\\User Data", "Chromium"}}}) {
            if (!inventory.pager.active()) break;
            const auto root = local.value + L"\\" + browser.first;
            inventory.complete = inventory.scan_root(browser.second, root, false) && inventory.complete;
        }
    }
    if (SUCCEEDED(roaming.status) && inventory.pager.active()) {
        const auto root = roaming.value + L"\\Mozilla\\Firefox\\Profiles";
        inventory.complete = inventory.scan_root("Firefox", root, true) && inventory.complete;
    }
    if (inventory.pager.active())
        inventory.complete = inventory.scan_all_profile_directories(current_profile) && inventory.complete;
    }
    auto result = inventory.pager.finish(
        limits.owned_inert_fixture_roots.empty()
            ? "current caller known-folder-derived browser roots plus bounded direct profile-directory candidates under GetProfilesDirectoryW using conventional AppData-relative roots; profile directories are not mapped to accounts; extension JSON only"
            : "explicit caller-owned inert fixture roots only; bounded extension JSON metadata; not production browser inventory",
        inventory.complete);
    result["browser_limits"] = {{"profiles", limits.profiles}, {"user_profile_candidates", limits.user_profile_candidates},
        {"directories", limits.directories}, {"manifests", limits.manifests},
        {"directory_depth", limits.directory_depth}, {"file_bytes", limits.file_bytes}, {"parse_depth", limits.parse_depth},
        {"metadata_string_bytes", limits.metadata_string_bytes}};
    result["all_profile_discovery"] = {{"state", inventory.user_profile_discovery_state},
        {"source", "GetProfilesDirectoryW direct directory enumeration; no ProfileList SID association"},
        {"profile_directory_entries_examined", std::to_string(inventory.user_profile_entries_examined)},
        {"noncurrent_profile_candidates", std::to_string(inventory.user_profile_candidates)},
        {"profile_directories_scanned", std::to_string(inventory.user_profiles_scanned)},
        {"built_in_or_current_directories_skipped", std::to_string(inventory.user_profiles_skipped)},
        {"directory_refusals", std::to_string(inventory.user_profile_refusals)},
        {"candidate_limit_omitted", std::to_string(inventory.user_profile_candidates_omitted)},
        {"current_profile_dedup_state", inventory.user_profile_dedup_state},
        {"account_sid_mapping", "not performed"}, {"effective_user_access", "current process token only"},
        {"raw_profile_paths_retained", false}, {"scope_tokens", "per-capture salted SHA-256 pseudonyms; not stable across captures"}};
    result["resource_scope"] = "bounded profile/directory/manifest candidates, file bytes, JSON depth, application copies/pages; native directory APIs and filesystem calls lack hard deadline/allocation guarantees";
    result["content_scope"] = "extension manifest.json and Firefox extensions.json metadata only; browser executables, extension code, credentials, cookies, history and network are not read";
    result["coverage_claim"] = "observed browser metadata candidates beneath current-caller known folders and bounded conventional AppData paths for direct profile directories; no account SID mapping, relocated-path discovery, inaccessible-data coverage, extension installation/running/signer proof, all-browser-products or complete-inventory claim";
    result["fixture_roots_used"] = !limits.owned_inert_fixture_roots.empty();
    return result;
}

} // namespace panopticon::officer::state
