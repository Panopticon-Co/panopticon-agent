#include "panopticon/officer/forensics/file_acquisition.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <aclapi.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace panopticon::officer::forensics {
namespace {

using Json = nlohmann::json;
constexpr std::uint32_t kChunkMagic = 0x31434650;  // "PFC1" little endian
constexpr std::size_t kNonceBytes = 12;
constexpr std::size_t kTagBytes = 16;
constexpr std::size_t kChunkHeaderBytes = 4 + 8 + 8 + 4 + kNonceBytes + kTagBytes;

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
            value = std::exchange(other.value, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    explicit operator bool() const noexcept { return value != INVALID_HANDLE_VALUE; }
};

struct BCryptAlg {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~BCryptAlg() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
    BCryptAlg(const BCryptAlg&) = delete;
    BCryptAlg& operator=(const BCryptAlg&) = delete;
    BCryptAlg() = default;
};
struct BCryptHash {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~BCryptHash() { if (value) BCryptDestroyHash(value); }
};

void nt_ok(NTSTATUS status, const char* what) {
    if (status < 0) throw std::runtime_error(what);
}

std::wstring lower_slashes(std::wstring value) {
    for (auto& c : value) {
        if (c == L'/') c = L'\\';
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    while (value.size() > 1 && value.back() == L'\\') value.pop_back();
    return value;
}

std::wstring final_path(HANDLE handle) {
    const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!needed || needed > 32768) throw std::runtime_error("cannot resolve normalized final file path");
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    const DWORD written = GetFinalPathNameByHandleW(handle, result.data(), needed, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!written || written >= needed) throw std::runtime_error("cannot resolve normalized final file path");
    result.resize(written);
    return lower_slashes(std::move(result));
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("cannot encode final path");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count, nullptr, nullptr))
        throw std::runtime_error("cannot encode final path");
    return result;
}

std::string hex(const std::uint8_t* bytes, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out(size * 2, '0');
    for (std::size_t i = 0; i != size; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return out;
}

void restrict_store_acl(const std::filesystem::path& path) {
    Handle token;
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        throw std::runtime_error("cannot inspect service identity for forensic store ACL");
    token = Handle{raw_token};
    DWORD needed = 0;
    (void)GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
    if (!needed || needed > 65536) throw std::runtime_error("cannot size forensic store owner identity");
    std::vector<std::uint8_t> token_bytes(needed);
    if (!GetTokenInformation(token.value, TokenUser, token_bytes.data(), needed, &needed))
        throw std::runtime_error("cannot read forensic store owner identity");
    auto* owner = reinterpret_cast<TOKEN_USER*>(token_bytes.data())->User.Sid;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID system = nullptr;
    if (!AllocateAndInitializeSid(&authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system))
        throw std::runtime_error("cannot create SYSTEM SID for forensic store ACL");
    EXPLICIT_ACCESSW entries[2]{};
    for (auto& entry : entries) {
        entry.grfAccessPermissions = FILE_ALL_ACCESS;
        entry.grfAccessMode = SET_ACCESS;
        entry.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    }
    entries[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(owner);
    entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entries[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system);
    PACL acl = nullptr;
    const DWORD built = SetEntriesInAclW(2, entries, nullptr, &acl);
    FreeSid(system);
    if (built != ERROR_SUCCESS || !acl) throw std::runtime_error("cannot build private forensic store ACL");
    const DWORD applied = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    LocalFree(acl);
    if (applied != ERROR_SUCCESS) throw std::runtime_error("cannot restrict forensic store to the agent account and SYSTEM");
}

void require_private_acl(const std::filesystem::path& path, const bool require_protected_dacl) {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        throw std::runtime_error("cannot inspect service identity for forensic store ACL");
    Handle token{raw_token};
    DWORD needed = 0;
    (void)GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
    if (!needed || needed > 65536) throw std::runtime_error("cannot size forensic store owner identity");
    std::vector<std::uint8_t> token_bytes(needed);
    if (!GetTokenInformation(token.value, TokenUser, token_bytes.data(), needed, &needed))
        throw std::runtime_error("cannot read forensic store owner identity");
    PSID user_sid = reinterpret_cast<TOKEN_USER*>(token_bytes.data())->User.Sid;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID system_sid = nullptr;
    if (!AllocateAndInitializeSid(&authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid))
        throw std::runtime_error("cannot create SYSTEM SID for forensic store ACL check");

    PSID owner_sid = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner_sid, nullptr, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS || !descriptor) {
        FreeSid(system_sid);
        throw std::runtime_error("cannot inspect existing forensic store ACL");
    }
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    bool safe = GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (!require_protected_dacl || (control & SE_DACL_PROTECTED) != 0) &&
        owner_sid && EqualSid(owner_sid, user_sid) && dacl && dacl->AceCount == 2;
    bool saw_user = false;
    bool saw_system = false;
    for (DWORD i = 0; safe && i < dacl->AceCount; ++i) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, i, &raw_ace)) { safe = false; break; }
        auto* header = static_cast<ACE_HEADER*>(raw_ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (header->AceFlags & ~(INHERITED_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)) != 0) {
            safe = false;
            break;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        PSID sid = &ace->SidStart;
        if (ace->Mask != FILE_ALL_ACCESS) { safe = false; break; }
        if (EqualSid(sid, user_sid) && !saw_user) saw_user = true;
        else if (EqualSid(sid, system_sid) && !saw_system) saw_system = true;
        else safe = false;
    }
    LocalFree(descriptor);
    FreeSid(system_sid);
    if (!safe || !saw_user || !saw_system)
        throw std::runtime_error("existing forensic store ACL is not restricted to the current service account and SYSTEM; preserve it and configure a dedicated protected store");
}

std::string manifest_mac(BCRYPT_ALG_HANDLE hmac_provider, const std::array<std::uint8_t, 32>& key, Json manifest) {
    manifest.erase("manifest_hmac");
    std::vector<std::uint8_t> object(4096);
    BCRYPT_HASH_HANDLE raw_hash = nullptr;
    nt_ok(BCryptCreateHash(hmac_provider, &raw_hash, object.data(), static_cast<ULONG>(object.size()),
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0), "cannot initialize manifest authenticator");
    BCryptHash hash{raw_hash};
    const auto serialized = manifest.dump();
    nt_ok(BCryptHashData(hash.value, reinterpret_cast<PUCHAR>(const_cast<char*>(serialized.data())),
        static_cast<ULONG>(serialized.size()), 0), "cannot authenticate acquisition manifest");
    std::array<std::uint8_t, 32> digest{};
    nt_ok(BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0), "cannot finalize manifest authenticator");
    return hex(digest.data(), digest.size());
}

void verify_manifest(BCRYPT_ALG_HANDLE hmac_provider, const std::array<std::uint8_t, 32>& key, Json& manifest) {
    const auto stored = manifest.value("manifest_hmac", std::string{});
    if (stored.size() != 64) throw std::runtime_error("manifest authentication tag is missing");
    const auto expected = manifest_mac(hmac_provider, key, manifest);
    unsigned difference = 0;
    for (std::size_t i = 0; i != stored.size(); ++i)
        difference |= static_cast<unsigned char>(stored[i] ^ expected[i]);
    if (difference != 0) throw std::runtime_error("manifest authentication failed");
    manifest["manifest_hmac"] = stored;
}

std::string identity(HANDLE handle) {
    FILE_ID_INFO info{};
    if (!GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info)))
        throw std::runtime_error("cannot read volume and file identity");
    std::array<std::uint8_t, sizeof(info.VolumeSerialNumber) + sizeof(info.FileId.Identifier)> bytes{};
    std::memcpy(bytes.data(), &info.VolumeSerialNumber, sizeof(info.VolumeSerialNumber));
    std::memcpy(bytes.data() + sizeof(info.VolumeSerialNumber), info.FileId.Identifier, sizeof(info.FileId.Identifier));
    return hex(bytes.data(), bytes.size());
}

struct FileFacts {
    std::uint64_t size = 0;
    std::int64_t write_time = 0;
    std::string file_identity;
    std::wstring path;
};

FileFacts facts(HANDLE handle) {
    FILE_STANDARD_INFO standard{};
    FILE_BASIC_INFO basic{};
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) ||
        !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)))
        throw std::runtime_error("cannot read opened file metadata");
    if (standard.Directory || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("directories and reparse points are refused");
    if (standard.EndOfFile.QuadPart < 0) throw std::runtime_error("file reports invalid size");
    return {static_cast<std::uint64_t>(standard.EndOfFile.QuadPart), basic.LastWriteTime.QuadPart,
            identity(handle), final_path(handle)};
}

std::wstring resolved_root(const std::filesystem::path& root, Handle& handle) {
    if (root.empty() || !root.is_absolute()) throw std::runtime_error("collection root must be explicitly configured as an absolute path");
    handle = Handle{CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!handle) throw std::runtime_error("cannot open configured collection root");
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(handle.value, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        !(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("collection root must be a non-reparse directory");
    return final_path(handle.value);
}

std::wstring validated_id(const std::string& id) {
    if (id.empty() || id.size() > 96) throw std::runtime_error("capture id length is invalid");
    for (const unsigned char c : id)
        if (!(std::isalnum(c) || c == '_' || c == '-')) throw std::runtime_error("capture id contains invalid characters");
    return std::wstring(id.begin(), id.end());
}

std::filesystem::path manifest_path(const std::filesystem::path& store, const std::string& id) {
    (void)validated_id(id);
    return store / (id + ".manifest.json");
}
std::filesystem::path chunk_path(const std::filesystem::path& store, const std::string& id, std::uint64_t sequence) {
    (void)validated_id(id);
    char name[128]{};
    std::snprintf(name, sizeof(name), "%s.%020llu.chunk", id.c_str(), static_cast<unsigned long long>(sequence));
    return store / name;
}

std::vector<std::uint8_t> encode_chunk(BCRYPT_ALG_HANDLE aes, const std::array<std::uint8_t, 32>& key,
    const std::string& id, std::uint64_t sequence, std::uint64_t offset, const std::vector<std::uint8_t>& plain) {
    std::array<std::uint8_t, kNonceBytes> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("secure nonce generation failed");
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    nt_ok(BCryptGenerateSymmetricKey(aes, &key_handle, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0), "cannot initialize AES-256 key");
    struct KeyCloser { BCRYPT_KEY_HANDLE key; ~KeyCloser() { if (key) BCryptDestroyKey(key); } } key_closer{key_handle};
    std::vector<std::uint8_t> cipher(plain.size());
    std::array<std::uint8_t, kTagBytes> tag{};
    std::string aad = id;
    aad.push_back('\0');
    for (unsigned i = 0; i != 8; ++i) aad.push_back(static_cast<char>((sequence >> (8 * i)) & 0xff));
    for (unsigned i = 0; i != 8; ++i) aad.push_back(static_cast<char>((offset >> (8 * i)) & 0xff));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = nonce.data(); auth.cbNonce = static_cast<ULONG>(nonce.size());
    auth.pbTag = tag.data(); auth.cbTag = static_cast<ULONG>(tag.size());
    auth.pbAuthData = reinterpret_cast<PUCHAR>(aad.data()); auth.cbAuthData = static_cast<ULONG>(aad.size());
    ULONG written = 0;
    nt_ok(BCryptEncrypt(key_handle, const_cast<PUCHAR>(plain.data()), static_cast<ULONG>(plain.size()),
        &auth, nullptr, 0, cipher.data(), static_cast<ULONG>(cipher.size()), &written, 0), "AES-GCM encryption failed");
    cipher.resize(written);
    std::vector<std::uint8_t> output(kChunkHeaderBytes + cipher.size());
    auto* p = output.data();
    std::memcpy(p, &kChunkMagic, 4); p += 4;
    std::memcpy(p, &sequence, 8); p += 8;
    std::memcpy(p, &offset, 8); p += 8;
    const auto length = static_cast<std::uint32_t>(plain.size());
    std::memcpy(p, &length, 4); p += 4;
    std::memcpy(p, nonce.data(), nonce.size()); p += nonce.size();
    std::memcpy(p, tag.data(), tag.size()); p += tag.size();
    std::memcpy(p, cipher.data(), cipher.size());
    SecureZeroMemory(cipher.data(), cipher.size());
    return output;
}

std::vector<std::uint8_t> decode_chunk(BCRYPT_ALG_HANDLE aes, const std::array<std::uint8_t, 32>& key,
    const std::string& id, std::uint64_t expected_sequence, std::uint64_t expected_offset,
    const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("committed chunk is missing");
    in.seekg(0, std::ios::end); const auto end = in.tellg();
    if (end < static_cast<std::streamoff>(kChunkHeaderBytes) || end > static_cast<std::streamoff>(kChunkHeaderBytes + 16ull * 1024 * 1024))
        throw std::runtime_error("committed chunk length is invalid");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end)); in.seekg(0);
    if (!in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("cannot read committed chunk");
    const auto* p = bytes.data(); std::uint32_t magic = 0, length = 0; std::uint64_t sequence = 0, offset = 0;
    std::memcpy(&magic, p, 4); p += 4; std::memcpy(&sequence, p, 8); p += 8;
    std::memcpy(&offset, p, 8); p += 8; std::memcpy(&length, p, 4); p += 4;
    if (magic != kChunkMagic || sequence != expected_sequence || offset != expected_offset ||
        length != bytes.size() - kChunkHeaderBytes) throw std::runtime_error("committed chunk sequence or framing mismatch");
    const auto* nonce = p; p += kNonceBytes; const auto* tag = p; p += kTagBytes;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    nt_ok(BCryptGenerateSymmetricKey(aes, &key_handle, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0), "cannot initialize AES-256 key");
    struct KeyCloser { BCRYPT_KEY_HANDLE key; ~KeyCloser() { if (key) BCryptDestroyKey(key); } } key_closer{key_handle};
    std::vector<std::uint8_t> plain(length);
    std::string aad = id; aad.push_back('\0');
    for (unsigned i = 0; i != 8; ++i) aad.push_back(static_cast<char>((sequence >> (8 * i)) & 0xff));
    for (unsigned i = 0; i != 8; ++i) aad.push_back(static_cast<char>((offset >> (8 * i)) & 0xff));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = const_cast<PUCHAR>(nonce); auth.cbNonce = static_cast<ULONG>(kNonceBytes);
    auth.pbTag = const_cast<PUCHAR>(tag); auth.cbTag = static_cast<ULONG>(kTagBytes);
    auth.pbAuthData = reinterpret_cast<PUCHAR>(aad.data()); auth.cbAuthData = static_cast<ULONG>(aad.size());
    ULONG written = 0;
    nt_ok(BCryptDecrypt(key_handle, const_cast<PUCHAR>(p), length, &auth, nullptr, 0,
        plain.data(), length, &written, 0), "chunk authentication failed");
    plain.resize(written);
    SecureZeroMemory(bytes.data(), bytes.size());
    return plain;
}

void write_durable(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    Handle out{CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr)};
    if (!out) throw std::runtime_error("cannot create encrypted output chunk");
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
        DWORD written = 0;
        if (!WriteFile(out.value, bytes.data() + offset, count, &written, nullptr) || written != count)
            throw std::runtime_error("cannot write encrypted output chunk");
        offset += written;
    }
    if (!FlushFileBuffers(out.value)) throw std::runtime_error("cannot durably flush encrypted output chunk");
}

void persist_manifest(const std::filesystem::path& path, Json manifest, BCRYPT_ALG_HANDLE hmac_provider,
    const std::array<std::uint8_t, 32>& key) {
    const auto temp = path.wstring() + L".tmp";
    manifest["manifest_hmac"] = manifest_mac(hmac_provider, key, manifest);
    const auto serialized = manifest.dump(2);
    Handle out{CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr)};
    if (!out) throw std::runtime_error("cannot create acquisition manifest");
    DWORD written = 0;
    if (!WriteFile(out.value, serialized.data(), static_cast<DWORD>(serialized.size()), &written, nullptr) || written != serialized.size() ||
        !FlushFileBuffers(out.value)) throw std::runtime_error("cannot durably write acquisition manifest");
    out = Handle{};
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("cannot atomically commit acquisition manifest");
}

}  // namespace

bool load_or_create_dpapi_key(const std::filesystem::path& store_root,
    std::array<std::uint8_t, 32>& key, std::string& error_message, const bool create_if_missing) {
    SecureZeroMemory(key.data(), key.size());
    try {
        if (store_root.empty() || !store_root.is_absolute()) {
            error_message = "forensic store root must be an explicit absolute path";
            return false;
        }
        std::error_code ec;
        std::filesystem::create_directories(store_root.parent_path(), ec);
        if (ec) throw std::runtime_error("cannot create parent for configured forensic store root");
        ec.clear();
        const bool created_store = std::filesystem::create_directory(store_root, ec);
        if (ec) throw std::runtime_error("cannot create configured forensic store root");
        Handle store_handle{CreateFileW(store_root.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        FILE_ATTRIBUTE_TAG_INFO store_tag{};
        if (!store_handle || !GetFileInformationByHandleEx(store_handle.value, FileAttributeTagInfo, &store_tag, sizeof(store_tag)) ||
            !(store_tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (store_tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("forensic store root must be a non-reparse directory");
        if (created_store) restrict_store_acl(store_root);
        else require_private_acl(store_root, true);
        const auto key_path = store_root / L"acquisition-key.dpapi";
        // The root may predate the current DACL (for example after a manual
        // store migration), so verify the key file's existing ACL without
        // modifying it. A new key inherits from the protected store root.
        const auto key_attributes = GetFileAttributesW(key_path.c_str());
        if (key_attributes != INVALID_FILE_ATTRIBUTES) {
            if ((key_attributes & FILE_ATTRIBUTE_DIRECTORY) || (key_attributes & FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("protected forensic key path is not a regular file");
            require_private_acl(key_path, false);
        }
        const auto read_key = [&]() -> bool {
            std::ifstream input(key_path, std::ios::binary);
            if (!input) return false;
            std::vector<std::uint8_t> protected_bytes((std::istreambuf_iterator<char>(input)), {});
            if (protected_bytes.empty() || protected_bytes.size() > 16 * 1024)
                throw std::runtime_error("protected forensic key file has invalid size");
            DATA_BLOB protected_blob{static_cast<DWORD>(protected_bytes.size()), protected_bytes.data()};
            DATA_BLOB clear_blob{};
            if (!CryptUnprotectData(&protected_blob, nullptr, nullptr, nullptr, nullptr,
                    CRYPTPROTECT_UI_FORBIDDEN, &clear_blob))
                throw std::runtime_error("cannot unprotect forensic key under this Windows account");
            const bool valid = clear_blob.cbData == key.size();
            if (valid) std::memcpy(key.data(), clear_blob.pbData, key.size());
            if (clear_blob.pbData) {
                SecureZeroMemory(clear_blob.pbData, clear_blob.cbData);
                LocalFree(clear_blob.pbData);
            }
            SecureZeroMemory(protected_bytes.data(), protected_bytes.size());
            if (!valid) throw std::runtime_error("unprotected forensic key has invalid length");
            return true;
        };
        if (read_key()) return true;
        if (!create_if_missing)
            throw std::runtime_error("DPAPI acquisition key is unavailable; restart recovery will not provision a replacement key");

        std::array<std::uint8_t, 32> generated{};
        if (BCryptGenRandom(nullptr, generated.data(), static_cast<ULONG>(generated.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw std::runtime_error("forensic key entropy unavailable");
        DATA_BLOB clear_blob{static_cast<DWORD>(generated.size()), generated.data()};
        DATA_BLOB protected_blob{};
        if (!CryptProtectData(&clear_blob, L"Panopticon forensic acquisition key", nullptr, nullptr, nullptr,
                CRYPTPROTECT_UI_FORBIDDEN, &protected_blob)) {
            SecureZeroMemory(generated.data(), generated.size());
            throw std::runtime_error("cannot protect forensic acquisition key with DPAPI");
        }
        const auto temp_path = key_path.wstring() + L".tmp";
        DeleteFileW(temp_path.c_str());
        Handle output{CreateFileW(temp_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH, nullptr)};
        bool written_ok = false;
        if (output) {
            DWORD written = 0;
            written_ok = WriteFile(output.value, protected_blob.pbData, protected_blob.cbData, &written, nullptr) &&
                written == protected_blob.cbData && FlushFileBuffers(output.value);
        }
        if (protected_blob.pbData) {
            SecureZeroMemory(protected_blob.pbData, protected_blob.cbData);
            LocalFree(protected_blob.pbData);
        }
        SecureZeroMemory(generated.data(), generated.size());
        if (!written_ok) {
            DeleteFileW(temp_path.c_str());
            throw std::runtime_error("cannot durably write protected forensic key");
        }
        output = Handle{};
        if (!MoveFileExW(temp_path.c_str(), key_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temp_path.c_str());
            const DWORD move_error = GetLastError();
            if (move_error == ERROR_ALREADY_EXISTS || move_error == ERROR_FILE_EXISTS) {
                require_private_acl(key_path, false);
                if (read_key()) return true;
            }
            throw std::runtime_error("cannot commit protected forensic key");
        }
        require_private_acl(key_path, false);
        std::ifstream persisted(key_path, std::ios::binary);
        std::vector<std::uint8_t> protected_bytes((std::istreambuf_iterator<char>(persisted)), {});
        DATA_BLOB stored{static_cast<DWORD>(protected_bytes.size()), protected_bytes.data()};
        DATA_BLOB decoded{};
        if (!CryptUnprotectData(&stored, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &decoded))
            throw std::runtime_error("cannot verify persisted DPAPI forensic key");
        const bool valid = decoded.cbData == key.size();
        if (valid) std::memcpy(key.data(), decoded.pbData, key.size());
        if (decoded.pbData) { SecureZeroMemory(decoded.pbData, decoded.cbData); LocalFree(decoded.pbData); }
        SecureZeroMemory(protected_bytes.data(), protected_bytes.size());
        if (!valid) throw std::runtime_error("persisted forensic key has invalid length");
        return true;
    } catch (const std::exception& e) {
        SecureZeroMemory(key.data(), key.size());
        error_message = e.what();
        return false;
    }
}

struct FileAcquisitionStore::Impl {
    explicit Impl(FileAcquisitionConfig value) : config(std::move(value)) {
        if (config.collection_root.empty() || !config.collection_root.is_absolute() ||
            config.encrypted_store_root.empty() || !config.encrypted_store_root.is_absolute() ||
            config.maximum_capture_bytes == 0 || config.maximum_capture_bytes > 4ull * 1024 * 1024 * 1024 ||
            config.chunk_bytes == 0 || config.chunk_bytes > 16u * 1024 * 1024)
            throw std::invalid_argument("invalid bounded file acquisition configuration");
        if (std::all_of(config.encryption_key.begin(), config.encryption_key.end(), [](auto b) { return b == 0; }))
            throw std::invalid_argument("file acquisition encryption key is not provisioned");
        std::error_code ec;
        std::filesystem::create_directories(config.encrypted_store_root, ec);
        if (ec) throw std::runtime_error("cannot create explicitly configured encrypted store root");
        store_root_handle = Handle{CreateFileW(config.encrypted_store_root.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        FILE_ATTRIBUTE_TAG_INFO store_tag{};
        if (!store_root_handle || !GetFileInformationByHandleEx(store_root_handle.value, FileAttributeTagInfo,
                &store_tag, sizeof(store_tag)) || !(store_tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (store_tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("encrypted store root changed or became a reparse point during initialization");
        require_private_acl(config.encrypted_store_root, true);
        nt_ok(BCryptOpenAlgorithmProvider(&sha.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0), "cannot open SHA-256 provider");
        nt_ok(BCryptOpenAlgorithmProvider(&hmac.value, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG), "cannot open manifest HMAC provider");
        nt_ok(BCryptOpenAlgorithmProvider(&aes.value, BCRYPT_AES_ALGORITHM, nullptr, 0), "cannot open AES provider");
        nt_ok(BCryptSetProperty(aes.value, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0), "cannot configure AES-GCM");
    }
    FileAcquisitionConfig config;
    // Holding the root without FILE_SHARE_DELETE prevents path replacement
    // while this store instance writes manifests and chunks.
    Handle store_root_handle;
    BCryptAlg sha, hmac, aes;
    mutable std::mutex mutex;
};

FileAcquisitionStore::FileAcquisitionStore(FileAcquisitionConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
FileAcquisitionStore::~FileAcquisitionStore() {
    if (impl_) SecureZeroMemory(impl_->config.encryption_key.data(), impl_->config.encryption_key.size());
}

FileAcquisitionResult FileAcquisitionStore::inspect(const std::string& capture_id) const {
    FileAcquisitionResult result; result.capture_id = capture_id;
    try {
        (void)validated_id(capture_id);
        std::scoped_lock lock{impl_->mutex};
        const auto path = manifest_path(impl_->config.encrypted_store_root, capture_id);
        std::ifstream in(path, std::ios::binary);
        if (!in) { result.state = "refused"; result.error = "capture manifest does not exist"; return result; }
        Json manifest; in >> manifest;
        verify_manifest(impl_->hmac.value, impl_->config.encryption_key, manifest);
        if (manifest.at("version") != 1 || manifest.at("capture_id") != capture_id) throw std::runtime_error("manifest version or id mismatch");
        result.state = manifest.at("state").get<std::string>();
        result.captured_bytes = manifest.at("captured_bytes").get<std::uint64_t>();
        result.next_sequence = manifest.at("next_sequence").get<std::uint64_t>();
        result.sha256 = manifest.value("sha256", std::string{});
        result.manifest_path = path.string();
    } catch (const std::exception& e) { result.state = "failed"; result.error = e.what(); }
    return result;
}

FileAcquisitionResult FileAcquisitionStore::acquire(const FileAcquisitionRequest& request) {
    FileAcquisitionResult result; result.capture_id = request.capture_id;
    auto refused = [&](const std::string& why) { result.state = "refused"; result.error = why; return result; };
    try { (void)validated_id(request.capture_id); }
    catch (const std::exception& e) { return refused(e.what()); }
    if (request.resume_existing_only && (request.command_id.empty() || request.command_correlation_id.empty()))
        return refused("restart recovery requires the original command id and correlation id");
    Json manifest;
    std::filesystem::path manifest_file;
    Handle root_handle, source;
    BCryptHash hash;
    bool existing_capture_verified = false;
    try {
        if (request.relative_path.empty() || request.relative_path.is_absolute() || request.relative_path.has_root_name() ||
            request.relative_path.has_root_directory() || request.maximum_bytes == 0)
            return refused("request must name a relative path and a positive byte bound");
        for (const auto& part : request.relative_path) {
            if (part == L".." || part == L"." || part.empty()) return refused("path traversal and empty components are refused");
            if (part.native().find(L':') != std::wstring::npos) return refused("alternate data stream paths are refused");
        }
        const auto root_path = resolved_root(impl_->config.collection_root, root_handle);
        auto requested = root_path + L"\\" + request.relative_path.native();
        source = Handle{CreateFileW(requested.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
        if (!source) return refused("cannot open target read-only while holding it against new write/delete opens");
        const auto before = facts(source.value);
        const auto root_now = final_path(root_handle.value);
        const auto root_id = identity(root_handle.value);
        if (root_now != root_path) return refused("configured collection root identity or final path changed");
        const auto prefix = root_path + L"\\";
        if (before.path.size() <= prefix.size() || before.path.compare(0, prefix.size(), prefix) != 0)
            return refused("opened target final path is outside configured collection root");

        std::scoped_lock lock{impl_->mutex};
        manifest_file = manifest_path(impl_->config.encrypted_store_root, request.capture_id);
        const auto requested_cap = std::min(request.maximum_bytes, impl_->config.maximum_capture_bytes);
        if (std::filesystem::exists(manifest_file)) {
            std::ifstream in(manifest_file, std::ios::binary); in >> manifest;
            verify_manifest(impl_->hmac.value, impl_->config.encryption_key, manifest);
            if (manifest.at("version") != 1 || manifest.at("capture_id") != request.capture_id)
                throw std::runtime_error("existing manifest is invalid");
            const auto state = manifest.at("state").get<std::string>();
            if (state == "complete" || state == "truncated") {
                if (manifest.at("source_identity") != before.file_identity || manifest.at("source_path") != utf8(before.path) ||
                    manifest.value("requested_relative_path", std::string{}) != utf8(request.relative_path.wstring()) ||
                    manifest.at("source_size") != before.size || manifest.at("source_write_time") != before.write_time ||
                    manifest.at("root_identity") != root_id || manifest.at("maximum_bytes") != requested_cap ||
                    manifest.value("requested_maximum_bytes", std::uint64_t{}) != request.maximum_bytes ||
                    manifest.at("chunk_bytes") != impl_->config.chunk_bytes ||
                    (request.resume_existing_only && manifest.value("command_id", std::string{}) != request.command_id) ||
                    manifest.value("command_correlation_id", std::string{}) != request.command_correlation_id)
                    return refused("capture id already belongs to another source or request identity");
                existing_capture_verified = true;
                result.state = state; result.manifest_path = manifest_file.string();
                result.captured_bytes = manifest.at("captured_bytes").get<std::uint64_t>();
                result.next_sequence = manifest.at("next_sequence").get<std::uint64_t>();
                result.sha256 = manifest.value("sha256", std::string{});
                result.existing_capture_verified = true;
                return result;
            }
            if (state != "partial" || manifest.at("source_identity") != before.file_identity ||
                manifest.at("source_path") != utf8(before.path) ||
                manifest.value("requested_relative_path", std::string{}) != utf8(request.relative_path.wstring()) ||
                manifest.at("source_size") != before.size ||
                manifest.at("source_write_time") != before.write_time || manifest.at("root_identity") != root_id ||
                manifest.at("maximum_bytes") != requested_cap ||
                manifest.value("requested_maximum_bytes", std::uint64_t{}) != request.maximum_bytes ||
                manifest.at("chunk_bytes") != impl_->config.chunk_bytes ||
                (request.resume_existing_only && manifest.value("command_id", std::string{}) != request.command_id) ||
                manifest.value("command_correlation_id", std::string{}) != request.command_correlation_id)
                return refused("partial capture cannot resume because source or request identity changed");
            existing_capture_verified = true;
        } else {
            if (request.resume_existing_only)
                return refused("no authenticated capture manifest exists for interrupted command recovery");
            manifest = Json{{"version", 1}, {"capture_id", request.capture_id}, {"source_path", utf8(before.path)},
                {"requested_relative_path", utf8(request.relative_path.wstring())},
                {"source_identity", before.file_identity}, {"root_identity", root_id}, {"source_size", before.size},
                {"source_write_time", before.write_time}, {"maximum_bytes", requested_cap},
                {"requested_maximum_bytes", request.maximum_bytes},
                {"command_id", request.command_id}, {"command_correlation_id", request.command_correlation_id},
                {"chunk_bytes", impl_->config.chunk_bytes}, {"captured_bytes", 0}, {"next_sequence", 0},
                {"state", "partial"}, {"sha256", ""}, {"hash_scope", "captured_prefix"}};
            persist_manifest(manifest_file, manifest, impl_->hmac.value, impl_->config.encryption_key);
        }

        const auto captured = manifest.at("captured_bytes").get<std::uint64_t>();
        auto sequence = manifest.at("next_sequence").get<std::uint64_t>();
        if (captured > requested_cap || captured > before.size || sequence != (captured + impl_->config.chunk_bytes - 1) / impl_->config.chunk_bytes)
            throw std::runtime_error("partial manifest sequence accounting is inconsistent");
        std::vector<std::uint8_t> hash_object(4096);
        BCryptHash& hash_ref = hash;
        nt_ok(BCryptCreateHash(impl_->sha.value, &hash_ref.value, hash_object.data(), static_cast<ULONG>(hash_object.size()), nullptr, 0, 0), "cannot initialize SHA-256");
        std::uint64_t verified_extent = 0;
        for (std::uint64_t i = 0; i < sequence; ++i) {
            auto previous = decode_chunk(impl_->aes.value, impl_->config.encryption_key, request.capture_id, i, verified_extent,
                chunk_path(impl_->config.encrypted_store_root, request.capture_id, i));
            if (previous.empty() || previous.size() > impl_->config.chunk_bytes ||
                (i + 1 < sequence && previous.size() != impl_->config.chunk_bytes))
                throw std::runtime_error("committed chunk lengths do not match manifest sequence");
            nt_ok(BCryptHashData(hash.value, previous.data(), static_cast<ULONG>(previous.size()), 0), "cannot rebuild resumed SHA-256");
            verified_extent += previous.size(); SecureZeroMemory(previous.data(), previous.size());
        }
        if (verified_extent != captured) throw std::runtime_error("committed chunk extent differs from manifest");
        LARGE_INTEGER seek{}; seek.QuadPart = static_cast<LONGLONG>(captured);
        if (!SetFilePointerEx(source.value, seek, nullptr, FILE_BEGIN)) throw std::runtime_error("cannot seek held source file");
        std::uint64_t offset = captured;
        const auto cap = std::min<std::uint64_t>(requested_cap, before.size);
        std::string state;
        while (offset < cap) {
            const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(impl_->config.chunk_bytes, cap - offset));
            std::vector<std::uint8_t> plain(take);
            std::size_t got = 0;
            while (got < take) {
                DWORD read = 0;
                if (!ReadFile(source.value, plain.data() + got, static_cast<DWORD>(std::min<std::size_t>(take - got, 1u << 20)), &read, nullptr))
                    throw std::runtime_error("source read failed");
                if (!read) break;
                got += read;
            }
            if (!got) { SecureZeroMemory(plain.data(), plain.size()); state = "partial"; result.error = "source ended before admitted size"; break; }
            plain.resize(got);
            nt_ok(BCryptHashData(hash.value, plain.data(), static_cast<ULONG>(plain.size()), 0), "cannot update source SHA-256");
            auto encrypted = encode_chunk(impl_->aes.value, impl_->config.encryption_key, request.capture_id, sequence, offset, plain);
            const auto final_chunk = chunk_path(impl_->config.encrypted_store_root, request.capture_id, sequence);
            if (std::filesystem::exists(final_chunk)) {
                // A crash may occur after the encrypted chunk rename and before
                // its manifest commit. Adopt that orphan only when it decrypts
                // and exactly matches the held source bytes at this sequence.
                auto orphan = decode_chunk(impl_->aes.value, impl_->config.encryption_key, request.capture_id, sequence, offset, final_chunk);
                const bool matches = orphan == plain;
                SecureZeroMemory(orphan.data(), orphan.size());
                if (!matches) throw std::runtime_error("uncommitted chunk conflicts with held source; refusing replay");
            } else {
                const auto temp_chunk = final_chunk.wstring() + L".part";
                DeleteFileW(temp_chunk.c_str());
                write_durable(temp_chunk, encrypted);
                if (!MoveFileExW(temp_chunk.c_str(), final_chunk.c_str(), MOVEFILE_WRITE_THROUGH))
                    throw std::runtime_error("cannot commit encrypted chunk atomically");
            }
            SecureZeroMemory(plain.data(), plain.size());
            SecureZeroMemory(encrypted.data(), encrypted.size());
            offset += got; ++sequence;
            manifest["captured_bytes"] = offset; manifest["next_sequence"] = sequence;
            manifest["state"] = "partial";
            persist_manifest(manifest_file, manifest, impl_->hmac.value, impl_->config.encryption_key);
            if (got != take) { state = "partial"; result.error = "short read; capture remains resumable only if source identity stays stable"; break; }
        }
        const auto after = facts(source.value);
        if (after.file_identity != before.file_identity || after.path != before.path || after.size != before.size || after.write_time != before.write_time ||
            final_path(root_handle.value) != root_path || identity(root_handle.value) != root_id) {
            state = "partial";
            result.error = "source or collection root changed during acquisition; captured chunks retained as partial";
        }
        if (state.empty()) state = offset < before.size ? "truncated" : "complete";
        if (offset >= cap && cap < before.size && state != "partial") state = "truncated";
        std::array<std::uint8_t, 32> digest{};
        if (state == "partial" || offset == before.size || offset == cap) {
            nt_ok(BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0), "SHA-256 finalization failed");
            manifest["sha256"] = hex(digest.data(), digest.size());
            manifest["hash_scope"] = offset == before.size ? "complete_source" : "captured_prefix";
        }
        manifest["captured_bytes"] = offset; manifest["next_sequence"] = sequence; manifest["state"] = state;
        persist_manifest(manifest_file, manifest, impl_->hmac.value, impl_->config.encryption_key);
        result.state = state; result.manifest_path = manifest_file.string(); result.captured_bytes = offset;
        result.next_sequence = sequence; result.sha256 = manifest.value("sha256", std::string{});
        result.existing_capture_verified = existing_capture_verified;
    } catch (const std::exception& e) {
        result.state = "failed"; result.error = e.what(); result.existing_capture_verified = existing_capture_verified;
        if (!manifest_file.empty() && std::filesystem::exists(manifest_file)) {
            try {
                std::scoped_lock lock{impl_->mutex};
                std::ifstream in(manifest_file, std::ios::binary); in >> manifest;
                verify_manifest(impl_->hmac.value, impl_->config.encryption_key, manifest);
                if (manifest.value("state", std::string{}) == "partial") {
                    result.state = "partial";
                    result.captured_bytes = manifest.value("captured_bytes", std::uint64_t{});
                    result.next_sequence = manifest.value("next_sequence", std::uint64_t{});
                    result.manifest_path = manifest_file.string();
                }
            } catch (...) { /* preserve the primary error; manifest remains available for inspection */ }
        }
    }
    return result;
}

}  // namespace panopticon::officer::forensics
