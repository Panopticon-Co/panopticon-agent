#include "panopticon/officer/deployment/update_package.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wincrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iterator>
#include <limits>
#include <set>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace panopticon::officer::deployment {
namespace {
using Json = nlohmann::json;
constexpr char kDomain[] = "PANOPTICON-WINDOWS-UPDATE-MANIFEST-V1\0";
constexpr char kTrustDomain[] = "PANOPTICON-WINDOWS-PUBLISHER-TRUST-V1\0";
constexpr std::uint64_t kMaximumLifetimeMs = 30ull * 24 * 60 * 60 * 1000;
constexpr std::uint64_t kRotationOverlapMs = 24ull * 60 * 60 * 1000;

struct Handle {
    HANDLE value{INVALID_HANDLE_VALUE};
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); value = std::exchange(other.value, INVALID_HANDLE_VALUE); }
        return *this;
    }
};
struct FindHandle {
    HANDLE value{INVALID_HANDLE_VALUE};
    explicit FindHandle(HANDLE handle) : value(handle) {}
    ~FindHandle() { if (value != INVALID_HANDLE_VALUE) FindClose(value); }
    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;
};
struct Algorithm { BCRYPT_ALG_HANDLE value{}; ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); } };
struct Hash { BCRYPT_HASH_HANDLE value{}; ~Hash() { if (value) BCryptDestroyHash(value); } };
struct Key { BCRYPT_KEY_HANDLE value{}; ~Key() { if (value) BCryptDestroyKey(value); } };
struct LocalMemory { void* value{}; ~LocalMemory() { if (value) LocalFree(value); } };
[[noreturn]] void win_error(const char* message, DWORD code = GetLastError());
void validate_object_acl(HANDLE object, bool require_protected_dacl);
void verify_not_reparse(HANDLE object, bool require_directory);
struct StateLock {
    Handle file; OVERLAPPED overlap{}; bool locked{};
    explicit StateLock(const std::filesystem::path& root) {
        file.value = CreateFileW((root / L"update-stage-state.lock").c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file.value == INVALID_HANDLE_VALUE) win_error("cannot open update-state lock");
        verify_not_reparse(file.value, false);
        validate_object_acl(file.value, false);
        if (!LockFileEx(file.value, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlap)) win_error("cannot acquire update-state lock");
        locked = true;
    }
    ~StateLock() { if (locked) UnlockFileEx(file.value, 0, 1, 0, &overlap); }
};

[[noreturn]] void win_error(const char* message, DWORD code) {
    throw std::system_error(static_cast<int>(code), std::system_category(), message);
}

void validate_object_acl(HANDLE object, bool require_protected_dacl) {
    PSID owner = nullptr; PACL dacl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto status = GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    LocalMemory descriptor_memory{descriptor};
    if (status != ERROR_SUCCESS) win_error("cannot inspect update object security", status);
    if (!owner || !dacl || !IsValidAcl(dacl)) throw std::runtime_error("update object owner or DACL is absent/invalid");
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        (require_protected_dacl && !(control & SE_DACL_PROTECTED)))
        throw std::runtime_error("update staging root DACL must be protected");

    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) win_error("cannot inspect update service identity");
    DWORD token_bytes = 0; (void)GetTokenInformation(token.value, TokenUser, nullptr, 0, &token_bytes);
    if (!token_bytes || token_bytes > 65536) throw std::runtime_error("service token user information unavailable");
    std::vector<std::uint8_t> token_buffer(token_bytes);
    if (!GetTokenInformation(token.value, TokenUser, token_buffer.data(), token_bytes, &token_bytes))
        win_error("cannot read update service identity");
    const auto process_user = reinterpret_cast<TOKEN_USER*>(token_buffer.data())->User.Sid;
    LocalMemory system_sid, admins_sid, owner_rights_sid;
    if (!ConvertStringSidToSidW(L"S-1-5-18", reinterpret_cast<PSID*>(&system_sid.value)) ||
        !ConvertStringSidToSidW(L"S-1-5-32-544", reinterpret_cast<PSID*>(&admins_sid.value)) ||
        !ConvertStringSidToSidW(L"S-1-3-4", reinterpret_cast<PSID*>(&owner_rights_sid.value)))
        win_error("cannot create trusted update security principals");
    const auto trusted = [&](PSID sid) {
        return EqualSid(sid, process_user) || EqualSid(sid, system_sid.value) || EqualSid(sid, admins_sid.value) ||
            ((EqualSid(owner, process_user) || EqualSid(owner, system_sid.value) || EqualSid(owner, admins_sid.value)) &&
             EqualSid(sid, owner_rights_sid.value));
    };
    if (!trusted(owner)) throw std::runtime_error("update object is not owned by the service, SYSTEM, or administrators");

    const auto count = dacl->AceCount;
    if (count > 128) throw std::runtime_error("update object DACL ACE bound exceeded");
    constexpr ACCESS_MASK dangerous = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD;
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    for (WORD index = 0; index < count; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, index, &raw_ace) || !raw_ace) win_error("cannot inspect update DACL ACE");
        const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE || header->AceType == SYSTEM_AUDIT_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
            throw std::runtime_error("update object DACL contains an unsupported access-granting ACE");
        if (header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) throw std::runtime_error("update object DACL contains a truncated allow ACE");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        auto mask = ace->Mask;
        MapGenericMask(&mask, &mapping);
        auto sid = const_cast<DWORD*>(&ace->SidStart);
        if (!IsValidSid(sid) || GetLengthSid(sid) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart))
            throw std::runtime_error("update object DACL contains an invalid trustee SID");
        if ((mask & dangerous) && !trusted(sid))
            throw std::runtime_error("untrusted principal has update staging write/delete rights");
    }
}

void verify_not_reparse(HANDLE object, bool require_directory) {
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(object, FileAttributeTagInfo, &tag, sizeof(tag)))
        win_error("cannot inspect update object attributes");
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (require_directory && !(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ||
        (!require_directory && (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)))
        throw std::runtime_error("update object has an unsafe reparse or directory type");
}

Handle open_update_directory(const std::filesystem::path& path) {
    Handle directory(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (directory.value == INVALID_HANDLE_VALUE) win_error("cannot open update staging root");
    verify_not_reparse(directory.value, true);
    validate_object_acl(directory.value, true);
    return directory;
}

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    return result;
}

std::string sha256(std::span<const std::uint8_t> bytes) {
    Algorithm algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("SHA-256 provider unavailable");
    DWORD object_size = 0, returned = 0;
    if (BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0) < 0 || returned != sizeof(object_size))
        throw std::runtime_error("SHA-256 object size query failed");
    std::vector<std::uint8_t> object(object_size), digest(32);
    Hash hash;
    if (BCryptCreateHash(algorithm.value, &hash.value, object.data(), object_size, nullptr, 0, 0) < 0)
        throw std::runtime_error("SHA-256 initialization failed");
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = static_cast<ULONG>(std::min<std::size_t>(bytes.size() - offset, 1024 * 1024));
        if (BCryptHashData(hash.value, const_cast<PUCHAR>(bytes.data() + offset), count, 0) < 0)
            throw std::runtime_error("SHA-256 update failed");
        offset += count;
    }
    if (BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("SHA-256 finalization failed");
    return hex(digest);
}

bool has_keys(const Json& value, std::initializer_list<std::string_view> names) {
    if (!value.is_object() || value.size() != names.size()) return false;
    for (const auto name : names) if (!value.contains(std::string(name))) return false;
    return true;
}

std::uint64_t uint_field(const Json& value, const char* key) {
    if (!value.contains(key) || !value[key].is_number_unsigned())
        throw std::runtime_error(std::string("invalid unsigned manifest field: ") + key);
    return value[key].get<std::uint64_t>();
}

std::vector<std::uint8_t> decode_signature(const std::string& encoded) {
    DWORD count = 0;
    if (encoded.empty() || encoded.size() > 1024 ||
        !CryptStringToBinaryA(encoded.data(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64,
                              nullptr, &count, nullptr, nullptr) || count != 64)
        throw std::runtime_error("signature must be a 64-byte base64 ECDSA P-256 signature");
    std::vector<std::uint8_t> result(count);
    if (!CryptStringToBinaryA(encoded.data(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64,
                              result.data(), &count, nullptr, nullptr) || count != result.size())
        throw std::runtime_error("malformed signature encoding");
    return result;
}

std::vector<std::uint8_t> decode_hex(std::string_view encoded, std::size_t maximum_bytes) {
    if (encoded.empty() || encoded.size() % 2 || encoded.size() / 2 > maximum_bytes)
        throw std::runtime_error("publisher SPKI hex is empty, odd-sized, or oversized");
    const auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::vector<std::uint8_t> result(encoded.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        const auto high = digit(encoded[i * 2]), low = digit(encoded[i * 2 + 1]);
        if (high < 0 || low < 0) throw std::runtime_error("publisher SPKI hex must be lowercase canonical hexadecimal");
        result[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

std::string verify_signed_payload(std::string_view raw, const char* expected_format,
                                  const char* domain, const std::vector<PublisherPin>& pins,
                                  Json& envelope_out) {
    if (raw.empty() || raw.size() > kMaximumUpdateManifestBytes)
        throw std::runtime_error("signed trust bundle is empty or exceeds the 64 KiB bound");
    const auto envelope = Json::parse(raw.begin(), raw.end());
    if (!has_keys(envelope, {"format", "key_id", "payload", "signature"}) ||
        !envelope["format"].is_string() || envelope["format"] != expected_format ||
        !envelope["key_id"].is_string() || !envelope["payload"].is_string() || !envelope["signature"].is_string())
        throw std::runtime_error("unknown signed trust bundle envelope or field set");
    const auto key_id = envelope["key_id"].get<std::string>();
    const auto payload = envelope["payload"].get<std::string>();
    if (payload.empty() || payload.size() > kMaximumUpdateManifestBytes)
        throw std::runtime_error("signed trust bundle payload is empty or oversized");
    const PublisherPin* pin = nullptr;
    for (const auto& candidate : pins) if (candidate.key_id == key_id) { pin = &candidate; break; }
    if (!pin || pin->subject_public_key_info_der.empty() || pin->subject_public_key_info_der.size() > 4096 ||
        sha256(pin->subject_public_key_info_der) != pin->key_id)
        throw std::runtime_error("trust bundle signer is not a valid caller-provisioned bootstrap pin");
    LocalMemory decoded;
    DWORD decoded_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pin->subject_public_key_info_der.data(),
        static_cast<DWORD>(pin->subject_public_key_info_der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
        &decoded.value, &decoded_size)) throw std::runtime_error("bootstrap SPKI DER is invalid");
    auto* public_info = static_cast<CERT_PUBLIC_KEY_INFO*>(decoded.value);
    if (!public_info->Algorithm.pszObjId || std::string_view(public_info->Algorithm.pszObjId) != szOID_ECC_PUBLIC_KEY)
        throw std::runtime_error("bootstrap key is not elliptic-curve public key material");
    Key key;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, public_info, 0, nullptr, &key.value))
        throw std::runtime_error("Windows CNG cannot import bootstrap key");
    wchar_t algorithm[64]{}; DWORD got = 0;
    if (BCryptGetProperty(key.value, BCRYPT_ALGORITHM_NAME, reinterpret_cast<PUCHAR>(algorithm), sizeof(algorithm), &got, 0) < 0 ||
        std::wstring_view(algorithm) != BCRYPT_ECDSA_P256_ALGORITHM)
        throw std::runtime_error("bootstrap key must be ECDSA P-256");
    std::vector<std::uint8_t> signed_bytes;
    signed_bytes.reserve(std::strlen(domain) + 1 + payload.size());
    signed_bytes.insert(signed_bytes.end(), reinterpret_cast<const std::uint8_t*>(domain),
        reinterpret_cast<const std::uint8_t*>(domain) + std::strlen(domain) + 1);
    signed_bytes.insert(signed_bytes.end(), payload.begin(), payload.end());
    Algorithm hash_algorithm;
    if (BCryptOpenAlgorithmProvider(&hash_algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("trust bundle SHA-256 provider unavailable");
    DWORD object_size = 0;
    if (BCryptGetProperty(hash_algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size), &got, 0) < 0 || got != sizeof(object_size))
        throw std::runtime_error("trust bundle digest object query failed");
    std::vector<std::uint8_t> object(object_size), digest(32);
    Hash hash;
    if (BCryptCreateHash(hash_algorithm.value, &hash.value, object.data(), object_size, nullptr, 0, 0) < 0 ||
        BCryptHashData(hash.value, signed_bytes.data(), static_cast<ULONG>(signed_bytes.size()), 0) < 0 ||
        BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("trust bundle signature digest failed");
    const auto signature = decode_signature(envelope["signature"].get<std::string>());
    if (BCryptVerifySignature(key.value, nullptr, digest.data(), static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0) < 0)
        throw std::runtime_error("trust bundle bootstrap signature verification failed");
    envelope_out = envelope;
    return payload;
}

struct Manifest {
    Json document;
    std::string exact_envelope;
    std::uint64_t generation{};
    std::uint64_t size{};
    std::uint64_t expires{};
    std::string version;
    std::string architecture;
    std::string package_hash;
};

Manifest verify_manifest(std::string_view raw, const std::vector<PublisherPin>& pins,
                         std::uint64_t now, std::string_view architecture) {
    if (raw.empty() || raw.size() > kMaximumUpdateManifestBytes)
        throw std::runtime_error("update manifest is empty or exceeds the 64 KiB bound");
    const auto envelope = Json::parse(raw.begin(), raw.end());
    if (!has_keys(envelope, {"format", "key_id", "payload", "signature"}) ||
        !envelope["format"].is_string() || envelope["format"] != "panopticon_signed_update_manifest_v1" ||
        !envelope["key_id"].is_string() || !envelope["payload"].is_string() || !envelope["signature"].is_string())
        throw std::runtime_error("unknown update envelope format or field set");
    const auto key_id = envelope["key_id"].get<std::string>();
    const auto payload = envelope["payload"].get<std::string>();
    if (payload.empty() || payload.size() > kMaximumUpdateManifestBytes)
        throw std::runtime_error("update manifest payload is empty or oversized");
    const PublisherPin* pin = nullptr;
    for (const auto& candidate : pins) if (candidate.key_id == key_id) { pin = &candidate; break; }
    if (!pin) throw std::runtime_error("update publisher key is not pinned");
    if (pin->subject_public_key_info_der.empty() || pin->subject_public_key_info_der.size() > 4096 ||
        sha256(pin->subject_public_key_info_der) != pin->key_id)
        throw std::runtime_error("pinned publisher SPKI fingerprint or size is invalid");

    LocalMemory decoded;
    DWORD decoded_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        pin->subject_public_key_info_der.data(), static_cast<DWORD>(pin->subject_public_key_info_der.size()),
        CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded.value, &decoded_size))
        throw std::runtime_error("pinned publisher SPKI DER is invalid");
    auto* public_info = static_cast<CERT_PUBLIC_KEY_INFO*>(decoded.value);
    if (!public_info->Algorithm.pszObjId || std::string_view(public_info->Algorithm.pszObjId) != szOID_ECC_PUBLIC_KEY)
        throw std::runtime_error("publisher key is not elliptic-curve public key material");
    Key key;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, public_info, 0, nullptr, &key.value))
        throw std::runtime_error("Windows CNG cannot import pinned publisher key");
    wchar_t algorithm[64]{}; DWORD got = 0;
    if (BCryptGetProperty(key.value, BCRYPT_ALGORITHM_NAME, reinterpret_cast<PUCHAR>(algorithm),
        sizeof(algorithm), &got, 0) < 0 || std::wstring_view(algorithm) != BCRYPT_ECDSA_P256_ALGORITHM)
        throw std::runtime_error("publisher key must be ECDSA P-256");

    std::vector<std::uint8_t> signed_bytes;
    signed_bytes.reserve(sizeof(kDomain) - 1 + payload.size());
    signed_bytes.insert(signed_bytes.end(), reinterpret_cast<const std::uint8_t*>(kDomain),
        reinterpret_cast<const std::uint8_t*>(kDomain) + sizeof(kDomain) - 1);
    signed_bytes.insert(signed_bytes.end(), payload.begin(), payload.end());
    Algorithm hash_algorithm;
    if (BCryptOpenAlgorithmProvider(&hash_algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("SHA-256 provider unavailable");
    DWORD object_size = 0;
    if (BCryptGetProperty(hash_algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size), &got, 0) < 0 || got != sizeof(object_size))
        throw std::runtime_error("signature digest object query failed");
    std::vector<std::uint8_t> object(object_size), digest(32);
    Hash hash;
    if (BCryptCreateHash(hash_algorithm.value, &hash.value, object.data(), object_size, nullptr, 0, 0) < 0 ||
        BCryptHashData(hash.value, signed_bytes.data(), static_cast<ULONG>(signed_bytes.size()), 0) < 0 ||
        BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("manifest signature digest failed");
    const auto signature = decode_signature(envelope["signature"].get<std::string>());
    if (BCryptVerifySignature(key.value, nullptr, digest.data(), static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0) < 0)
        throw std::runtime_error("update manifest signature verification failed");

    auto doc = Json::parse(payload);
    if (doc.dump(-1, ' ', false, Json::error_handler_t::strict) != payload)
        throw std::runtime_error("manifest payload must use canonical JSON encoding");
    if (!has_keys(doc, {"schema_version", "product", "generation", "version", "architecture",
                        "package_size", "package_sha256", "issued_at_unix_ms", "expires_at_unix_ms"}) ||
        !doc["schema_version"].is_number_unsigned() || doc["schema_version"].get<unsigned>() != 1 ||
        !doc["product"].is_string() || doc["product"] != "panopticon-windows-agent" ||
        !doc["version"].is_string() || !doc["architecture"].is_string() || !doc["package_sha256"].is_string())
        throw std::runtime_error("unknown update manifest schema, product, or field set");
    Manifest result;
    result.document = envelope;
    result.exact_envelope.assign(raw);
    result.generation = uint_field(doc, "generation");
    result.size = uint_field(doc, "package_size");
    const auto issued = uint_field(doc, "issued_at_unix_ms");
    result.expires = uint_field(doc, "expires_at_unix_ms");
    result.version = doc["version"].get<std::string>();
    result.architecture = doc["architecture"].get<std::string>();
    result.package_hash = doc["package_sha256"].get<std::string>();
    if (result.version.empty() || result.version.size() > 64 ||
        !std::all_of(result.version.begin(), result.version.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '.' || c == '-' || c == '+';
        })) throw std::runtime_error("invalid bounded product version string");
    if (result.architecture != "x64" && result.architecture != "arm64")
        throw std::runtime_error("unsupported package architecture");
    if (result.architecture != architecture) throw std::runtime_error("package architecture does not match this endpoint");
    if (!result.generation || !result.size || result.size > kMaximumUpdatePackageBytes ||
        result.package_hash.size() != 64 || !std::all_of(result.package_hash.begin(), result.package_hash.end(),
            [](unsigned char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))
        throw std::runtime_error("generation, package size, or SHA-256 identity is invalid");
    if (result.expires <= issued || result.expires - issued > kMaximumLifetimeMs ||
        (issued > now && issued - now > 300000) || now >= result.expires)
        throw std::runtime_error("manifest is expired or outside the bounded issue/expiry window");
    return result;
}

void check_no_reparse_components(const std::filesystem::path& path, bool final_must_be_directory) {
    if (!path.is_absolute() || path.has_root_name() == false || path.lexically_normal() != path)
        throw std::runtime_error("path must be absolute and lexically normalized");
    auto current = path.root_path();
    const auto relative = path.relative_path();
    for (auto it = relative.begin(); it != relative.end(); ++it) {
        current /= *it;
        const auto attributes = GetFileAttributesW(current.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) win_error("cannot inspect path component");
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) throw std::runtime_error("reparse-point path component refused");
        const bool final = std::next(it) == relative.end();
        if ((!final || final_must_be_directory) && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
            throw std::runtime_error("path component is not a directory");
    }
}

std::string digest_open_handle(HANDLE input, HANDLE output, std::uint64_t expected_size) {
    Algorithm algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("SHA-256 provider unavailable");
    DWORD object_size = 0, returned = 0;
    if (BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size), &returned, 0) < 0 || returned != sizeof(object_size))
        throw std::runtime_error("package hash object query failed");
    std::vector<std::uint8_t> object(object_size), digest(32), buffer(1024 * 1024);
    Hash hash;
    if (BCryptCreateHash(algorithm.value, &hash.value, object.data(), object_size, nullptr, 0, 0) < 0)
        throw std::runtime_error("package hash initialization failed");
    std::uint64_t total = 0;
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(input, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) win_error("cannot read update package");
        if (!read) break;
        if (total > expected_size || read > expected_size - total) throw std::runtime_error("package grew beyond signed size");
        if (BCryptHashData(hash.value, buffer.data(), read, 0) < 0) throw std::runtime_error("package SHA-256 update failed");
        if (output) {
            DWORD offset = 0;
            while (offset < read) {
                DWORD written = 0;
                if (!WriteFile(output, buffer.data() + offset, read - offset, &written, nullptr) || !written)
                    win_error("cannot write staged update package");
                offset += written;
            }
        }
        total += read;
    }
    if (total != expected_size) throw std::runtime_error("package size differs from signed manifest");
    if (BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("package SHA-256 finalization failed");
    if (output && !FlushFileBuffers(output)) win_error("cannot flush staged update package");
    return hex(digest);
}

Json load_state(const std::filesystem::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
        return Json{{"format", "panopticon_update_stage_state_v2"}, {"highest_generation", 0ull},
                    {"manifest", ""}, {"package_sha256", ""}, {"staged_filename", ""},
                    {"previous_generation", 0ull}, {"previous_manifest", ""}, {"previous_filename", ""},
                    {"rollback_intent_generation", 0ull}, {"publisher_trust_bundle", ""}, {"previous_trust_bundle", ""}};
    if (attributes == INVALID_FILE_ATTRIBUTES) win_error("cannot inspect update metadata");
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("update metadata is not a regular file");
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) win_error("cannot open update metadata");
    verify_not_reparse(file.value, false);
    validate_object_acl(file.value, false);
    FILE_STANDARD_INFO info{};
    if (!GetFileInformationByHandleEx(file.value, FileStandardInfo, &info, sizeof(info)) || info.EndOfFile.QuadPart <= 0 || info.EndOfFile.QuadPart > 1024 * 1024)
        throw std::runtime_error("update metadata is empty, unreadable, or oversized");
    std::string raw(static_cast<std::size_t>(info.EndOfFile.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.value, raw.data(), static_cast<DWORD>(raw.size()), &read, nullptr) || read != raw.size())
        throw std::runtime_error("cannot read complete update metadata");
    auto state = Json::parse(raw);
    const bool legacy = has_keys(state, {"format", "highest_generation", "manifest", "package_sha256", "staged_filename",
        "previous_generation", "previous_manifest", "previous_filename", "rollback_intent_generation"}) &&
        state["format"] == "panopticon_update_stage_state_v1";
    const bool current = has_keys(state, {"format", "highest_generation", "manifest", "package_sha256", "staged_filename",
        "previous_generation", "previous_manifest", "previous_filename", "rollback_intent_generation",
        "publisher_trust_bundle", "previous_trust_bundle"}) && state["format"] == "panopticon_update_stage_state_v2";
    if ((!legacy && !current) || !state["manifest"].is_string() || !state["previous_manifest"].is_string() ||
        !state["package_sha256"].is_string() || !state["staged_filename"].is_string() || !state["previous_filename"].is_string())
        throw std::runtime_error("malformed update metadata schema");
    if (legacy) {
        state["publisher_trust_bundle"] = "";
        state["previous_trust_bundle"] = "";
        state["format"] = "panopticon_update_stage_state_v2";
    } else if (!state["publisher_trust_bundle"].is_string() || !state["previous_trust_bundle"].is_string())
        throw std::runtime_error("malformed update trust provenance fields");
    return state;
}

void verify_staged_file(const std::filesystem::path& path, std::uint64_t expected_size,
                        const std::string& expected_hash) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        throw std::runtime_error("staged package is missing or unsafe");
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) win_error("cannot open staged package", GetLastError());
    verify_not_reparse(file.value, false);
    validate_object_acl(file.value, false);
    FILE_STANDARD_INFO info{};
    if (!GetFileInformationByHandleEx(file.value, FileStandardInfo, &info, sizeof(info)) ||
        info.EndOfFile.QuadPart < 0 || static_cast<std::uint64_t>(info.EndOfFile.QuadPart) != expected_size)
        throw std::runtime_error("staged package size does not match signed metadata");
    if (digest_open_handle(file.value, nullptr, expected_size) != expected_hash)
        throw std::runtime_error("staged package digest does not match signed metadata");
}

// Remove only abandoned transaction temporaries while holding the shared state
// lock. A process crash can leave a partially written package or metadata file;
// such files are never candidates for installation, but retaining them forever
// consumes the fixed staging volume. Handle-based deletion avoids following a
// path that changes after enumeration. The root ACL and per-object ACL are
// rechecked before deleting every candidate.
void recover_transaction_temporaries(const std::filesystem::path& root) {
    constexpr std::array<const wchar_t*, 3> patterns{
        L".stage-*.tmp", L"update-stage-state.json.tmp-*", L"publisher-trust-state.json.tmp-*"};
    constexpr std::size_t maximum_candidates = 4096;
    std::size_t examined = 0;
    for (const auto* pattern : patterns) {
        WIN32_FIND_DATAW entry{};
        const auto search_path = root / pattern;
        HANDLE search = FindFirstFileW(search_path.c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) continue;
            win_error("cannot enumerate abandoned update transaction files", error);
        }
        FindHandle search_guard{search};
        do {
            if (++examined > maximum_candidates) {
                throw std::runtime_error("abandoned update transaction count exceeds recovery bound");
            }
            if (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
                throw std::runtime_error("unsafe directory or reparse object occupies update temporary name");
            }
            const auto candidate = root / entry.cFileName;
            Handle file(CreateFileW(candidate.c_str(), DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (file.value == INVALID_HANDLE_VALUE) {
                const auto error = GetLastError();
                win_error("cannot open abandoned update transaction file", error);
            }
            verify_not_reparse(file.value, false);
            validate_object_acl(file.value, false);
            FILE_DISPOSITION_INFO disposition{TRUE};
            if (!SetFileInformationByHandle(file.value, FileDispositionInfo, &disposition, sizeof(disposition))) {
                const auto error = GetLastError();
                win_error("cannot remove abandoned update transaction file", error);
            }
        } while (FindNextFileW(search, &entry));
        const auto error = GetLastError();
        if (error != ERROR_NO_MORE_FILES) win_error("update temporary enumeration was incomplete", error);
    }
}

Manifest verify_persisted_manifest(const Json& state, const std::vector<PublisherPin>& pins) {
    const auto raw = state.value("manifest", std::string{});
    if (raw.empty()) throw std::runtime_error("durable update high-water record lacks its signed manifest");
    const auto envelope = Json::parse(raw);
    const auto document = Json::parse(envelope.at("payload").get<std::string>());
    const auto issued = uint_field(document, "issued_at_unix_ms");
    const auto architecture = document.at("architecture").get<std::string>();
    const auto manifest = verify_manifest(raw, pins, issued, architecture);
    if (manifest.generation != uint_field(state, "highest_generation") ||
        manifest.package_hash != state.value("package_sha256", std::string{}) ||
        state.value("staged_filename", std::string{}) != "package-" + std::to_string(manifest.generation) +
            "-" + manifest.package_hash + ".pkg")
        throw std::runtime_error("durable update high-water metadata disagrees with its signed manifest");
    return manifest;
}

void atomic_write(const std::filesystem::path& path, std::string_view bytes) {
    const auto temp = path.wstring() + L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    Handle file(CreateFileW(temp.c_str(), GENERIC_WRITE | READ_CONTROL, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) win_error("cannot create update metadata temporary file");
    verify_not_reparse(file.value, false);
    validate_object_acl(file.value, false);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(file.value, bytes.data() + offset, chunk, &written, nullptr) || !written)
            win_error("cannot write update metadata");
        offset += written;
    }
    if (!FlushFileBuffers(file.value)) win_error("cannot flush update metadata");
    CloseHandle(std::exchange(file.value, INVALID_HANDLE_VALUE)); // close before atomic replacement
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError(); DeleteFileW(temp.c_str()); win_error("cannot atomically replace update metadata", error);
    }
}

std::filesystem::path safe_child(const std::filesystem::path& root, const std::string& filename) {
    if (filename.empty() || filename.find_first_of("\\/:") != std::string::npos || filename == "." || filename == "..")
        throw std::runtime_error("unsafe staged package filename in metadata");
    return root / std::filesystem::path(filename);
}

struct ParsedTrustBundle {
    Json envelope;
    std::uint64_t generation{};
    std::vector<PublisherTrustKey> keys;
};

ParsedTrustBundle parse_trust_bundle(std::string_view raw, const std::vector<PublisherPin>& bootstrap,
                                    std::uint64_t now, bool require_active = true) {
    Json envelope;
    const auto payload = verify_signed_payload(raw, "panopticon_signed_publisher_trust_v1", kTrustDomain, bootstrap, envelope);
    const auto document = Json::parse(payload);
    if (document.dump(-1, ' ', false, Json::error_handler_t::strict) != payload ||
        !has_keys(document, {"schema_version", "product", "generation", "issued_at_unix_ms", "expires_at_unix_ms", "keys"}) ||
        !document["schema_version"].is_number_unsigned() || document["schema_version"].get<unsigned>() != 1 ||
        !document["product"].is_string() || document["product"] != "panopticon-windows-agent" || !document["keys"].is_array())
        throw std::runtime_error("publisher trust payload is noncanonical or has an unsupported closed schema");
    ParsedTrustBundle result;
    result.envelope = std::move(envelope);
    result.generation = uint_field(document, "generation");
    const auto issued = uint_field(document, "issued_at_unix_ms"), expires = uint_field(document, "expires_at_unix_ms");
    if (!result.generation || expires <= issued || expires - issued > kMaximumLifetimeMs ||
        (issued > now && issued - now > 300000) || now >= expires)
        throw std::runtime_error("publisher trust generation or issue/expiry window is invalid");
    if (document["keys"].empty() || document["keys"].size() > kMaximumUpdateTrustKeys)
        throw std::runtime_error("publisher keyset must contain 1..8 bounded keys");
    std::set<std::string> ids;
    for (const auto& item : document["keys"]) {
        if (!has_keys(item, {"key_id", "spki_der_hex", "activates_at_unix_ms", "retires_at_unix_ms", "revoked_at_unix_ms"}) ||
            !item["key_id"].is_string() || !item["spki_der_hex"].is_string())
            throw std::runtime_error("publisher trust key has unknown fields or invalid types");
        PublisherTrustKey key;
        key.publisher.key_id = item["key_id"].get<std::string>();
        key.publisher.subject_public_key_info_der = decode_hex(item["spki_der_hex"].get<std::string>(), 4096);
        key.activates_at_unix_ms = uint_field(item, "activates_at_unix_ms");
        key.retires_at_unix_ms = uint_field(item, "retires_at_unix_ms");
        key.revoked_at_unix_ms = uint_field(item, "revoked_at_unix_ms");
        if (key.publisher.key_id.size() != 64 || !std::all_of(key.publisher.key_id.begin(), key.publisher.key_id.end(),
                [](unsigned char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) ||
            sha256(key.publisher.subject_public_key_info_der) != key.publisher.key_id || !ids.insert(key.publisher.key_id).second)
            throw std::runtime_error("publisher key fingerprint is invalid or duplicated");
        if (key.activates_at_unix_ms < issued || key.activates_at_unix_ms >= key.retires_at_unix_ms ||
            key.retires_at_unix_ms > expires || (key.revoked_at_unix_ms &&
                (key.revoked_at_unix_ms < key.activates_at_unix_ms || key.revoked_at_unix_ms > expires)))
            throw std::runtime_error("publisher key activation, retirement, or revocation interval is invalid");
        // Validate each stored key is actually importable as ECDSA P-256 now,
        // not only when it is eventually selected for a package signature.
        LocalMemory decoded; DWORD decoded_size = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, key.publisher.subject_public_key_info_der.data(),
            static_cast<DWORD>(key.publisher.subject_public_key_info_der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
            &decoded.value, &decoded_size)) throw std::runtime_error("publisher key SPKI DER is invalid");
        auto* info = static_cast<CERT_PUBLIC_KEY_INFO*>(decoded.value);
        Key imported;
        wchar_t algorithm[64]{}; DWORD got = 0;
        if (!info->Algorithm.pszObjId || std::string_view(info->Algorithm.pszObjId) != szOID_ECC_PUBLIC_KEY ||
            !CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0, nullptr, &imported.value) ||
            BCryptGetProperty(imported.value, BCRYPT_ALGORITHM_NAME, reinterpret_cast<PUCHAR>(algorithm), sizeof(algorithm), &got, 0) < 0 ||
            std::wstring_view(algorithm) != BCRYPT_ECDSA_P256_ALGORITHM)
            throw std::runtime_error("publisher trust key is not importable ECDSA P-256");
        result.keys.push_back(std::move(key));
    }
    std::vector<const PublisherTrustKey*> rotation;
    for (const auto& key : result.keys)
        if (!key.revoked_at_unix_ms || key.revoked_at_unix_ms > now) rotation.push_back(&key);
    std::sort(rotation.begin(), rotation.end(), [](const auto* a, const auto* b) { return a->activates_at_unix_ms < b->activates_at_unix_ms; });
    for (std::size_t i = 1; i < rotation.size(); ++i) {
        const auto prior_end = rotation[i - 1]->revoked_at_unix_ms
            ? (std::min)(rotation[i - 1]->retires_at_unix_ms, rotation[i - 1]->revoked_at_unix_ms)
            : rotation[i - 1]->retires_at_unix_ms;
        const auto next_end = rotation[i]->revoked_at_unix_ms
            ? (std::min)(rotation[i]->retires_at_unix_ms, rotation[i]->revoked_at_unix_ms)
            : rotation[i]->retires_at_unix_ms;
        const auto overlap_end = (std::min)(prior_end, next_end);
        const auto overlap = overlap_end > rotation[i]->activates_at_unix_ms
            ? overlap_end - rotation[i]->activates_at_unix_ms : 0;
        if (overlap < kRotationOverlapMs) throw std::runtime_error("publisher rotation requires at least 24 hours of key overlap");
    }
    if (require_active && std::none_of(result.keys.begin(), result.keys.end(), [&](const auto& key) {
        return key.activates_at_unix_ms <= now && now < key.retires_at_unix_ms &&
            (!key.revoked_at_unix_ms || now < key.revoked_at_unix_ms);
    })) throw std::runtime_error("trust bundle has no publisher active at the current time");
    return result;
}

Json read_trust_state(const std::filesystem::path& root) {
    const auto path = root / L"publisher-trust-state.json";
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) return nullptr;
    if (attributes == INVALID_FILE_ATTRIBUTES) win_error("cannot inspect publisher trust state");
    if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("publisher trust state is not a regular file");
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) win_error("cannot open publisher trust state");
    verify_not_reparse(file.value, false); validate_object_acl(file.value, false);
    FILE_STANDARD_INFO info{};
    if (!GetFileInformationByHandleEx(file.value, FileStandardInfo, &info, sizeof(info)) || info.EndOfFile.QuadPart <= 0 ||
        info.EndOfFile.QuadPart > kMaximumUpdateManifestBytes + 4096)
        throw std::runtime_error("publisher trust state is empty or oversized");
    std::string raw(static_cast<std::size_t>(info.EndOfFile.QuadPart), '\0'); DWORD read = 0;
    if (!ReadFile(file.value, raw.data(), static_cast<DWORD>(raw.size()), &read, nullptr) || read != raw.size())
        throw std::runtime_error("cannot read complete publisher trust state");
    const auto state = Json::parse(raw);
    if (!has_keys(state, {"format", "generation", "signed_bundle"}) || state["format"] != "panopticon_publisher_trust_state_v1" ||
        !state["signed_bundle"].is_string()) throw std::runtime_error("publisher trust state schema is invalid");
    return state;
}

}  // namespace

PublisherTrustStore::PublisherTrustStore(std::filesystem::path root, std::vector<PublisherPin> bootstrap_pins)
    : root_(std::filesystem::absolute(std::move(root)).lexically_normal()), bootstrap_pins_(std::move(bootstrap_pins)) {
    if (root_.root_name().native().size() != 2 || GetDriveTypeW(root_.root_path().c_str()) != DRIVE_FIXED)
        throw std::invalid_argument("publisher trust root must be on a local fixed drive");
    if (bootstrap_pins_.empty() || bootstrap_pins_.size() > kMaximumUpdateTrustKeys)
        throw std::invalid_argument("bootstrap trust must contain 1..8 caller-provisioned pins");
    std::set<std::string> ids;
    for (const auto& pin : bootstrap_pins_) {
        if (pin.key_id.size() != 64 || pin.subject_public_key_info_der.empty() ||
            pin.subject_public_key_info_der.size() > 4096 || !ids.insert(pin.key_id).second)
            throw std::invalid_argument("invalid, duplicate, or oversized bootstrap pin");
    }
    check_no_reparse_components(root_, true);
    auto root_handle = open_update_directory(root_);
    const auto attributes = GetFileAttributesW(root_.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        throw std::invalid_argument("publisher trust root must already exist as a directory");
}

PublisherTrustResult PublisherTrustStore::install_signed_bundle(std::string_view signed_bundle,
                                                                  std::uint64_t now_unix_ms) {
    PublisherTrustResult result;
    try {
        auto root_handle = open_update_directory(root_);
        StateLock lock(root_);
        recover_transaction_temporaries(root_);
        const auto parsed = parse_trust_bundle(signed_bundle, bootstrap_pins_, now_unix_ms);
        const auto state = read_trust_state(root_);
        if (!state.is_null()) {
            const auto previous_raw = state.at("signed_bundle").get<std::string>();
            const auto previous_envelope = Json::parse(previous_raw);
            const auto previous_payload = previous_envelope.at("payload").get<std::string>();
            const auto previous_document = Json::parse(previous_payload);
            const auto previous_issue = uint_field(previous_document, "issued_at_unix_ms");
            const auto previous = parse_trust_bundle(previous_raw, bootstrap_pins_, previous_issue, false);
            const auto previous_generation = uint_field(state, "generation");
            if (previous.generation != previous_generation)
                throw std::runtime_error("durable trust generation disagrees with signed prior bundle");
            if (parsed.generation < previous_generation)
                throw std::runtime_error("publisher trust replay refused below durable generation high-water");
            if (parsed.generation == previous_generation) {
                if (previous_payload == parsed.envelope.at("payload").get<std::string>()) {
                    result.state = "already_installed"; result.generation = previous_generation; return result;
                }
                throw std::runtime_error("publisher trust fork refused at an existing generation");
            }
        }
        const Json next{{"format", "panopticon_publisher_trust_state_v1"},
            {"generation", parsed.generation}, {"signed_bundle", std::string(signed_bundle)}};
        atomic_write(root_ / L"publisher-trust-state.json", next.dump());
        result.state = "installed"; result.generation = parsed.generation;
    } catch (const std::exception& error) {
        result.state = "unavailable"; result.error = error.what();
    }
    return result;
}

PublisherTrustSnapshot PublisherTrustStore::snapshot(std::uint64_t now_unix_ms) const {
    PublisherTrustSnapshot result;
    try {
        auto root_handle = open_update_directory(root_);
        StateLock lock(root_);
        return snapshot_locked(now_unix_ms);
    } catch (const std::exception& error) {
        result.state = "unavailable"; result.error = error.what();
    }
    return result;
}

PublisherTrustSnapshot PublisherTrustStore::snapshot_locked(std::uint64_t now_unix_ms) const {
    PublisherTrustSnapshot result;
    try {
        const auto state = read_trust_state(root_);
        if (state.is_null()) { result.state = "unknown"; result.error = "no signed publisher trust bundle has been committed"; return result; }
        const auto raw = state.at("signed_bundle").get<std::string>();
        const auto parsed = parse_trust_bundle(raw, bootstrap_pins_, now_unix_ms);
        result.generation = parsed.generation;
        if (uint_field(state, "generation") != result.generation)
            throw std::runtime_error("durable trust generation disagrees with signed bundle");
        result.keys = parsed.keys;
        result.signed_bundle = raw;
        for (const auto& key : result.keys)
            if (key.activates_at_unix_ms <= now_unix_ms && now_unix_ms < key.retires_at_unix_ms &&
                (!key.revoked_at_unix_ms || now_unix_ms < key.revoked_at_unix_ms))
                result.active_publishers.push_back(key.publisher);
        if (result.active_publishers.empty()) throw std::runtime_error("no publisher key is active at the requested time");
        result.state = "healthy";
    } catch (const std::exception& error) {
        result.state = "unavailable"; result.active_publishers.clear(); result.keys.clear(); result.error = error.what();
    }
    return result;
}

PublisherTrustSnapshot PublisherTrustStore::historical_publishers(
    std::string_view signed_bundle, std::uint64_t manifest_issued_at_unix_ms) const {
    PublisherTrustSnapshot result;
    try {
        Json envelope;
        const auto payload = verify_signed_payload(signed_bundle, "panopticon_signed_publisher_trust_v1",
            kTrustDomain, bootstrap_pins_, envelope);
        const auto document = Json::parse(payload);
        const auto bundle_issue = uint_field(document, "issued_at_unix_ms");
        const auto bundle_expiry = uint_field(document, "expires_at_unix_ms");
        if (manifest_issued_at_unix_ms < bundle_issue || manifest_issued_at_unix_ms >= bundle_expiry)
            throw std::runtime_error("package manifest issue time is outside its signed publisher trust bundle window");
        const auto parsed = parse_trust_bundle(signed_bundle, bootstrap_pins_, bundle_issue, false);
        result.generation = parsed.generation;
        result.keys = parsed.keys;
        result.signed_bundle.assign(signed_bundle);
        for (const auto& key : result.keys)
            if (key.activates_at_unix_ms <= manifest_issued_at_unix_ms &&
                manifest_issued_at_unix_ms < key.retires_at_unix_ms &&
                (!key.revoked_at_unix_ms || manifest_issued_at_unix_ms < key.revoked_at_unix_ms))
                result.active_publishers.push_back(key.publisher);
        if (result.active_publishers.empty()) throw std::runtime_error("historical bundle had no publisher active at package issue time");
        result.state = "healthy";
    } catch (const std::exception& error) {
        result.state = "unavailable"; result.active_publishers.clear(); result.keys.clear(); result.error = error.what();
    }
    return result;
}

UpdatePackageStore::UpdatePackageStore(std::filesystem::path root, std::vector<PublisherPin> pins)
    : root_(std::filesystem::absolute(std::move(root)).lexically_normal()), pins_(std::move(pins)) {
    if (root_.root_name().native().size() != 2 || GetDriveTypeW(root_.root_path().c_str()) != DRIVE_FIXED)
        throw std::invalid_argument("update staging root must be on a local fixed drive");
    if (pins_.empty() || pins_.size() > kMaximumUpdateTrustKeys)
        throw std::invalid_argument("publisher trust set must contain 1..8 pinned keys");
    std::set<std::string> ids;
    for (const auto& pin : pins_) {
        if (pin.key_id.size() != 64 || pin.subject_public_key_info_der.empty() ||
            pin.subject_public_key_info_der.size() > 4096 || !ids.insert(pin.key_id).second)
            throw std::invalid_argument("invalid, duplicate, or oversized publisher pin");
    }
    check_no_reparse_components(root_, true);
    auto root_handle = open_update_directory(root_);
    const auto root_attributes = GetFileAttributesW(root_.c_str());
    if (root_attributes == INVALID_FILE_ATTRIBUTES || !(root_attributes & FILE_ATTRIBUTE_DIRECTORY))
        throw std::invalid_argument("fixed update staging root must already exist as a directory");
}

UpdatePackageStore::UpdatePackageStore(std::filesystem::path root, PublisherTrustStore& trust_store)
    : root_(std::filesystem::absolute(std::move(root)).lexically_normal()), trust_store_(&trust_store) {
    if (root_.root_name().native().size() != 2 || GetDriveTypeW(root_.root_path().c_str()) != DRIVE_FIXED)
        throw std::invalid_argument("update staging root must be on a local fixed drive");
    if (root_ != trust_store.root_)
        throw std::invalid_argument("publisher trust state and update stage must share one protected root and lock");
    check_no_reparse_components(root_, true);
    auto root_handle = open_update_directory(root_);
    const auto root_attributes = GetFileAttributesW(root_.c_str());
    if (root_attributes == INVALID_FILE_ATTRIBUTES || !(root_attributes & FILE_ATTRIBUTE_DIRECTORY))
        throw std::invalid_argument("fixed update staging root must already exist as a directory");
}

UpdateResult UpdatePackageStore::stage(std::string_view raw, const std::filesystem::path& source,
                                      std::uint64_t now, std::string_view architecture) {
    UpdateResult result;
    try {
        auto root_handle = open_update_directory(root_);
        StateLock state_lock(root_);
        recover_transaction_temporaries(root_);
        PublisherTrustSnapshot trust_snapshot;
        const std::vector<PublisherPin>* manifest_pins = &pins_;
        if (trust_store_) {
            trust_snapshot = trust_store_->snapshot_locked(now);
            if (trust_snapshot.state != "healthy")
                throw std::runtime_error("publisher trust is " + trust_snapshot.state + ": " + trust_snapshot.error);
            manifest_pins = &trust_snapshot.active_publishers;
        }
        const auto manifest = verify_manifest(raw, *manifest_pins, now, architecture);
        result.generation = manifest.generation;
        result.version = manifest.version;
        result.package_sha256 = manifest.package_hash;

        check_no_reparse_components(source, false);
        Handle input(CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (input.value == INVALID_HANDLE_VALUE) win_error("cannot open source package");
        FILE_ATTRIBUTE_TAG_INFO tag{}; FILE_STANDARD_INFO source_info{};
        if (!GetFileInformationByHandleEx(input.value, FileAttributeTagInfo, &tag, sizeof(tag)) ||
            !GetFileInformationByHandleEx(input.value, FileStandardInfo, &source_info, sizeof(source_info)))
            win_error("cannot inspect source package handle");
        if (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT || tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ||
            source_info.EndOfFile.QuadPart < 0 || static_cast<std::uint64_t>(source_info.EndOfFile.QuadPart) != manifest.size)
            throw std::runtime_error("source package is not a regular file of the signed size");

        const auto state_path = root_ / L"update-stage-state.json";
        auto state = load_state(state_path);
        const auto prior_generation = uint_field(state, "highest_generation");
        std::string prior_trust_bundle = state.value("publisher_trust_bundle", std::string{});
        if (prior_generation) {
            auto prior_pins = pins_;
            if (trust_store_) {
                const auto prior_envelope = Json::parse(state.value("manifest", std::string{}));
                const auto prior_document = Json::parse(prior_envelope.at("payload").get<std::string>());
                const auto prior_issued = uint_field(prior_document, "issued_at_unix_ms");
                if (prior_trust_bundle.empty()) prior_trust_bundle = trust_snapshot.signed_bundle;
                const auto historical = trust_store_->historical_publishers(prior_trust_bundle, prior_issued);
                if (historical.state != "healthy")
                    throw std::runtime_error("prior package trust provenance is " + historical.state + ": " + historical.error);
                prior_pins = historical.active_publishers;
            }
            (void)verify_persisted_manifest(state, prior_pins);
        }
        const auto manifest_envelope = Json::parse(raw.begin(), raw.end());
        if (prior_generation && manifest.generation < prior_generation)
            throw std::runtime_error("update replay refused: generation is below durable high-water mark");
        if (prior_generation == manifest.generation && prior_generation != 0 &&
            state.value("manifest", std::string{}) != manifest_envelope.dump())
            throw std::runtime_error("update fork refused: generation has different signed manifest");

        const auto filename = "package-" + std::to_string(manifest.generation) + "-" + manifest.package_hash + ".pkg";
        const auto final_path = safe_child(root_, filename);
        const auto temp_path = root_ / (L".stage-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".tmp");
        Handle output(CreateFileW(temp_path.c_str(), GENERIC_WRITE | READ_CONTROL, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (output.value == INVALID_HANDLE_VALUE) win_error("cannot create package staging temporary");
        verify_not_reparse(output.value, false);
        validate_object_acl(output.value, false);
        std::string actual_hash;
        try { actual_hash = digest_open_handle(input.value, output.value, manifest.size); }
        catch (...) { CloseHandle(std::exchange(output.value, INVALID_HANDLE_VALUE)); DeleteFileW(temp_path.c_str()); throw; }
        CloseHandle(std::exchange(output.value, INVALID_HANDLE_VALUE));
        if (actual_hash != manifest.package_hash) { DeleteFileW(temp_path.c_str()); throw std::runtime_error("package SHA-256 does not match signed manifest"); }

        if (prior_generation == manifest.generation && prior_generation != 0) {
            DeleteFileW(temp_path.c_str());
            const auto prior_file = safe_child(root_, state.value("staged_filename", std::string{}));
            verify_staged_file(prior_file, manifest.size, manifest.package_hash);
            result.state = "already_staged";
            result.staged_path = prior_file;
            if (!state.value("previous_filename", std::string{}).empty())
                result.rollback_candidate = safe_child(root_, state.value("previous_filename", std::string{}));
            return result;
        }

        if (!MoveFileExW(temp_path.c_str(), final_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
            const auto error = GetLastError(); DeleteFileW(temp_path.c_str());
            if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
                verify_staged_file(final_path, manifest.size, manifest.package_hash);
            else win_error("cannot atomically promote staged package", error);
        }
        Json next{{"format", "panopticon_update_stage_state_v2"},
                  {"highest_generation", manifest.generation}, {"manifest", manifest_envelope.dump()},
                  {"package_sha256", manifest.package_hash}, {"staged_filename", filename},
                  {"previous_generation", prior_generation},
                  {"previous_manifest", state.value("manifest", std::string{})},
                  {"previous_filename", state.value("staged_filename", std::string{})},
                  {"rollback_intent_generation", 0ull},
                  {"publisher_trust_bundle", trust_store_ ? trust_snapshot.signed_bundle : std::string{}},
                  {"previous_trust_bundle", prior_trust_bundle}};
        try { atomic_write(state_path, next.dump()); }
        catch (...) {
            // Leave the content-addressed package for safe retry/reconciliation;
            // never advance memory state or delete a previously committed package.
            throw;
        }
        result.state = "staged";
        result.staged_path = final_path;
        if (prior_generation) result.rollback_candidate = safe_child(root_, state.value("staged_filename", std::string{}));
    } catch (const std::exception& error) {
        result.state = "failed";
        result.error = error.what();
    }
    return result;
}

UpdateResult UpdatePackageStore::record_rollback_intent() {
    UpdateResult result;
    try {
        auto root_handle = open_update_directory(root_);
        StateLock state_lock(root_);
        recover_transaction_temporaries(root_);
        const auto state_path = root_ / L"update-stage-state.json";
        auto state = load_state(state_path);
        const auto previous_generation = uint_field(state, "previous_generation");
        const auto current_generation = uint_field(state, "highest_generation");
        if (!current_generation) throw std::runtime_error("no staged update metadata is available");
        auto current_pins = pins_;
        if (trust_store_) {
            const auto current_envelope = Json::parse(state.value("manifest", std::string{}));
            const auto current_document = Json::parse(current_envelope.at("payload").get<std::string>());
            const auto current_issued = uint_field(current_document, "issued_at_unix_ms");
            const auto provenance = state.value("publisher_trust_bundle", std::string{});
            const auto historical = trust_store_->historical_publishers(provenance, current_issued);
            if (historical.state != "healthy")
                throw std::runtime_error("current package trust provenance is " + historical.state + ": " + historical.error);
            current_pins = historical.active_publishers;
        }
        (void)verify_persisted_manifest(state, current_pins);
        const auto previous_name = state.value("previous_filename", std::string{});
        if (!previous_generation || previous_name.empty()) throw std::runtime_error("no prior staged package is available");
        const auto candidate = safe_child(root_, previous_name);
        const auto previous_raw = state.value("previous_manifest", std::string{});
        if (previous_raw.empty()) throw std::runtime_error("prior signed manifest is unavailable");
        const auto previous_envelope = Json::parse(previous_raw);
        const auto previous_document = Json::parse(previous_envelope.at("payload").get<std::string>());
        const auto issued = uint_field(previous_document, "issued_at_unix_ms");
        const auto previous_architecture = previous_document.at("architecture").get<std::string>();
        auto rollback_pins = pins_;
        if (trust_store_) {
            const auto provenance = state.value("previous_trust_bundle", std::string{});
            const auto historical = trust_store_->historical_publishers(provenance, issued);
            if (historical.state != "healthy")
                throw std::runtime_error("rollback package trust provenance is " + historical.state + ": " + historical.error);
            rollback_pins = historical.active_publishers;
        }
        const auto verified = verify_manifest(previous_raw, rollback_pins, issued, previous_architecture);
        if (verified.generation != previous_generation || previous_name != "package-" +
            std::to_string(previous_generation) + "-" + verified.package_hash + ".pkg")
            throw std::runtime_error("prior rollback metadata does not match its signed package identity");
        verify_staged_file(candidate, verified.size, verified.package_hash);
        state["rollback_intent_generation"] = previous_generation;
        atomic_write(state_path, state.dump());
        result.state = "rollback_intent_recorded";
        result.generation = previous_generation;
        result.rollback_candidate = candidate;
        result.error = "selection recorded only; external authorization and installer rollback are not performed";
    } catch (const std::exception& error) {
        result.state = "failed";
        result.error = error.what();
    }
    return result;
}

}  // namespace panopticon::officer::deployment
