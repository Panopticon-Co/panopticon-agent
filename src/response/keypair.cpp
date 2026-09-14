#include "panopticon/officer/response/keypair.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>

#include <cstring>
#include <fstream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace panopticon::officer::response {

namespace {

// BCRYPT_ECCKEY_BLOB header: { ULONG dwMagic; ULONG cbKey; } followed by
// X (cbKey bytes), Y (cbKey bytes), and -- for the private blob only --
// d (cbKey bytes). cbKey is 32 for P-256.
constexpr ULONG kP256KeyBytes = 32;
constexpr std::size_t kBlobHeaderBytes = 8;

class AlgorithmHandle {
public:
    explicit AlgorithmHandle(LPCWSTR algorithm_id) {
        BCryptOpenAlgorithmProvider(&handle_, algorithm_id, nullptr, 0);
    }
    ~AlgorithmHandle() {
        if (handle_) BCryptCloseAlgorithmProvider(handle_, 0);
    }
    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
    [[nodiscard]] BCRYPT_ALG_HANDLE get() const { return handle_; }
    [[nodiscard]] bool valid() const { return handle_ != nullptr; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class KeyHandle {
public:
    KeyHandle() = default;
    ~KeyHandle() {
        if (handle_) BCryptDestroyKey(handle_);
    }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    [[nodiscard]] BCRYPT_KEY_HANDLE* address() { return &handle_; }
    [[nodiscard]] BCRYPT_KEY_HANDLE get() const { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

bool restrict_to_current_user(const std::wstring& path, std::string& error_message) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error_message = "cannot open process token to restrict key file ACL";
        return false;
    }
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<unsigned char> buffer(needed);
    const bool have_user =
        needed != 0 && GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed) != FALSE;
    PSID user_sid = have_user ? reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid : nullptr;
    if (!have_user || user_sid == nullptr) {
        CloseHandle(token);
        error_message = "cannot resolve current user SID to restrict key file ACL";
        return false;
    }

    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = GENERIC_ALL;
    access.grfAccessMode = SET_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(user_sid);

    PACL new_acl = nullptr;
    const DWORD result = SetEntriesInAclW(1, &access, nullptr, &new_acl);
    CloseHandle(token);
    if (result != ERROR_SUCCESS || new_acl == nullptr) {
        error_message = "cannot build a restrictive ACL for the key file";
        return false;
    }
    const DWORD applied = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, user_sid, nullptr, new_acl, nullptr);
    LocalFree(new_acl);
    if (applied != ERROR_SUCCESS) {
        error_message = "cannot apply a restrictive ACL to the key file";
        return false;
    }
    return true;
}

}  // namespace

std::optional<EcKeyPair> generate_ec_p256_keypair(std::string& error_message) {
    AlgorithmHandle alg{BCRYPT_ECDSA_P256_ALGORITHM};
    if (!alg.valid()) {
        error_message = "cannot open ECDSA P-256 algorithm provider";
        return std::nullopt;
    }
    KeyHandle key;
    if (BCryptGenerateKeyPair(alg.get(), key.address(), 256, 0) != 0) {
        error_message = "cannot generate ECDSA P-256 key pair";
        return std::nullopt;
    }
    if (BCryptFinalizeKeyPair(key.get(), 0) != 0) {
        error_message = "cannot finalize ECDSA P-256 key pair";
        return std::nullopt;
    }

    ULONG public_size = 0;
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &public_size, 0) != 0 ||
        public_size != kBlobHeaderBytes + 2 * kP256KeyBytes) {
        error_message = "unexpected ECDSA public key blob size";
        return std::nullopt;
    }
    std::vector<std::uint8_t> public_blob(public_size);
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, public_blob.data(),
                         static_cast<ULONG>(public_blob.size()), &public_size, 0) != 0) {
        error_message = "cannot export ECDSA public key";
        return std::nullopt;
    }

    ULONG private_size = 0;
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &private_size, 0) != 0) {
        error_message = "cannot size ECDSA private key export";
        return std::nullopt;
    }
    std::vector<std::uint8_t> private_blob(private_size);
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB, private_blob.data(),
                         static_cast<ULONG>(private_blob.size()), &private_size, 0) != 0) {
        error_message = "cannot export ECDSA private key";
        return std::nullopt;
    }

    EcKeyPair result;
    result.private_blob = std::move(private_blob);
    result.public_point[0] = 0x04;
    std::memcpy(result.public_point.data() + 1, public_blob.data() + kBlobHeaderBytes, 2 * kP256KeyBytes);
    return result;
}

std::optional<RawSignature> sign_raw(const EcKeyPair& keypair, const std::vector<std::uint8_t>& data,
                                      std::string& error_message) {
    AlgorithmHandle ecdsa_alg{BCRYPT_ECDSA_P256_ALGORITHM};
    if (!ecdsa_alg.valid()) {
        error_message = "cannot open ECDSA P-256 algorithm provider";
        return std::nullopt;
    }
    KeyHandle key;
    if (BCryptImportKeyPair(ecdsa_alg.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB, key.address(),
                             const_cast<PUCHAR>(keypair.private_blob.data()),
                             static_cast<ULONG>(keypair.private_blob.size()), 0) != 0) {
        error_message = "cannot import ECDSA private key";
        return std::nullopt;
    }

    AlgorithmHandle sha256_alg{BCRYPT_SHA256_ALGORITHM};
    if (!sha256_alg.valid()) {
        error_message = "cannot open SHA-256 algorithm provider";
        return std::nullopt;
    }
    BCRYPT_HASH_HANDLE hash_handle = nullptr;
    if (BCryptCreateHash(sha256_alg.get(), &hash_handle, nullptr, 0, nullptr, 0, 0) != 0) {
        error_message = "cannot create SHA-256 hash object";
        return std::nullopt;
    }
    std::array<std::uint8_t, 32> digest{};
    const bool hashed =
        BCryptHashData(hash_handle, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0) == 0 &&
        BCryptFinishHash(hash_handle, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0;
    BCryptDestroyHash(hash_handle);
    if (!hashed) {
        error_message = "cannot hash data before signing";
        return std::nullopt;
    }

    ULONG signature_size = 0;
    if (BCryptSignHash(key.get(), nullptr, digest.data(), static_cast<ULONG>(digest.size()), nullptr, 0,
                        &signature_size, 0) != 0 ||
        signature_size != 64) {
        error_message = "unexpected ECDSA signature size";
        return std::nullopt;
    }
    RawSignature signature{};
    ULONG written = 0;
    if (BCryptSignHash(key.get(), nullptr, digest.data(), static_cast<ULONG>(digest.size()), signature.data(),
                        static_cast<ULONG>(signature.size()), &written, 0) != 0 ||
        written != signature.size()) {
        error_message = "cannot sign data";
        return std::nullopt;
    }
    return signature;
}

bool store_ec_keypair(const std::filesystem::path& path, const EcKeyPair& keypair, std::string& error_message) {
    std::error_code filesystem_error;
    std::filesystem::create_directories(path.parent_path(), filesystem_error);
    if (filesystem_error) {
        error_message = "cannot create key directory";
        return false;
    }
    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output{temporary, std::ios::trunc | std::ios::binary};
        if (!output) {
            error_message = "cannot write key file";
            return false;
        }
        const auto size = static_cast<std::uint32_t>(keypair.private_blob.size());
        output.write(reinterpret_cast<const char*>(&size), sizeof(size));
        output.write(reinterpret_cast<const char*>(keypair.private_blob.data()), keypair.private_blob.size());
        output.flush();
        if (!output) {
            error_message = "cannot persist key file";
            return false;
        }
    }
    std::string acl_error;
    if (!restrict_to_current_user(std::filesystem::path{temporary}.wstring(), acl_error)) {
        error_message = acl_error;
    }
    std::filesystem::rename(temporary, path, filesystem_error);
    if (filesystem_error) {
        std::filesystem::remove(temporary, filesystem_error);
        error_message = "cannot publish key file";
        return false;
    }
    return true;
}

std::optional<EcKeyPair> load_ec_keypair(const std::filesystem::path& path, std::string& error_message) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        error_message = "key file is absent";
        return std::nullopt;
    }
    std::uint32_t size = 0;
    input.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!input || size == 0 || size > 4096) {
        error_message = "key file is truncated or has an implausible size";
        return std::nullopt;
    }
    std::vector<std::uint8_t> private_blob(size);
    input.read(reinterpret_cast<char*>(private_blob.data()), size);
    if (!input || static_cast<std::uint32_t>(input.gcount()) != size) {
        error_message = "key file is truncated";
        return std::nullopt;
    }

    // Re-derive the public point by importing the private blob and
    // re-exporting the public half -- BCRYPT_ECCPRIVATE_BLOB already
    // contains X/Y, but round-tripping through CNG confirms the blob is a
    // genuinely importable key, not merely a file of the right byte count.
    AlgorithmHandle alg{BCRYPT_ECDSA_P256_ALGORITHM};
    if (!alg.valid()) {
        error_message = "cannot open ECDSA P-256 algorithm provider";
        return std::nullopt;
    }
    KeyHandle key;
    if (BCryptImportKeyPair(alg.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB, key.address(), private_blob.data(),
                             static_cast<ULONG>(private_blob.size()), 0) != 0) {
        error_message = "key file does not contain a valid ECDSA P-256 private key";
        return std::nullopt;
    }
    ULONG public_size = 0;
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &public_size, 0) != 0 ||
        public_size != kBlobHeaderBytes + 2 * kP256KeyBytes) {
        error_message = "cannot re-derive public key from stored private key";
        return std::nullopt;
    }
    std::vector<std::uint8_t> public_blob(public_size);
    if (BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, public_blob.data(),
                         static_cast<ULONG>(public_blob.size()), &public_size, 0) != 0) {
        error_message = "cannot export re-derived public key";
        return std::nullopt;
    }

    EcKeyPair result;
    result.private_blob = std::move(private_blob);
    result.public_point[0] = 0x04;
    std::memcpy(result.public_point.data() + 1, public_blob.data() + kBlobHeaderBytes, 2 * kP256KeyBytes);
    return result;
}

}  // namespace panopticon::officer::response
