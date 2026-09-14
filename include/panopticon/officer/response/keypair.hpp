#pragma once

// Phase 13: the endpoint-held half of enrollment cryptographic identity
// (docs/adr/004-agent-enrollment-identity.md in panopticon-manager). Built
// entirely on Windows CNG (bcrypt.h) -- the same OS-shipped, already-linked
// dependency officer-delivery's Uploader already uses for random UUIDs, so
// this adds no new library. ECDSA P-256 is CNG's most broadly-available EC
// algorithm; the private key never leaves this process as anything but an
// opaque, ACL-locked local blob.

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace panopticon::officer::response {

// The raw uncompressed NIST P-256 point (0x04 || X || Y) -- the exact wire
// format panopticon-contracts/schema/enrollment_request.schema.json expects
// for public_key, so callers can base64-encode this directly.
using PublicKeyPoint = std::array<std::uint8_t, 65>;

// Raw r||s ECDSA signature (32 + 32 bytes) -- CNG's native BCryptSignHash
// output format for ECDSA, and the format the wire contract now expects
// (see the CONTRACT.md correction: not ASN.1 DER).
using RawSignature = std::array<std::uint8_t, 64>;

// An ECDSA P-256 keypair. private_blob is CNG's own exportable
// BCRYPT_ECCPRIVATE_BLOB format -- opaque to everything except
// import_ec_p256_keypair/sign_raw below, never parsed or reconstructed by
// hand, and never serialized to any wire format.
struct EcKeyPair {
    std::vector<std::uint8_t> private_blob;
    PublicKeyPoint public_point{};
};

// Generates a brand-new P-256 keypair. The private key exists only in
// memory (as an opaque exportable blob) until store_ec_keypair persists it.
[[nodiscard]] std::optional<EcKeyPair> generate_ec_p256_keypair(std::string& error_message);

// Signs `data` with SHA-256 then ECDSA (i.e. produces an ECDSA-SHA256
// signature over `data`, not over a pre-hashed value the caller computed
// itself) and returns the raw 64-byte r||s signature.
[[nodiscard]] std::optional<RawSignature> sign_raw(
    const EcKeyPair& keypair, const std::vector<std::uint8_t>& data, std::string& error_message);

// Persists a keypair's private blob to `path`, ACL-locked to the current
// user only (mirrors identity.cpp's restrict_to_current_user), via
// write-temp-then-rename so a crash mid-write never leaves a partial,
// ambiguous key file behind.
[[nodiscard]] bool store_ec_keypair(
    const std::filesystem::path& path, const EcKeyPair& keypair, std::string& error_message);

// Loads a previously stored keypair. Fails closed (nullopt) on a missing,
// truncated, or otherwise unimportable file -- a corrupt key file is never
// silently treated as "no key" and regenerated (which would silently
// discard the endpoint's already-enrolled identity binding); the caller
// must be able to tell "never enrolled" apart from "enrollment state is
// corrupt" and handle the latter as an operational failure, not a retry.
[[nodiscard]] std::optional<EcKeyPair> load_ec_keypair(
    const std::filesystem::path& path, std::string& error_message);

}  // namespace panopticon::officer::response
