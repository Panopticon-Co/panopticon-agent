#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::officer::deployment {

inline constexpr std::uint64_t kMaximumUpdatePackageBytes = 512ull * 1024 * 1024;
inline constexpr std::size_t kMaximumUpdateManifestBytes = 64 * 1024;
inline constexpr std::size_t kMaximumUpdateTrustKeys = 8;

struct PublisherPin {
    // Lowercase SHA-256 hex of the exact DER SubjectPublicKeyInfo.
    std::string key_id;
    std::vector<std::uint8_t> subject_public_key_info_der;
};

struct UpdateResult {
    // staged, already_staged, or failed. No result implies installation.
    std::string state = "failed";
    std::uint64_t generation = 0;
    std::string version;
    std::string package_sha256;
    std::filesystem::path staged_path;
    std::filesystem::path rollback_candidate;
    std::string error;
};

struct PublisherTrustKey {
    PublisherPin publisher;
    std::uint64_t activates_at_unix_ms{};
    std::uint64_t retires_at_unix_ms{};
    // Zero means not revoked. Revocation immediately prevents future manifest
    // verification at/after this timestamp; it does not rewrite old evidence.
    std::uint64_t revoked_at_unix_ms{};
};

struct PublisherTrustSnapshot {
    // unknown means no bundle has ever been committed; unavailable means the
    // durable state could not be read or authenticated. Neither permits trust.
    std::string state = "unknown";
    std::uint64_t generation{};
    std::vector<PublisherPin> active_publishers;
    std::vector<PublisherTrustKey> keys;
    // Signed provenance retained for package high-water verification across rotation.
    std::string signed_bundle;
    std::string error;
};

struct PublisherTrustResult {
    std::string state = "unavailable";
    std::uint64_t generation{};
    std::string error;
};

// Maintains a service-owned publisher keyset. Bootstrap pins are provisioned
// externally; this class never invents, enrolls, or rotates bootstrap trust.
class PublisherTrustStore final {
public:
    PublisherTrustStore(std::filesystem::path fixed_state_root,
                        std::vector<PublisherPin> bootstrap_pins);

    // Verifies and atomically commits one signed, canonical trust bundle.
    // Returns unavailable on validation/IO failure and never alters bootstrap pins.
    PublisherTrustResult install_signed_bundle(std::string_view signed_bundle,
                                               std::uint64_t now_unix_ms);

    // Only keys within their activation/retirement/revocation interval are
    // returned as active. Unknown/unavailable state returns no active keys.
    [[nodiscard]] PublisherTrustSnapshot snapshot(std::uint64_t now_unix_ms) const;

    // Verifies a previously authenticated bundle at a package-manifest issue
    // time. Used only to validate durable historical package state, never to
    // authorize a new package at current time.
    [[nodiscard]] PublisherTrustSnapshot historical_publishers(
        std::string_view signed_bundle, std::uint64_t manifest_issued_at_unix_ms) const;

private:
    friend class UpdatePackageStore;
    [[nodiscard]] PublisherTrustSnapshot snapshot_locked(std::uint64_t now_unix_ms) const;
    std::filesystem::path root_;
    std::vector<PublisherPin> bootstrap_pins_;
};

// Verifies and stages one signed update package. The caller must provide an
// independently provisioned pin set and a pre-created service-owned root.
// This class never installs, executes, loads, or interprets package contents.
class UpdatePackageStore final {
public:
    // Legacy, scoped trust API: pins are static for this object's lifetime and
    // have no activation/revocation lifecycle. Prefer the trust-store overload.
    [[deprecated("static publisher pins do not enforce key activation or revocation; use PublisherTrustStore")]]
    UpdatePackageStore(std::filesystem::path fixed_staging_root,
                       std::vector<PublisherPin> publisher_pins);
    // The referenced trust store must outlive this stager and use the same root.
    UpdatePackageStore(std::filesystem::path fixed_staging_root,
                       PublisherTrustStore& publisher_trust_store);

    // Manifest is an exact signed envelope. Its payload is canonical bounded
    // UTF-8 JSON. package_source must be a regular file, not a reparse point.
    UpdateResult stage(std::string_view signed_manifest,
                       const std::filesystem::path& package_source,
                       std::uint64_t now_unix_ms,
                       std::string_view current_architecture);

    // Records intent to select the prior staged package for an external,
    // separately authorized rollback. Does not apply or execute that package.
    UpdateResult record_rollback_intent();

private:
    std::filesystem::path root_;
    std::vector<PublisherPin> pins_;
    PublisherTrustStore* trust_store_{};
};

}  // namespace panopticon::officer::deployment
