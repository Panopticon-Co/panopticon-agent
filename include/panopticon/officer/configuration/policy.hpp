#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace panopticon::officer::configuration {

// Closed collection-policy schema only; no commands, scripts, arbitrary paths,
// registry writes, response actions, or plugins can be represented here.
inline constexpr std::size_t kMaximumEnvelopeBytes = 256 * 1024;
inline constexpr std::size_t kMaximumPayloadBytes = 128 * 1024;
inline constexpr std::size_t kMaximumTrustKeys = 8;

struct TrustKey {
    // Lowercase SHA-256 hex of the exact DER SubjectPublicKeyInfo below.
    std::string key_id;
    std::vector<std::uint8_t> subject_public_key_info_der;
};

struct FeatureState {
    std::string name;
    bool desired = false;
    bool effective = false;
    // disabled, active, pending, unsupported, unauthorized, or expired.
    std::string state;
};

struct Snapshot {
    bool authorized = false;
    bool policy_expired = false;
    bool rolled_back = false;
    std::uint64_t desired_generation = 0;
    std::uint64_t effective_generation = 0;
    std::uint64_t highest_accepted_generation = 0;
    std::string policy_digest;
    std::string error;
    std::vector<FeatureState> features;
};

struct Result {
    bool accepted = false;
    bool changed = false;
    Snapshot snapshot;
};

// `state_file` must be in a service-owned directory whose ACL denies writes to
// untrusted principals. Trust anchors arrive through a separately authenticated
// installation/update channel; rotating that set is outside this class.
class PolicyStore final {
public:
    PolicyStore(std::filesystem::path state_file, std::vector<TrustKey> trust_keys);

    // Envelope payload is an exact UTF-8 JSON string. ECDSA P-256/SHA-256 signs
    // a domain separator plus those exact payload bytes. The supported list
    // must reflect platform/source support. No collector starts in this call.
    Result activate(std::string_view signed_envelope, std::uint64_t now_unix_ms,
                    const std::vector<std::string>& supported_features);

    // Caller must gate rollback through an independently authorized local
    // operator/control path. This never lowers the highest accepted generation.
    Result rollback(std::uint64_t now_unix_ms,
                    const std::vector<std::string>& supported_features);

    // Called only after authorized collectors have actually started or
    // stopped. Previously effective features cannot be silently removed.
    Result confirm_effective(std::uint64_t generation,
                    const std::vector<std::string>& actually_effective_features,
                    std::uint64_t now_unix_ms,
                    const std::vector<std::string>& supported_features);

    Snapshot current(std::uint64_t now_unix_ms,
                     const std::vector<std::string>& supported_features) const;

private:
    std::filesystem::path state_file_;
    std::vector<TrustKey> trust_keys_;
};

}  // namespace panopticon::officer::configuration
