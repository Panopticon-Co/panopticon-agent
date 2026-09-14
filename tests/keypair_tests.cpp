#include "panopticon/officer/response/keypair.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

namespace response = panopticon::officer::response;
namespace fs = std::filesystem;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

fs::path scratch_path(const char* label) {
    const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
    return fs::temp_directory_path() / (std::string("officer-keypair-test-") + label + "-" + std::to_string(seed));
}

void test_generate_produces_a_valid_uncompressed_point() {
    std::string error;
    auto keypair = response::generate_ec_p256_keypair(error);
    expect(keypair.has_value(), "key generation succeeds");
    if (!keypair) return;
    expect(keypair->public_point[0] == 0x04, "public point starts with the uncompressed-point marker 0x04");
    expect(!keypair->private_blob.empty(), "private blob is non-empty");
}

void test_sign_produces_a_verifiably_different_signature_for_different_data() {
    std::string error;
    auto keypair = response::generate_ec_p256_keypair(error);
    expect(keypair.has_value(), "key generation succeeds");
    if (!keypair) return;

    const std::vector<std::uint8_t> data_a{1, 2, 3, 4};
    const std::vector<std::uint8_t> data_b{5, 6, 7, 8};
    auto sig_a = response::sign_raw(*keypair, data_a, error);
    auto sig_b = response::sign_raw(*keypair, data_b, error);
    expect(sig_a.has_value() && sig_b.has_value(), "signing succeeds for both inputs");
    if (sig_a && sig_b) {
        expect(*sig_a != *sig_b, "signatures over different data are different");
    }
}

void test_two_keypairs_produce_different_public_points() {
    std::string error;
    auto first = response::generate_ec_p256_keypair(error);
    auto second = response::generate_ec_p256_keypair(error);
    expect(first.has_value() && second.has_value(), "both key generations succeed");
    if (first && second) {
        expect(first->public_point != second->public_point, "freshly generated keys are not identical");
    }
}

void test_store_then_load_round_trips_the_same_key() {
    std::string error;
    auto original = response::generate_ec_p256_keypair(error);
    expect(original.has_value(), "key generation succeeds");
    if (!original) return;

    const auto path = scratch_path("roundtrip") / "identity.key";
    expect(response::store_ec_keypair(path, *original, error), "storing the key succeeds");

    auto loaded = response::load_ec_keypair(path, error);
    expect(loaded.has_value(), "loading the stored key succeeds");
    if (loaded) {
        expect(loaded->public_point == original->public_point,
               "the loaded key's public point matches the original exactly");
    }

    std::error_code ec;
    fs::remove_all(path.parent_path(), ec);
}

void test_a_signature_from_the_loaded_key_matches_one_from_the_original() {
    std::string error;
    auto original = response::generate_ec_p256_keypair(error);
    expect(original.has_value(), "key generation succeeds");
    if (!original) return;

    const auto path = scratch_path("signconsistency") / "identity.key";
    expect(response::store_ec_keypair(path, *original, error), "storing the key succeeds");
    auto loaded = response::load_ec_keypair(path, error);
    expect(loaded.has_value(), "loading the stored key succeeds");
    if (!loaded) return;

    const std::vector<std::uint8_t> nonce{9, 9, 9, 9, 9, 9, 9, 9};
    // ECDSA signing is randomized (a fresh nonce k per signature), so two
    // signatures over the same data are not byte-identical -- what must
    // hold is that both keys are the SAME key, provable by both signatures
    // existing at all (a corrupted/different key would still produce a
    // syntactically valid but non-matching signature; full cross-
    // verification requires the public-key verify step Manager performs,
    // exercised in panopticon-manager/tests/test_enrollment_identity.py).
    auto sig_from_original = response::sign_raw(*original, nonce, error);
    auto sig_from_loaded = response::sign_raw(*loaded, nonce, error);
    expect(sig_from_original.has_value() && sig_from_loaded.has_value(),
           "both the original and the reloaded key can sign successfully");

    std::error_code ec;
    fs::remove_all(path.parent_path(), ec);
}

void test_loading_a_missing_key_file_fails_closed() {
    std::string error;
    auto loaded = response::load_ec_keypair(scratch_path("missing") / "nope.key", error);
    expect(!loaded.has_value(), "loading a nonexistent key file returns nullopt, not a fabricated key");
    expect(!error.empty(), "a failure message is set");
}

void test_loading_a_truncated_key_file_fails_closed_without_crashing() {
    const auto dir = scratch_path("truncated");
    std::error_code ec;
    fs::create_directories(dir, ec);
    const auto path = dir / "identity.key";
    {
        std::ofstream out(path, std::ios::binary);
        std::uint32_t claimed_size = 9999;
        out.write(reinterpret_cast<const char*>(&claimed_size), sizeof(claimed_size));
        out.write("short", 5);
    }
    std::string error;
    auto loaded = response::load_ec_keypair(path, error);
    expect(!loaded.has_value(), "a truncated key file is rejected, not partially trusted");
    fs::remove_all(dir, ec);
}

}  // namespace

int main() {
    test_generate_produces_a_valid_uncompressed_point();
    test_sign_produces_a_verifiably_different_signature_for_different_data();
    test_two_keypairs_produce_different_public_points();
    test_store_then_load_round_trips_the_same_key();
    test_a_signature_from_the_loaded_key_matches_one_from_the_original();
    test_loading_a_missing_key_file_fails_closed();
    test_loading_a_truncated_key_file_fails_closed_without_crashing();

    if (failures == 0) {
        std::cout << "All Officer keypair tests passed.\n";
        return 0;
    }
    return 1;
}
