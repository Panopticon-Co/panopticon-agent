// Host-side tests for the officer-hook wire decoder and actor verification.
// These exercise the user-mode contract (version/size/field/bound validation,
// bounded UTF-16 to UTF-8, rename constraints) and the PID/creation-time
// verification that gates whether a claimed actor is trusted. Hook injection and
// live interception are validated separately on the VM.
#define PANOPTICON_APIHOOK_USER
#include "panopticon/officer/apihook/apihook_protocol.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace a = panopticon::officer::apihook;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void set_units(unsigned short* dst, unsigned short* units, const wchar_t* text) {
    const auto n = static_cast<unsigned short>(std::char_traits<wchar_t>::length(text));
    *units = n;
    for (unsigned short i = 0; i < n; ++i) dst[i] = static_cast<unsigned short>(text[i]);
}

PanopticonApiHookEvent valid_record() {
    PanopticonApiHookEvent r{};
    r.version = PANOPTICON_APIHOOK_PROTOCOL_VERSION;
    r.record_bytes = sizeof(PanopticonApiHookEvent);
    r.sequence = 5;
    r.dropped_before = 0;
    r.operation = PanopticonApiHookOpCreate;
    r.phase = PanopticonApiHookPhasePost;
    r.actor_pid = 9000;
    r.actor_create = 131500000000000000ull;
    r.thread_id = 11;
    r.win32_error = 0;
    r.event_time = 132000000000000000ull;
    set_units(r.api_name, &r.api_name_units, L"CreateFileW");
    set_units(r.path, &r.path_units, L"C:\\Users\\analyst\\secret.txt");
    return r;
}

std::vector<unsigned char> bytes_of(const PanopticonApiHookEvent& r) {
    std::vector<unsigned char> b(sizeof(r));
    std::memcpy(b.data(), &r, sizeof(r));
    return b;
}

void decodes_valid_create() {
    const auto buffer = bytes_of(valid_record());
    std::string error;
    const auto decoded = a::decode_apihook_event(buffer.data(), buffer.size(), error);
    require(decoded.has_value(), "valid record decodes");
    require(decoded->operation == PanopticonApiHookOpCreate, "operation preserved");
    require(decoded->post, "post phase preserved");
    require(decoded->api_name == "CreateFileW", "api name preserved");
    require(decoded->claimed_pid == 9000, "claimed pid preserved");
    require(decoded->path == "C:\\\\Users\\\\analyst\\\\secret.txt", "path round-trips with doubled backslashes");
}

void rejects_version_size_and_codes() {
    std::string error;
    auto r = valid_record(); r.version = 2;
    auto b = bytes_of(r);
    require(!a::decode_apihook_event(b.data(), b.size(), error), "version mismatch rejected");

    r = valid_record(); r.record_bytes = sizeof(PanopticonApiHookEvent) + 4;
    b = bytes_of(r);
    require(!a::decode_apihook_event(b.data(), b.size(), error), "record_bytes mismatch rejected");

    const auto full = bytes_of(valid_record());
    require(!a::decode_apihook_event(full.data(), full.size() - 1, error), "short buffer rejected");

    r = valid_record(); r.operation = 99;
    b = bytes_of(r);
    require(!a::decode_apihook_event(b.data(), b.size(), error), "unknown operation rejected");

    r = valid_record(); r.api_name_units = 0;
    b = bytes_of(r);
    require(!a::decode_apihook_event(b.data(), b.size(), error), "empty api name rejected");

    r = valid_record(); r.api_name_units = 65;
    b = bytes_of(r);
    require(!a::decode_apihook_event(b.data(), b.size(), error), "overlong api name rejected");
}

void enforces_rename_previous_path() {
    std::string error;
    auto r = valid_record();
    r.operation = PanopticonApiHookOpWrite;
    set_units(r.previous_path, &r.previous_units, L"old");
    auto b = bytes_of(r);
    require(!a::decode_apihook_event(b.data(), b.size(), error), "previous path on non-rename rejected");

    r = valid_record();
    r.operation = PanopticonApiHookOpRename;
    set_units(r.previous_path, &r.previous_units, L"C:\\old.txt");
    b = bytes_of(r);
    const auto decoded = a::decode_apihook_event(b.data(), b.size(), error);
    require(decoded.has_value() && decoded->previous_path.has_value(), "rename carries previous path");
    require(*decoded->previous_path == "C:\\\\old.txt", "previous path preserved");
}

void actor_verification_gates_identity() {
    const auto buffer = bytes_of(valid_record());
    std::string error;
    const auto decoded = a::decode_apihook_event(buffer.data(), buffer.size(), error);
    require(decoded.has_value(), "record decodes for verification");

    std::string reason;
    // Matching PID + creation time: accepted.
    require(a::verify_claimed_actor(*decoded, 9000, 131500000000000000ull, reason),
        "matching pid and creation time verifies");

    // Wrong PID: rejected (a different process connected than the one claimed).
    require(!a::verify_claimed_actor(*decoded, 1234, 131500000000000000ull, reason),
        "mismatched pid is rejected");
    require(!reason.empty(), "pid rejection has a reason");

    // Same PID, different creation time: rejected (PID reuse / race).
    require(!a::verify_claimed_actor(*decoded, 9000, 999999999999999ull, reason),
        "same pid with different creation time is rejected");

    // PID matches, OS gave no creation token: accepted on live-peer PID alone.
    require(a::verify_claimed_actor(*decoded, 9000, std::nullopt, reason),
        "pid match verifies when OS creation token is unavailable");
}

void lossless_hex_for_unpaired_surrogate() {
    const unsigned short units[] = {0xdc00, static_cast<unsigned short>(L'z')};
    const auto text = a::apihook_text(units, 2);
    require(text == "\\udc00z", "unpaired low surrogate escaped losslessly");
}

int main() {
    try {
        decodes_valid_create();
        rejects_version_size_and_codes();
        enforces_rename_previous_path();
        actor_verification_gates_identity();
        lossless_hex_for_unpaired_surrogate();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
