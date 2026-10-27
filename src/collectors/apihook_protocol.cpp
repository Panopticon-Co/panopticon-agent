// User-mode decoder and actor-verification for the officer-hook wire protocol.
// Mirrors fsmon_protocol.cpp: strict bounds, lossless UTF-16->UTF-8, no
// over-read. The actor fields are treated as CLAIMS until verify_claimed_actor
// confirms them against the pipe's out-of-band peer identity.
#define PANOPTICON_APIHOOK_USER
#include "panopticon/officer/apihook/apihook_protocol.hpp"

#include <cstring>

namespace panopticon::officer::apihook {
namespace {

void append_hex_byte(std::string& out, unsigned char byte) {
    static constexpr char kDigits[] = "0123456789abcdef";
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
}

bool known_operation(unsigned char value) {
    switch (value) {
        case PanopticonApiHookOpCreate:
        case PanopticonApiHookOpOpen:
        case PanopticonApiHookOpWrite:
        case PanopticonApiHookOpSetInformation:
        case PanopticonApiHookOpOverwrite:
        case PanopticonApiHookOpRename:
        case PanopticonApiHookOpDelete:
            return true;
        default:
            return false;
    }
}

}  // namespace

std::string apihook_text(const unsigned short* units, std::size_t count) {
    std::string out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const unsigned int unit = units[i];
        auto emit_escape = [&](unsigned int value) {
            out += "\\u";
            append_hex_byte(out, static_cast<unsigned char>(value >> 8));
            append_hex_byte(out, static_cast<unsigned char>(value & 0xff));
        };
        if (unit < 0x80) {
            if (unit == '\\') out += "\\\\";
            else out.push_back(static_cast<char>(unit));
        } else if (unit < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (unit >> 6)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3f)));
        } else if (unit >= 0xd800 && unit <= 0xdbff) {
            if (i + 1 < count && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff) {
                const unsigned int low = units[++i];
                const unsigned int cp = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else {
                emit_escape(unit);
            }
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            emit_escape(unit);
        } else {
            out.push_back(static_cast<char>(0xe0 | (unit >> 12)));
            out.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3f)));
        }
    }
    return out;
}

std::optional<DecodedApiHookEvent> decode_apihook_event(
    const unsigned char* buffer, std::size_t bytes, std::string& error) {
    error.clear();
    if (buffer == nullptr) { error = "null buffer"; return std::nullopt; }
    if (bytes < sizeof(PanopticonApiHookEvent)) {
        error = "buffer smaller than fixed record";
        return std::nullopt;
    }

    PanopticonApiHookEvent record{};
    std::memcpy(&record, buffer, sizeof(record));

    if (record.version != PANOPTICON_APIHOOK_PROTOCOL_VERSION) { error = "protocol version mismatch"; return std::nullopt; }
    if (record.record_bytes != sizeof(PanopticonApiHookEvent)) { error = "record_bytes does not match the compiled layout"; return std::nullopt; }
    if (!known_operation(record.operation)) { error = "unknown operation code"; return std::nullopt; }
    if (record.phase != PanopticonApiHookPhasePre && record.phase != PanopticonApiHookPhasePost) { error = "unknown phase code"; return std::nullopt; }
    if (record.api_name_units == 0 || record.api_name_units > 64) { error = "api_name_units out of range"; return std::nullopt; }
    if (record.path_units > PANOPTICON_APIHOOK_MAX_PATH) { error = "path_units exceeds capacity"; return std::nullopt; }
    if (record.previous_units > PANOPTICON_APIHOOK_MAX_PATH) { error = "previous_units exceeds capacity"; return std::nullopt; }
    if (record.path_truncated && record.path_units != PANOPTICON_APIHOOK_MAX_PATH) { error = "path_truncated set but path_units below capacity"; return std::nullopt; }
    if (record.previous_truncated && record.previous_units != PANOPTICON_APIHOOK_MAX_PATH) { error = "previous_truncated set but previous_units below capacity"; return std::nullopt; }
    const bool rename = record.operation == PanopticonApiHookOpRename;
    if (!rename && (record.previous_units != 0 || record.previous_truncated)) { error = "previous_path present on a non-rename operation"; return std::nullopt; }

    DecodedApiHookEvent decoded;
    decoded.operation = static_cast<PanopticonApiHookOperation>(record.operation);
    decoded.post = record.phase == PanopticonApiHookPhasePost;
    decoded.win32_error = record.win32_error;
    decoded.claimed_pid = record.actor_pid;
    if (record.actor_create != 0) decoded.claimed_create = record.actor_create;
    decoded.thread_id = record.thread_id;
    decoded.sequence = record.sequence;
    decoded.dropped_before = record.dropped_before;
    decoded.event_time = record.event_time;
    decoded.api_name = apihook_text(record.api_name, record.api_name_units);
    decoded.path = apihook_text(record.path, record.path_units);
    decoded.path_truncated = record.path_truncated != 0;
    if (rename) {
        decoded.previous_path = apihook_text(record.previous_path, record.previous_units);
        decoded.previous_truncated = record.previous_truncated != 0;
    }
    return decoded;
}

bool verify_claimed_actor(const DecodedApiHookEvent& event, std::uint32_t verified_pid,
                          std::optional<std::uint64_t> verified_create, std::string& reason) {
    reason.clear();
    if (event.claimed_pid != verified_pid) {
        reason = "claimed PID does not match the verified pipe peer";
        return false;
    }
    // When both the hook and the OS supply a creation token, they must agree:
    // this defeats a PID reused by a different process between connect and send.
    if (event.claimed_create && verified_create && *event.claimed_create != *verified_create) {
        reason = "claimed creation time does not match the verified peer";
        return false;
    }
    // If the OS gave us a creation token but the hook did not, prefer the OS one
    // upstream; identity is still considered verified by PID + live peer handle.
    return true;
}

}  // namespace panopticon::officer::apihook
