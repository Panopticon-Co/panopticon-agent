// User-mode decoder for the panopticon-fsmon wire protocol. Validates a buffer
// received from the driver (already past FILTER_MESSAGE_HEADER) and converts it
// into a DecodedFsMonEvent. Every version/size/field/bound violation returns
// nullopt with a reason; the decoder never over-reads the supplied buffer.
#define PANOPTICON_FSMON_USER
#include "panopticon/officer/minifilter/fsmon_protocol.hpp"

#include <array>
#include <cstring>

namespace panopticon::officer::minifilter {
namespace {

// Lowercase hex for a single byte, appended to out.
void append_hex_byte(std::string& out, unsigned char byte) {
    static constexpr char kDigits[] = "0123456789abcdef";
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
}

bool known_operation(unsigned char value) {
    switch (value) {
        case PanopticonFsMonOpCreate:
        case PanopticonFsMonOpOpen:
        case PanopticonFsMonOpWrite:
        case PanopticonFsMonOpSetInformation:
        case PanopticonFsMonOpOverwrite:
        case PanopticonFsMonOpRename:
        case PanopticonFsMonOpDelete:
            return true;
        default:
            return false;
    }
}

}  // namespace

std::string fsmon_text(const unsigned short* units, std::size_t count) {
    // UTF-16LE -> UTF-8. An unpaired surrogate or any malformed sequence is
    // escaped as \uXXXX-style hex so no code unit is silently dropped. The
    // output is always valid UTF-8 and reversible to the original units.
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
            // A literal backslash is doubled so the escape form stays unambiguous.
            if (unit == '\\') out += "\\\\";
            else out.push_back(static_cast<char>(unit));
        } else if (unit < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (unit >> 6)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3f)));
        } else if (unit >= 0xd800 && unit <= 0xdbff) {
            // High surrogate: needs a following low surrogate.
            if (i + 1 < count && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff) {
                const unsigned int low = units[++i];
                const unsigned int cp = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else {
                emit_escape(unit);  // unpaired high surrogate
            }
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            emit_escape(unit);  // unpaired low surrogate
        } else {
            out.push_back(static_cast<char>(0xe0 | (unit >> 12)));
            out.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3f)));
        }
    }
    return out;
}

std::optional<DecodedFsMonEvent> decode_fsmon_event(
    const unsigned char* buffer, std::size_t bytes, std::string& error) {
    error.clear();
    if (buffer == nullptr) { error = "null buffer"; return std::nullopt; }
    if (bytes < sizeof(PanopticonFsMonEvent)) {
        error = "buffer smaller than fixed record";
        return std::nullopt;
    }

    // Copy into an aligned record; the source buffer is packed and may be
    // misaligned relative to the struct's natural alignment.
    PanopticonFsMonEvent record{};
    std::memcpy(&record, buffer, sizeof(record));

    if (record.version != PANOPTICON_FSMON_PROTOCOL_VERSION) {
        error = "protocol version mismatch";
        return std::nullopt;
    }
    if (record.record_bytes != sizeof(PanopticonFsMonEvent)) {
        error = "record_bytes does not match the compiled layout";
        return std::nullopt;
    }
    if (!known_operation(record.operation)) {
        error = "unknown operation code";
        return std::nullopt;
    }
    if (record.phase != PanopticonFsMonPhasePre && record.phase != PanopticonFsMonPhasePost) {
        error = "unknown phase code";
        return std::nullopt;
    }
    if (record.path_units > PANOPTICON_FSMON_MAX_PATH) {
        error = "path_units exceeds capacity";
        return std::nullopt;
    }
    if (record.previous_units > PANOPTICON_FSMON_MAX_PATH) {
        error = "previous_units exceeds capacity";
        return std::nullopt;
    }
    // Truncation flags must be consistent with the unit count: a path marked
    // truncated must fill the buffer; one not truncated must fit within it.
    if (record.path_truncated && record.path_units != PANOPTICON_FSMON_MAX_PATH) {
        error = "path_truncated set but path_units below capacity";
        return std::nullopt;
    }
    if (record.previous_truncated && record.previous_units != PANOPTICON_FSMON_MAX_PATH) {
        error = "previous_truncated set but previous_units below capacity";
        return std::nullopt;
    }
    const bool rename = record.operation == PanopticonFsMonOpRename;
    if (!rename && (record.previous_units != 0 || record.previous_truncated)) {
        error = "previous_path present on a non-rename operation";
        return std::nullopt;
    }

    DecodedFsMonEvent decoded;
    decoded.operation = static_cast<PanopticonFsMonOperation>(record.operation);
    decoded.post = record.phase == PanopticonFsMonPhasePost;
    decoded.status = static_cast<std::int32_t>(record.status);
    decoded.actor_pid = record.actor_pid;
    if (record.actor_create != 0) decoded.actor_create = record.actor_create;
    decoded.actor_session = record.actor_session;
    decoded.thread_id = record.thread_id;
    decoded.sequence = record.sequence;
    decoded.dropped_before = record.dropped_before;
    decoded.event_time = record.event_time;
    decoded.path = fsmon_text(record.path, record.path_units);
    decoded.path_truncated = record.path_truncated != 0;
    if (rename) {
        decoded.previous_path = fsmon_text(record.previous_path, record.previous_units);
        decoded.previous_truncated = record.previous_truncated != 0;
    }
    return decoded;
}

}  // namespace panopticon::officer::minifilter
