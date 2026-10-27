// Host-side tests for the panopticon-fsmon wire decoder. These exercise the
// user-mode contract end to end (version/size/field/bound validation, bounded
// UTF-16 to UTF-8 with lossless escaping, rename vs non-rename constraints)
// without the driver. Live interception is validated separately on the VM.
#define PANOPTICON_FSMON_USER
#include "panopticon/officer/minifilter/fsmon_protocol.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace m = panopticon::officer::minifilter;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

// Build a well-formed record; tests mutate single fields to probe each rule.
PanopticonFsMonEvent valid_record() {
    PanopticonFsMonEvent record{};
    record.version = PANOPTICON_FSMON_PROTOCOL_VERSION;
    record.record_bytes = sizeof(PanopticonFsMonEvent);
    record.sequence = 100;
    record.dropped_before = 0;
    record.operation = PanopticonFsMonOpWrite;
    record.phase = PanopticonFsMonPhasePost;
    record.path_truncated = 0;
    record.previous_truncated = 0;
    record.actor_pid = 4242;
    record.actor_create = 131000000000000000ull;
    record.actor_session = 1;
    record.thread_id = 77;
    record.status = 0;  // STATUS_SUCCESS
    record.event_time = 132000000000000000ull;
    const wchar_t path[] = L"\\Device\\HarddiskVolume3\\owned.txt";
    const auto units = static_cast<unsigned short>(std::char_traits<wchar_t>::length(path));
    record.path_units = units;
    for (unsigned short i = 0; i < units; ++i) record.path[i] = static_cast<unsigned short>(path[i]);
    return record;
}

std::vector<unsigned char> bytes_of(const PanopticonFsMonEvent& record) {
    std::vector<unsigned char> buffer(sizeof(record));
    std::memcpy(buffer.data(), &record, sizeof(record));
    return buffer;
}

void decodes_a_valid_write() {
    const auto buffer = bytes_of(valid_record());
    std::string error;
    const auto decoded = m::decode_fsmon_event(buffer.data(), buffer.size(), error);
    require(decoded.has_value(), "valid record decodes");
    require(decoded->operation == PanopticonFsMonOpWrite, "operation preserved");
    require(decoded->post, "post phase preserved");
    require(decoded->actor_pid == 4242, "actor pid preserved");
    require(decoded->actor_create.has_value() && *decoded->actor_create == 131000000000000000ull, "creation ticks preserved");
    require(decoded->sequence == 100, "sequence preserved");
    require(decoded->path == "\\\\Device\\\\HarddiskVolume3\\\\owned.txt", "path round-trips with doubled backslashes");
    require(!decoded->previous_path.has_value(), "no previous path on write");
}

void rejects_version_and_size() {
    auto record = valid_record();
    record.version = 999;
    auto buffer = bytes_of(record);
    std::string error;
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "version mismatch rejected");
    require(!error.empty(), "version mismatch has a reason");

    record = valid_record();
    record.record_bytes = sizeof(PanopticonFsMonEvent) - 1;
    buffer = bytes_of(record);
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "record_bytes mismatch rejected");

    // A buffer shorter than the fixed record never over-reads.
    const auto full = bytes_of(valid_record());
    require(!m::decode_fsmon_event(full.data(), full.size() - 1, error), "short buffer rejected");
    require(!m::decode_fsmon_event(nullptr, 0, error), "null buffer rejected");
}

void rejects_unknown_codes() {
    auto record = valid_record();
    record.operation = 0;
    auto buffer = bytes_of(record);
    std::string error;
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "operation 0 rejected");

    record = valid_record();
    record.operation = 42;
    buffer = bytes_of(record);
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "unknown operation rejected");

    record = valid_record();
    record.phase = 7;
    buffer = bytes_of(record);
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "unknown phase rejected");
}

void enforces_path_bounds_and_truncation() {
    auto record = valid_record();
    record.path_units = PANOPTICON_FSMON_MAX_PATH + 1;
    auto buffer = bytes_of(record);
    std::string error;
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "path_units past capacity rejected");

    // Truncated flag must agree with a full buffer.
    record = valid_record();
    record.path_truncated = 1;
    record.path_units = 10;
    buffer = bytes_of(record);
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "inconsistent truncation rejected");

    // A legitimately full, truncated path decodes and carries the flag.
    record = valid_record();
    record.path_truncated = 1;
    record.path_units = PANOPTICON_FSMON_MAX_PATH;
    for (unsigned short i = 0; i < PANOPTICON_FSMON_MAX_PATH; ++i) record.path[i] = L'a';
    buffer = bytes_of(record);
    const auto decoded = m::decode_fsmon_event(buffer.data(), buffer.size(), error);
    require(decoded.has_value() && decoded->path_truncated, "full truncated path decodes with flag");
    require(decoded->path.size() == PANOPTICON_FSMON_MAX_PATH, "truncated path has full unit count");
}

void enforces_rename_previous_path() {
    // previous_path only on rename.
    auto record = valid_record();
    record.operation = PanopticonFsMonOpWrite;
    record.previous_units = 3;
    record.previous_path[0] = L'a';
    record.previous_path[1] = L'b';
    record.previous_path[2] = L'c';
    auto buffer = bytes_of(record);
    std::string error;
    require(!m::decode_fsmon_event(buffer.data(), buffer.size(), error), "previous path on non-rename rejected");

    record = valid_record();
    record.operation = PanopticonFsMonOpRename;
    const wchar_t previous[] = L"old.txt";
    const auto units = static_cast<unsigned short>(std::char_traits<wchar_t>::length(previous));
    record.previous_units = units;
    for (unsigned short i = 0; i < units; ++i) record.previous_path[i] = static_cast<unsigned short>(previous[i]);
    buffer = bytes_of(record);
    const auto decoded = m::decode_fsmon_event(buffer.data(), buffer.size(), error);
    require(decoded.has_value(), "rename with previous path decodes");
    require(decoded->previous_path.has_value() && *decoded->previous_path == "old.txt", "previous path preserved on rename");
}

void pre_phase_has_no_status_meaning() {
    auto record = valid_record();
    record.phase = PanopticonFsMonPhasePre;
    record.status = 0;
    const auto buffer = bytes_of(record);
    std::string error;
    const auto decoded = m::decode_fsmon_event(buffer.data(), buffer.size(), error);
    require(decoded.has_value() && !decoded->post, "pre phase decodes as attempt");
}

void lossless_hex_for_unpaired_surrogate() {
    // An unpaired high surrogate must survive as an escape, not a replacement.
    const unsigned short units[] = {0xd800, static_cast<unsigned short>(L'x')};
    const auto text = m::fsmon_text(units, 2);
    require(text == "\\ud800x", "unpaired surrogate escaped losslessly");

    // A valid surrogate pair (U+1F600) becomes 4-byte UTF-8.
    const unsigned short pair[] = {0xd83d, 0xde00};
    const auto emoji = m::fsmon_text(pair, 2);
    require(emoji.size() == 4 && static_cast<unsigned char>(emoji[0]) == 0xf0, "surrogate pair becomes 4-byte UTF-8");
}

int main() {
    try {
        decodes_a_valid_write();
        rejects_version_and_size();
        rejects_unknown_codes();
        enforces_path_bounds_and_truncation();
        enforces_rename_previous_path();
        pre_phase_has_no_status_meaning();
        lossless_hex_for_unpaired_surrogate();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
