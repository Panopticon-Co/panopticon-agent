// Wire protocol between panopticon-fsmon.sys (kernel) and MinifilterCollector
// (user mode). Included from both, so it uses only MSVC builtin fixed-width
// types and a POD layout -- no STL, no Windows headers required here. The user
// side gets validation helpers under PANOPTICON_FSMON_USER.
#ifndef PANOPTICON_OFFICER_FSMON_PROTOCOL_HPP
#define PANOPTICON_OFFICER_FSMON_PROTOCOL_HPP

// A version bump is required for any change to the layout or the meaning of a
// field below. The driver stamps it; the collector refuses a mismatch.
#define PANOPTICON_FSMON_PROTOCOL_VERSION 1u

// Communication port name. The driver restricts connect access to
// SYSTEM/Administrators via a security descriptor at registration time.
#define PANOPTICON_FSMON_PORT_NAME L"\\PanopticonFsMonPort"

// Bounded path capacity, in UTF-16 code units including no terminator. A longer
// native path is truncated and flagged; the collector never over-reads.
#define PANOPTICON_FSMON_MAX_PATH 512u

// Normalized file operation. Matches telemetry::FileOperation ordering intent
// but is its own stable wire enum (the driver never includes agent headers).
enum PanopticonFsMonOperation : unsigned char {
    PanopticonFsMonOpCreate = 1,          // IRP_MJ_CREATE, new file
    PanopticonFsMonOpOpen = 2,            // IRP_MJ_CREATE, existing file
    PanopticonFsMonOpWrite = 3,           // IRP_MJ_WRITE
    PanopticonFsMonOpSetInformation = 4,  // IRP_MJ_SET_INFORMATION, non-rename/delete
    PanopticonFsMonOpOverwrite = 5,       // IRP_MJ_CREATE with overwrite/supersede disposition
    PanopticonFsMonOpRename = 6,          // FileRenameInformation
    PanopticonFsMonOpDelete = 7,          // FileDispositionInformation (delete requested)
};

// Where the filter observed the operation. Pre is the attempt (outcome unknown);
// post carries the completion status. Sources without the split never occur here.
enum PanopticonFsMonPhase : unsigned char {
    PanopticonFsMonPhasePre = 1,
    PanopticonFsMonPhasePost = 2,
};

// One fixed-size event record. Flexible fields are bounded inline buffers so the
// record is a single contiguous POD the driver writes and the collector reads
// without pointer chasing. All multi-byte integers are host-endian (same box).
#pragma pack(push, 1)
struct PanopticonFsMonEvent {
    unsigned int version;            // PANOPTICON_FSMON_PROTOCOL_VERSION
    unsigned int record_bytes;       // sizeof(PanopticonFsMonEvent); sanity/versioning
    unsigned __int64 sequence;       // monotonic per driver session; gaps imply loss
    unsigned __int64 dropped_before; // events dropped (queue full) before this one
    unsigned char operation;         // PanopticonFsMonOperation
    unsigned char phase;             // PanopticonFsMonPhase
    unsigned char path_truncated;    // 1 if path exceeded capacity
    unsigned char previous_truncated;// 1 if previous_path exceeded capacity (rename)
    unsigned int actor_pid;          // acting process id
    unsigned __int64 actor_create;   // actor creation time, 100ns FILETIME ticks (0 if unknown)
    unsigned int actor_session;      // actor session id (0xFFFFFFFF if unknown)
    unsigned int thread_id;          // acting thread id
    long status;                     // NTSTATUS, meaningful only for post; 0 for pre
    unsigned __int64 event_time;     // KeQuerySystemTimePrecise, 100ns since 1601 (FILETIME base)
    unsigned short path_units;       // UTF-16 code units used in path (<= MAX_PATH)
    unsigned short previous_units;   // UTF-16 code units used in previous_path
    unsigned short path[PANOPTICON_FSMON_MAX_PATH];
    unsigned short previous_path[PANOPTICON_FSMON_MAX_PATH];
};
#pragma pack(pop)

// The driver's reply to a FilterGetMessage: a bare header plus the event. The
// FILTER_MESSAGE_HEADER is prepended by FltMgr; the collector strips it.
struct PanopticonFsMonMessage {
    // FILTER_MESSAGE_HEADER occupies the first 8 bytes when received; the
    // collector offsets past it. Kept implicit to avoid a kernel header here.
    PanopticonFsMonEvent event;
};

#ifdef PANOPTICON_FSMON_USER
#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::minifilter {

// Decoded, validated event. Strings are UTF-8 (converted from bounded UTF-16).
struct DecodedFsMonEvent {
    PanopticonFsMonOperation operation{};
    bool post{};                 // false = attempt (pre), true = completion (post)
    std::int32_t status{};       // NTSTATUS, meaningful when post
    std::uint32_t actor_pid{};
    std::optional<std::uint64_t> actor_create;  // native creation ticks
    std::uint32_t actor_session{};
    std::uint32_t thread_id{};
    std::uint64_t sequence{};
    std::uint64_t dropped_before{};
    std::uint64_t event_time{};  // 100ns since 1601
    std::string path;            // UTF-8; may be a lossless hex object upstream
    bool path_truncated{};
    std::optional<std::string> previous_path;  // rename only
    bool previous_truncated{};
};

// Validate a received buffer (already past FILTER_MESSAGE_HEADER) and decode it.
// Returns nullopt with a reason on any version/size/field/bound violation; never
// over-reads. The caller counts a parse failure rather than trusting the record.
[[nodiscard]] std::optional<DecodedFsMonEvent> decode_fsmon_event(
    const unsigned char* buffer, std::size_t bytes, std::string& error);

// UTF-16LE (bounded) to UTF-8; invalid sequences become a lossless hex marker so
// no byte is silently dropped or replaced.
[[nodiscard]] std::string fsmon_text(const unsigned short* units, std::size_t count);

}  // namespace panopticon::officer::minifilter
#endif  // PANOPTICON_FSMON_USER

#endif  // PANOPTICON_OFFICER_FSMON_PROTOCOL_HPP
