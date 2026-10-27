// Wire protocol between officer-hook.dll (injected into a monitored process)
// and the user-mode ApiHookCollector. The hook DLL writes one fixed-size record
// per intercepted API call to a named pipe; the collector verifies the peer PID
// out of band (GetNamedPipeClientProcessId + creation time) before trusting the
// self-reported actor fields. Shared by both sides; POD, no STL in the wire part.
#ifndef PANOPTICON_OFFICER_APIHOOK_PROTOCOL_HPP
#define PANOPTICON_OFFICER_APIHOOK_PROTOCOL_HPP

// Bump on any layout or field-meaning change; the collector refuses a mismatch.
#define PANOPTICON_APIHOOK_PROTOCOL_VERSION 1u

// Named-pipe instance the agent serves and the hook connects to. ACL is applied
// at creation time (SYSTEM/Administrators + the monitored token where relevant).
#define PANOPTICON_APIHOOK_PIPE_NAME L"\\\\.\\pipe\\PanopticonOfficerHook"

// Bounded path capacity in UTF-16 code units (no terminator). Longer native
// arguments are truncated and flagged; neither side over-reads.
#define PANOPTICON_APIHOOK_MAX_PATH 512u

// The intercepted API family, normalized to a file operation intent. This is a
// stable wire enum; the hook maps each concrete API to one of these.
enum PanopticonApiHookOperation : unsigned char {
    PanopticonApiHookOpCreate = 1,          // CreateFileW with a creating disposition
    PanopticonApiHookOpOpen = 2,            // CreateFileW opening an existing file
    PanopticonApiHookOpWrite = 3,           // WriteFile / WriteFileEx
    PanopticonApiHookOpSetInformation = 4,  // SetFileInformationByHandle (non rename/delete)
    PanopticonApiHookOpOverwrite = 5,       // CreateFileW with CREATE_ALWAYS/TRUNCATE_EXISTING
    PanopticonApiHookOpRename = 6,          // MoveFileExW / SetFileInformationByHandle rename
    PanopticonApiHookOpDelete = 7,          // DeleteFileW / SetFileInformationByHandle disposition
};

// Attempt (pre-call, outcome unknown) vs completion (post-call, carries Win32
// error). The hook emits both where it brackets the call; write is pre-only.
enum PanopticonApiHookPhase : unsigned char {
    PanopticonApiHookPhasePre = 1,
    PanopticonApiHookPhasePost = 2,
};

#pragma pack(push, 1)
struct PanopticonApiHookEvent {
    unsigned int version;             // PANOPTICON_APIHOOK_PROTOCOL_VERSION
    unsigned int record_bytes;        // sizeof(PanopticonApiHookEvent)
    unsigned __int64 sequence;        // monotonic per hook-DLL session; gaps imply loss
    unsigned __int64 dropped_before;  // records the hook dropped (pipe full) before this
    unsigned char operation;          // PanopticonApiHookOperation
    unsigned char phase;              // PanopticonApiHookPhase
    unsigned char path_truncated;     // 1 if path exceeded capacity
    unsigned char previous_truncated; // 1 if previous_path exceeded capacity (rename)
    unsigned int actor_pid;           // GetCurrentProcessId() in the hooked process (claimed)
    unsigned __int64 actor_create;    // actor creation time, 100ns FILETIME ticks (claimed, 0 if unknown)
    unsigned int thread_id;           // GetCurrentThreadId()
    unsigned int win32_error;         // GetLastError() captured post-call; 0 for pre
    unsigned __int64 event_time;      // GetSystemTimePreciseAsFileTime, 100ns since 1601
    unsigned short api_name_units;    // UTF-16 code units in api_name (<= 64)
    unsigned short path_units;        // UTF-16 code units in path (<= MAX_PATH)
    unsigned short previous_units;    // UTF-16 code units in previous_path
    unsigned short api_name[64];      // concrete API, e.g. L"CreateFileW"
    unsigned short path[PANOPTICON_APIHOOK_MAX_PATH];
    unsigned short previous_path[PANOPTICON_APIHOOK_MAX_PATH];
};
#pragma pack(pop)

#ifdef PANOPTICON_APIHOOK_USER
#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::apihook {

// Decoded, validated record. The actor_pid/actor_create here are the values the
// hook CLAIMED; the collector cross-checks them against the verified peer before
// trusting identity. Strings are UTF-8 (converted from bounded UTF-16).
struct DecodedApiHookEvent {
    PanopticonApiHookOperation operation{};
    bool post{};
    std::uint32_t win32_error{};
    std::uint32_t claimed_pid{};
    std::optional<std::uint64_t> claimed_create;
    std::uint32_t thread_id{};
    std::uint64_t sequence{};
    std::uint64_t dropped_before{};
    std::uint64_t event_time{};
    std::string api_name;
    std::string path;
    bool path_truncated{};
    std::optional<std::string> previous_path;  // rename only
    bool previous_truncated{};
};

// Validate a received buffer and decode it. nullopt + reason on any
// version/size/field/bound violation; never over-reads.
[[nodiscard]] std::optional<DecodedApiHookEvent> decode_apihook_event(
    const unsigned char* buffer, std::size_t bytes, std::string& error);

// UTF-16LE (bounded) to UTF-8 with lossless hex escaping of invalid sequences.
[[nodiscard]] std::string apihook_text(const unsigned short* units, std::size_t count);

// Decide whether the hook's claimed actor identity is trustworthy given the
// out-of-band verified peer PID and creation ticks from the pipe. The claim is
// accepted only when the PID matches and, when both sides supply creation
// ticks, those match too. Returns false (with reason) otherwise.
[[nodiscard]] bool verify_claimed_actor(
    const DecodedApiHookEvent& event, std::uint32_t verified_pid,
    std::optional<std::uint64_t> verified_create, std::string& reason);

}  // namespace panopticon::officer::apihook
#endif  // PANOPTICON_APIHOOK_USER

#endif  // PANOPTICON_OFFICER_APIHOOK_PROTOCOL_HPP
