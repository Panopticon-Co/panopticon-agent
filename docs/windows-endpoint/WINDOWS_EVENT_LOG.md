# Independent Windows Event Log collection

Eight independent local native pull subscriptions cover Security, PowerShell
Operational and classic Windows PowerShell, TaskScheduler Operational, WMI
Activity Operational, Defender Operational, System and DNS Client Operational.
The query is `*`; disabled channels are reported and never silently enabled.
The agent needs no Manager or Detection Engine to capture these records.

Each channel has one worker and one bounded pending original. No Windows event
callback performs a journal write. EvtNext pulls one event; bounded EvtRender
retains the rendered XML, then native event/bookmark handles close before journal
admission. XML is at most 128 KiB of native UTF-16; converted XML is at most
192 KiB. EventData keeps up to 1024 ordered elements, including duplicate names,
raw text and compact element XML. UserData and uninterpreted metadata remain in
the full rendered XML. This is rendered native XML, **not original binary bytes**.

System metadata preserves provider, record ID as decimal text, channel, computer,
version/level/task/opcode/keywords, writer PID/TID, Security UserID and activity
IDs. The writer PID is never a security subject process. Native EventData PID,
SID, logon ID and script fragments are descriptive source fields; process/entity
correlation is not established. Security event labels require the matching
Security-Auditing provider/channel; selected authentication/account/group/audit/
task/process events and SCM events have source-native labels. PowerShell 4104
is explicitly an unassembled fragment. These labels are not detection rules.

Native SystemTime is validated through Windows calendar round-trip and retained
at 100 ns precision if representable by the signed nanosecond envelope clock.
Ambiguous duplicate System fields cannot supply trusted time/record ID. Missing,
invalid or out-of-range event time creates capture-time `evidence` with the
original XML/time intact. Envelope boot identity identifies the collector's
boot; native historical events have unknown boot identity, explicitly recorded.

## Atomic durability and replay

Journal schema 4 adds at most 64 encrypted source checkpoints, each bounded to
16 KiB. A checkpoint is namespaced by local channel and query version
`winevt:v1:<channel>`. DPAPI binds cursor ciphertext to the source key. Plaintext
cursor bytes count toward retained payload quota; sampled physical admission
also covers encrypted growth. The original record and replacement bookmark
commit in one FULL/WAL transaction. Revision comparison fences competing readers.
The most recent identical record/bookmark retry is idempotent, including after
receipt retirement of the record. ACKs do not delete source checkpoints.

An admission refusal preserves the saved cursor and retries the same canonical
record bytes; no next native event is read. Startup without a checkpoint begins
at the oldest retained channel record, with an explicit unknown pre-retention
history gap. Saved bookmarks resume strictly after the last accepted event.
Native subscription/seek/read refusals retain an ordinary source gap and preserve
the checkpoint; a formerly checkpointed unavailable source is blind. No recovery
path silently switches to future-only collection. Explicit XML render refusal,
conversion failure or bound excess creates a checkpointed gap counting one
unretained delivered body, with native error and unknown provider loss count.

## Observable scope and limits

Health exposes all configured channels, enablement, subscription errors, saved
revision, delivered/committed/gap/decode-quality counters, one-record admission
backpressure, replay-draining state and monotonic poll/acceptance times. These
are scoped object-lifetime counters; provider loss remains unknown. An active
subscription stays degraded because audit/provider policy and continuity remain
unverified. Disabled and denied sources do not become healthy empty sources.

Missing: audit policy enablement coverage, native log-generation identity and
clear/rollover reconciliation, bookmark stale recovery policy, selective query/
retention/privacy policy, script assembly, actor/lifecycle correlation, task/WMI
state and remediation, DNS request/result semantics, subscription watchdog and
hard native API deadlines, bounded native library allocations, source fairness,
resource/storm/soak/OS/service-account/VM qualification. Periodic health is not
durable full-disk fault intent. A native bookmark alone does not qualify exact
continuity across log clears and record-ID reuse.

## Evidence

The native suite exercises malformed/ambiguous XML, uint64 IDs, native clock
precision/refusals, ordered duplicate data, unknown actors, script-fragment scope,
canonical envelopes, cursor CAS/idempotency, ACK retirement, DPAPI at rest,
combined quota rollback, reopen and abrupt process termination after commit.
A benign owned Application provider verifies actual EvtSubscribe/EvtNext,
immutable refusal retries and strict bookmark resume over a stopped collector.

`tools/validate_windows_logs.py` additionally drives an owned real Windows agent,
validates canonical schema fixtures and every recovered record, abruptly exits
only that owned process and checks immutable journal reopen. This host evidence
does not imply guest/Server/ARM64 qualification. See VALIDATION.md for exact runs.

Mechanisms follow Microsoft's [EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe)
and [bookmarking events](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events)
contracts. No source/Detection integration restriction was used to reduce the
Windows endpoint scope.
