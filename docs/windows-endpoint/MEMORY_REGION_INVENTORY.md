# Bounded native memory-region metadata

The endpoint periodically rotates through at most eight caller-visible process
descriptors and opens each with only `PROCESS_QUERY_INFORMATION | SYNCHRONIZE`.
It obtains a held-process PID and creation FILETIME before region traversal. A
stable process entity is emitted only when the native boot identity is known;
otherwise the PID/creation observation remains explicitly unscoped. Open and
identity refusals are durable rows with exact Win32 status and no invented
process identity.

For each held process, `VirtualQueryEx` emits bounded metadata for at most 256
non-free regions and 4,096 queries. It retains native base/allocation addresses,
region length, state, allocation/current protection and native type as decimal
strings, plus cautious derived booleans for executable, write-capable, guard
and private-executable regions. Free ranges are counted and skipped. A native
address boundary, an API failure, per-process bounds and consumer refusal are
reported separately. A single process's mappings can change between queries;
the collector makes no snapshot, mapping-lifetime or completeness claim.

No memory contents are read. The collector never requests VM read/write or
thread creation access, enables privileges, modifies a target, or classifies a
region as malicious. `MEM_PRIVATE` executable metadata is an observation, not
proof of injection. It does not identify a module, thread start address, handle
source, allocation caller, cross-process operation, shellcode, copy-on-write
state or an injection technique. The Windows API itself can continue to report
copy-on-write pages as mapped/image; working-set probing is intentionally not
used here.

Each capture uses the endpoint's durable begin/page/manifest transaction and
committed freshness health. The capture never asserts full process or memory
coverage. Native APIs and Toolhelp allocation have no hard deadline or native
allocation cap; application candidate, query, row, page and encoded-copy bounds
are enforced. Protected/PPL/system targets can be unavailable and remain
explicitly visible.

Real-Windows component validation creates owned private RW and RX allocations,
checks their `VirtualQueryEx` metadata through a held process identity, verifies
PID-zero open refusal, schema/Manager body preservation and scoped false
content/injection/full-coverage claims. This does not yet qualify the endpoint
runtime capture, protected targets, memory change telemetry, injection
correlation, performance/soak, crash recovery or OS matrix behavior.

Primary native references: [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
and [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
