# Windows endpoint validation ledger

Native memory-region implementation wave, 2026-10-09: bounded rotating held
process metadata capture is integrated into the durable state worker. It emits
native `VirtualQueryEx` region attributes without reading contents or changing
targets, and publishes explicit process open/identity refusals plus partial
coverage/freshness health. Fresh Debug and Release suites each contain 42
tests. The fresh Release `officer-memory-inventory-tests` executes on Windows
and verifies an owned held process, private RW and RX allocations, PID-zero open
refusal and false content/injection/full-coverage claims. The component report
is retained at
`C:\Users\Acer\AppData\Local\Temp\panopticon-memory-component-2e892b4155574ea68fa8d0fd16133b99.json`.
This is native host component evidence, not dedicated-guest endpoint runtime,
durable-recovery, protected-target, performance/soak or OS-matrix qualification.
R remains partial. See [memory regions](MEMORY_REGION_INVENTORY.md).

Native USN checkpoint recovery follow-up, 2026-10-07: fresh Debug/Release
builds each pass 41 tests; Release elapsed 19.25 s. The expanded elevated native
component exits zero in owned guest directory
`C:\ProgramData\PanopticonValidation\usn-cursor-fault-eb424ba8f25642c3aa134311433e9cc4`.
Its tested executable and DLL were exported and SHA-256 matched to the host
build. Evidence is preserved in
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\usn-cursor-fault-eb424ba8f25642c3aa134311433e9cc4`.
The test closes the durable journal after stopping the source, creates a file
while both are closed, reopens the exact checkpoint and verifies native replay.
It also seeds isolated owned stores with a mismatched journal ID, an ahead
cursor, a cursor before actual retained bounds and a malformed cursor. Real
native queries produce the first three explicit durable gaps with replacement
cursors derived from native bounds. The malformed cursor remains unchanged at
revision one, with blind health and no accepted record. Native journal policy,
ID and retention are never modified. `usn-cursor-verification-report.json`
independently checks gap classification, native-buffer fidelity and Schema/Manager
body preservation: 197 decoded rows checked, including two synthetic rows.
Report original SHA-256:
`23a359e87aa63cb66c26feadf78e996641dc5992181a9a20e802b5e5cef1b85d`.
The launch observation timed out while UAC was pending; the same launched run
was subsequently inspected and its completed transcript/exit-zero report
exported. No duplicate launch occurred. The owned test process was absent at
the subsequent process census. This follow-up does not rerun the endpoint
runtime harness or qualify actual journal rotation/retention pressure, full
service/process restart, disk-full, power loss or OS compatibility. Those gates
remain open; the full capability matrix and DoD remain incomplete.

Native USN filesystem wave, 2026-10-07: independent existing-journal readers,
bounded V2/V3 decoding with complete original native buffers, atomic accepted
record/cursor transactions, immutable refusal retries and per-volume committed
cursor/health bindings are integrated. Fresh Debug and Release suites each pass
41 tests; Release elapsed 14.89 s. Non-elevated host journal access returns
Win32 5 and does not count as live verification. V2 layouts are synthetic-tested;
the successful guest runtime returned V3 records with 128-bit native file IDs.

Final elevated guest `run-20261006-173322`, package `build-20261007-060108`,
passes all 23 component executables. Native component evidence verifies actual
create/ADS/rename/delete reasons, independent held-file identity agreement,
unchanged cursors during refused commits and replay of a mutation made while
the source is stopped. That replay restarts the collector with the journal
object open; it does not qualify a full service restart or native power loss.
The independent endpoint runtime fixture also verifies create/ADS/rename/delete.
Export `C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\guest-usn-final-20261007`
preserves 104 root files; encrypted spool stays in the guest with unchanged ACLs.
`usn-verification-report.json` validates 1,061 original Schema 1.0 records,
exact Manager body preservation, package hashes and byte-identical originals
across two recovery reopens after abrupt owned endpoint exit. It independently
checks native-buffer fidelity for six runtime batches containing 65 V3 rows,
one explicit gap, 11 owned fixture rows and 23 committed cursor/health bindings.
Three separate synthetic contract records are checked, not counted as live
Windows evidence. Original NDJSON SHA-256:
`6d7e97c872167d959cc61a12d929e88323e9ea8c1b3dc7dad9a13c91ef3ef1c3`.
Consolidated thread revalidation covers 18 pages/1,105 rows/1,090 native exact
references, 15 query/open refusals and 21 manifest/health bindings. This run
did not request process lifecycle fixtures and adds no process-stop qualification.

Earlier attempts remain preserved and excluded from successful qualification:
guest `run-20261006-172209` exposed an incorrect test assumption equating native
64-bit file indexes with V3 128-bit identities, and a PowerShell ADS fixture API
failure. The test now queries both native identity forms independently; ADS uses
the Windows PowerShell stream provider. Guest `run-20261006-172712` passed all
23 components but runtime report serialization failed on a generic list; the
final harness materializes an array explicitly. Their guest roots and selected
host evidence remain available. Successful final launcher PID 2704 was confirmed
absent. No foreign processes, ETW sessions, Linux work or VM configuration were
reset or removed.

H remains partial. Actor attribution, full paths, initial file/FIM baseline,
content integrity, minifilter enforcement, volume hotplug/clone reconciliation,
journal rotation/retention faults, hard native stop deadlines, byte fairness,
spool feedback, sustained resource/chaos and OS/security qualification remain
open. Full filesystem coverage and the all-domain Definition of Done are false.
See [native USN fallback](USN_JOURNAL.md).

Native thread state wave, 2026-10-07: independent bounded Toolhelp thread
snapshot plus separate held-thread TID/creation/CPU/owner-PID/priority/cycle and
point-in-time termination queries; versioned native thread identities require
host/boot/held TID/nonzero creation FILETIME. Descriptor instance and owner
process instance remain unresolved, undefined exit time stays null, and no
start-address, continuous thread, handle or injection coverage is asserted.
Durable begin/pages/manifests, immutable acceptance retry, exact query errors,
shutdown state and record-bound six-minute freshness/blind transitions are
integrated. Fresh final Debug and Release builds each pass all 40 tests; final
Release suite elapsed 23.53 s. Owned native host tests cover actual self thread,
missing boot, cancellation, rejected pages, total bounds and invalid limits.

Dedicated guest `run-20261006-170030`, fresh package `build-20261007-052929`,
passes all 22 component executables and the endpoint runtime/persistence capture
harness. Export `C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\guest-thread-wave-20261007`
preserves 98 root files; encrypted guest spool stays in place with unchanged
ACLs. `thread-inventory-report.json` validates 1,141 Schema 1.0 records and
exact Manager body preservation, package hashes and byte-identical original
journal recovery across two reopens after abrupt owned endpoint exit. Runtime
thread capture has 17 ordered pages, 1,048 rows, 1,034 native exact references,
14 OpenThread refusals with exact Win32 error 87 (cause not inferred), 14 query
failures and 22 committed manifest/freshness health bindings. Snapshot traversal
completed; inventory/continuous thread coverage and owner instances remain
unqualified. Original NDJSON SHA-256:
`6f8c59b69814be1eab9f06a688a1ef9f48d483fba087f470c39497a8a97c5427`.
987 native Windows log records were retained. This run did not request the owned
process-lifecycle fixture; its ProcessStopVerified and retained graph fixture
flags are false, and it adds no lifecycle qualification beyond earlier evidence.
Temporary persistence fixtures cleaned up and elevated launcher PID 5612 was
confirmed absent at completion. Linux VM configuration/work remained untouched.
Both guests stay running under latest user concurrency authorization. C remains
partial, all-domain DoD remains unmet. See [thread state](THREAD_STATE.md).
Native process scalar wave, 2026-10-07: nineteen selected UInt32/UInt64 source
properties now retain template-scoped absence/refusal/native-read status and
lossless decimal carriers, event ID/version and provider GUID. No sequence
aliases or creator/parent instances are promoted. Fresh Debug/Release builds
pass all 39 tests (25.82/25.41 s). Native TDH fixtures cover old stop, sequenced
stop and birth templates, maximum unsigned carriers, truncation, source/operation
scope, failure/null consistency and handoff ownership. A consolidated guest run
passes all 21 component executables and recovers 1,640 unchanged originals
validated by Schema 1.0, Manager body preservation and package hashes. Four
archived live lifecycle records use birth version 4 and stop version 2. Their
process sequences are retained, two parent sequences are retained on births,
and the owned exact target's birth/stop sequences agree. Each stop has eleven
copied scalars and eight template-absent fields. Exact target exit and durable
birth/stop graph verification remain positive; parent edges remain unverified.
Evidence:
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\guest-native-process-fields-20261007`
(`native-process-fields-report.json`, `host-verification-report.json`, originals
and independent synthetic fixtures). B/Y/AK remain partial. See
[native process fields](NATIVE_PROCESS_FIELDS.md).

Native guest SCM validation, 2026-10-07: the guarded manual LocalSystem fixture
completes two start/stop iterations against one journal directory, verifies exact
executable/account/PID binding, Stopped status and zero native/service-specific
exit codes. Journal sizes are 25,579,520 and 49,094,656 bytes. Exported report:
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\service-wave-20261007/service-report.json`.
LocalSystem content recovery, fault/stop deadline, reboot, installer/update/signing
and OS/security matrix qualification remain open. AJ remains partial.

First consolidated dedicated Windows guest validation, 2026-10-07:
Windows 11 Enterprise LTSC 26100.1742, four vCPUs/4 GiB, concurrent Linux guest
unchanged. Corrected elevated harness runs all 21 selected component executables
with native exit code zero and no timeout. Its owned runtime, abrupt exit and
two readbacks yield 1,164 immutable Schema 1.0 records; Manager native-body
preservation and installed package hashes verify on exported evidence.
There are 1,012 native log records across Security (193), System (193), Defender
Operational (194), WMI Activity (199), PowerShell Operational (98) and classic
PowerShell (135). Task/DNS enabled-channel semantics remain unverified.
Nine real ETW births and nine stops survive in the independent lifecycle archive.
The owned ping fixture's exact PID/creation FILETIME/exit code binds one live
stop in delivery and archive, and its durable graph contains both birth and stop,
zero index backlog, null liveness and no parent edge. This proves retained exact
lifecycle reconstruction; positive parent ancestry/creator/complete continuity
remain unverified. Disabled hidden task and inert Run-value fixtures are captured
and cleaned up. Nine native identity/persistence/software captures assemble with
reported counts; one LSA query refusal remains explicit. Device Guard has one
durable provider capture and 22 exact health bindings, without effective-protection
claims. All domains remain partial and no fleet/OS-matrix/soak qualification is
claimed. Evidence directory:
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\guest-wave-corrected-20261007`
(`host-verification-report.json`, `native-surface-summary.json`, runtime/lifecycle/
Device Guard reports and exact originals). Repeatable host verifier:
`tools/verify_windows_guest_evidence.py`. Initial null-exit/task-settings harness
failure is preserved separately; it is not counted as a passing run.

Durable process graph wave, 2026-10-07: schema 6 commits an exact identity/parent
index with encrypted lifecycle originals, delivery acceptance and source cursors.
Bounded ancestry queries rederive evidence under one read transaction; reported
parentage, unresolved PID-only claims and null liveness remain explicit. Durable
index counters and bounded schema-5 archive backfill expose backlog. Fresh Debug/
Release builds pass all 39 tests (25.80/22.28 s), covering restart/ACK independence,
actual migration/backfill, source separation, PID reuse, forged references,
conflicts, cycles and query bounds. Positive ancestry is fixture evidence only.
An owned 20-second host runtime recovers 7,945 unchanged Schema 1.0 originals
with Manager body preservation and 23 graph health records. Host ETW is denied;
there are zero archived lifecycle records and the absent-identity query correctly
returns no evidence/edges. Live native ancestry and guest qualification remain
unverified. See [process graph](PROCESS_GRAPH.md) and
`demo-run/process-graph/persistence-runtime-715aca2c54b841589d0aaef8103f7e53/process-graph-report.json`.
B/AG remain partial. Latest hashed Release package:
`staging/build-20261007-043554`.

Device Guard/VBS provider wave, 2026-10-07: ten selected local Win32_DeviceGuard
properties are captured with native HRESULT/type/carrier provenance, bounded
SAFEARRAY copying, immutable journal retry and independent capture freshness.
Fresh Debug/Release builds pass all 38 CTest entries (24.98/22.07 s). Native host
component/runtime queries each return ten readable properties. An owned
20-second Release runtime and abrupt exit recover 11,643 originals with
byte-identical repeated readback, Schema 1.0 validity and Manager body preservation.
One durable Device Guard capture and 22 committed health bindings match the exact
body/record and capture/commit ordering. Effective enforcement, policy authority,
attestation, provider deadlines/faults and cross-version/guest qualification remain
unverified. X/Y remain partial. See [Device Guard evidence](DEVICE_GUARD.md) and
`demo-run/device-guard/persistence-runtime-0caed55b684c49ef805d39476ed27a2f/device-guard-report.json`.

Durable process history wave, 2026-10-07: schema 5 archives exact encrypted
canonical-tagged process birth/stop originals atomically with delivery acceptance
and source checkpoint updates. ACK retirement cannot erase local lifecycle
evidence. Shared retention quota charges both copies before ACK and the archive
afterward. Bounded streaming inspection and durable count/byte health are added.
This is lifecycle evidence retention, not a complete or trusted process graph.
Fresh Debug/Release builds pass all 37 CTest entries (23.06/18.44 s), including
schema-4 migration, rollback on shared quota/cursor refusal, retry after ACK,
encrypted reopen and actual abrupt child exit after lifecycle retirement.
An owned 20-second Release runtime recovers 13,762 immutable records; all pass
Schema 1.0 and Manager body preservation. Twenty-five archive health records
report zero lifecycle rows/degraded scope; streaming archive readback is empty.
Host ETW remains access-denied. Evidence:
`demo-run/history-runtime/persistence-runtime-4f0f684e7b794609ad5997de3cbfe778/report.json`
and `history-report.json`. Positive archive lifecycle contents are component
fixtures, not live privileged source/guest evidence. Guest harness archive
readbacks and exact identity verification are prepared; execution remains pending.
See [process history](PROCESS_HISTORY.md). B/AG remain partial.


VM access/recovery wave, 2026-10-07: the dedicated four-vCPU/4096 MiB guest
still has a black framebuffer and Guest Additions unavailable. Two 30-second
storage samples are identical; Ctrl+Alt+Delete has no visible effect and a normal
ACPI shutdown request did not stop the guest. No bug check is reported. A live
diagnostic snapshot completed successfully (UUID
`019f78a5-96dd-4e03-988c-b2962f65c084`) before one recovery reset; the guest
returned to EFI Windows boot-manager loading and a boot splash. This preserves
the original installation stall. Post-reset disk reads increased from 101,311,488
to 285,601,792 bytes and writes from 13,312 to 48,895,488 bytes over 30 seconds,
with a boot spinner visible. This verifies boot activity, not successful
installation/login or endpoint execution. Those remain unverified. Evidence:
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\diagnostics\run-dd4140dffe9842269886a1b78947447f\report.json`.
The subsequent framebuffer reached Windows setup's `Installing 0%` screen,
confirming installation resumed beyond the black screen; completion is pending.
Post-reset evidence is in `diagnostics\run-1fa98df51f82418eb1ce1de1572df280`
under the same validation root.
The new Diagnose action retains scoped state/storage/memory/screenshot evidence,
excludes secrets and suspect debugger clock queries, and performs no recovery
mutation. Guest validation now guards guest/elevation before mutation, defaults
to native ETW and optionally verifies a live owned stop using exact PID plus
creation FILETIME/exit code, with immutable recovery and retained failure reports.
Both scripts pass PowerShell AST parsing; the guest script rejects this host
before package access. These are tooling checks, **not guest validation**. New
Release package `build-20261007-011626` retains existing binaries with updated
scripts and hashes. See [VM workflow](WINDOWS_VM.md). No capability is promoted.

Process stop wave, 2026-10-07: native ETW ID 2 and Sysmon ID 5 decode/dispatch
paths now emit dedicated canonical stop observations, independent stop clocks,
exact native/source-scoped identity or explicit null, and source facts. Resident
tombstones change after durable acceptance; late duplicate stops cannot move
the earliest retained stop or affect a reused PID instance. Source availability
projects scoped degraded/blind stop health. Stops bypass legacy birth normalization
and creation-cache admission. TDH metadata/property copy and name/array bounds
are enforced. Debug build and all 37 CTest entries pass (26.35 s).
Tests exercise synthetic payloads using actual native TDH ID 2 version 0
metadata, truncated payloads, Sysmon XML/duplicate fields, clock/identity/PID reuse
and legacy-normalizer refusal. Release build and all 37 CTest entries also pass
(21.83 s). Three canonical stop fixtures pass Schema 1.0 and
Manager body preservation. Evidence:
`demo-run/process-lifecycle/1d342c71e5914394ac80e2bba006b051/report.json`.
This is component/native-ABI evidence, not live privileged ETW or Sysmon
termination capture. Guest/live-source configuration,
complete lifecycle/ancestry and durable graph qualification remain open.
See [process lifecycle](PROCESS_LIFECYCLE.md). B remains partial.
An owned 20-second `--source etw` host runtime followed by abrupt exit recovers
3,708 records with identical complete readbacks. All originals pass Schema 1.0
and Manager native-data preservation. ETW StartTraceW explicitly reports access
denied; zero stop records are retained and scoped stop coverage is blind. Other
native state/log capture continues. This verifies refusal/coverage behavior,
not live termination telemetry. Evidence:
`demo-run/lifecycle-runtime/persistence-runtime-4b32a09b80b34af784c549bd1a153f4d/report.json`
and its `stop-source-report.json`. The new Release package includes the lifecycle
test binary; guest execution remains pending.

SCM host wave, 2026-10-07: own-process `--service` dispatch, explicit status
transitions, short STOP/SHUTDOWN handlers and owned/duplicated stop events are
implemented. Absolute enabled storage/credential/action-root paths are required.
Checkpoints reflect actual startup/join/drain progress, never a timer that masks
a stuck native call. Runtime host mode and incomplete service scope appear in
durable health. All 36 CTest entries pass in fresh Debug/Release builds
(24.22/20.38 s after final status-error propagation refinement).
The status sink tests cover stop/readiness races, duplicate controls,
checkpoint semantics, failures and exactly-once terminal publication.

Native console invocation of `--service` correctly returns SCM error 1063 rather
than starting a console collector; `--service --help` succeeds. Evidence:
`demo-run/service-host/91dd5ac42c234be68c51043a0975ea92/report.json`.
This verifies dispatch rejection/CLI behavior, not an actual SCM start-stop.
A dedicated-guest-only LocalSystem start/stop/restart fixture is prepared,
checks package/executable/account/PID binding and preserves a still-active
service on observation timeout. Guest installation remains unverified, so the
fixture has not run. Same-account DPAPI content recovery, hard native deadlines,
shutdown/reboot/fault/security qualification, installer/signing/update and broker
separation remain open. See [service host](SERVICE_HOST.md). AJ remains partial.
An owned console runtime after the service dispatch refactor recovers 2,992
records following abrupt exit; complete stopped-spool readbacks are identical.
All records pass Schema 1.0 and preserve native data through Manager, with 25
health records explicitly identifying console mode and incomplete service
qualification. Evidence:
`demo-run/service-console/persistence-runtime-935850bf64a64695aad4694c1dfa5a29/report.json`
and its `manager-body-preservation.json`. This is a console regression, not SCM
or orderly service shutdown proof.

Native software registration wave, 2026-10-07: independent MSI and selected
uninstall-registry workers emit durable begin/pages/manifests and source-bound
freshness. Fresh Debug/Release builds pass all 35 CTest entries (24.65/21.08 s).
Owned HKCU fixture checks include malformed UTF-16 metadata, no actor/file proof,
bounded pages, refusal and cancellation. Independent MSI failure and stale
software-domain freshness regressions pass. A first runtime check exposed false
copy-refusal accounting from untouched output lengths on failed native calls;
fixed it, added regressions and reran both builds/runtimes. Earlier evidence is
retained but superseded for that counter.

Corrected owned 20-second Debug/Release runtimes followed by abrupt exit recover
4,169/13,386 records. Software capture retains 213 MSI registrations plus two
all-user-context ERROR_ACCESS_DENIED rows, and 389 uninstall registrations plus
six absent-partition rows. Five MSI property getters report ERROR_UNKNOWN_PROPERTY
(1608). MSI enumeration is incomplete; registry indexed enumeration completes
without proving atomic/full software coverage. Four fixture failures are the
owned malformed string appearing in retained registry views/hive observations.
Both sources stay degraded with zero copy refusals. Capture sets assemble,
accepted manifests match committed fresh health, and second readbacks are
byte-identical. All runtime originals and 158 component fixtures per build pass
Schema 1.0 and Manager native-data preservation. Evidence:
`demo-run/software-fixed/persistence-runtime-93f600e00b6741e99f0c6e60a3e29fea/report.json`
and `demo-run/software-release/persistence-runtime-017b8ce665364f2d963780ab423b3a43/report.json`,
with separate `manager-body-preservation.json` reports. See
[software state](SOFTWARE_STATE.md). Guest tests remain pending; the new Release
package and nine-source guest checks are prepared. No VM/soak/complete Z claim.

Native account/group/logon/WTS wave, 2026-10-07: four independent bounded-page
workers now emit durable captures, immutable admission retries and explicit
query/copy/budget/cancellation health. All 34 CTest entries pass in fresh Debug
and Release builds (23.67/23.32 s). Native host queries retain seven account,
50 group/member/summary, 26 logon and two WTS rows. Twenty-four LSA queries return
NTSTATUS 0xC0000022; denied rows remain visible. All identity sources remain
degraded; enumeration completion does not prove a complete identity census.
Owned 20-second Debug/Release runtimes followed by abrupt exit recover
4,238/13,200 records. All seven identity/persistence capture sets assemble;
accepted manifests match committed fresh health, and second readbacks are
byte-identical. All originals and 88 component fixtures per build pass endpoint
Schema 1.0 and Manager native-data preservation. Evidence:
`demo-run/identity/persistence-runtime-263852cfe0ac46899062d94bd51ed990/report.json`
and `demo-run/identity-release/persistence-runtime-951f0afa1feb4ba595720ebccac88cce/report.json`.
See [identity state](IDENTITY_STATE.md) for semantics and remaining gates.
The guest script now validates all seven sources and a fresh Release package
was staged. The four-CPU/4-GiB guest is running but has no ready Guest Additions
channel; no guest execution or VM qualification is claimed.
Additional focused Debug/Release freshness regressions pass: LSA refusal cannot
erase independent account/group/WTS evidence; stale identity captures make D/U
blind; local account evidence cannot invent remote-session coverage. Only the
test target changed after the full 34-test runs; the fresh test binary was
included in a new staged package. Manager preservation evidence is retained as
`manager-body-preservation.json` alongside each runtime report.

Native persistence wave, 2026-10-07: independent Task Scheduler definition/getter/
SDDL, permanent WMI subscription and selected startup registry/folder workers
now emit durable begin/pages/ordered manifests with immutable refusal retries,
explicit query/copy/budget/cancellation accounting and record-bound freshness.
Fresh Debug/Release builds pass all 33 CTest entries. Native host checks retain
371 task/folder, nine WMI object/scan and 92 startup rows. Four loaded
LocalService/NetworkService Run-key access refusals remain explicit; startup
enumeration is incomplete. An owned 20-second Debug runtime and abrupt exit
recover 5,851 records. All three capture sets assemble exactly; health references
accepted manifests, and second readback is identical. All 37 component and 5,851
runtime records pass shared Schema 1.0 and Manager native-body preservation.
Evidence: `demo-run/persistence/persistence-runtime-7b5ab233966c4bbea86b45b74dd60f44/report.json`.
Guest installation is still running; guest execution/qualification is pending.
See [persistence](PERSISTENCE_STATE.md). No broad Detection scenario was run.

The fresh Release 20-second run retained 10,071 records. The initial recovery
harness correctly refused its 10,000-record aggregate bound; this was a harness
limit, not journal loss. Added bounded-page NDJSON streaming readback and verified
the same stopped spool without restarting the endpoint. All 10,071 originals
pass Schema 1.0 and Manager native-body preservation; all three capture sets and
fresh health match, and two complete readbacks have identical SHA-256
`9dddf017b4060273b83e761ca85fbfea2d1d110c67a92db80d4cced1cadd0b30`.
Evidence: `demo-run/persistence-release/persistence-runtime-57dfe38ec14e4abcb824cd9f48a19987/report.json`.
The final Debug/Release builds and all 33 CTest entries pass (22.12/13.60 s). Short-run record
counts are functional recovery evidence, not throughput/soak qualification.

Independent Windows log wave, 2026-10-06: MSVC x64 Debug build and all 32
native CTest entries pass (23.82 s). Added decoder/CAS/encryption/quota/ACK/reopen
checks, real owned Application EvtSubscribe/EvtNext refusal retries and strict
bookmark restart, plus abrupt owned process exit after combined record/cursor
commit. The Application test retains exactly two owned tokens across collector
restart without re-consuming the first accepted event. Full channel/event,
log-generation continuity, attribution and resource qualification are not implied.

Actual owned agent runtime for 12 s, then abrupt exit and immutable spool reopen,
recovers 566 canonical records: 483 native XML records from five channels
(classic PowerShell 97, System 97, PowerShell Operational 97, WMI Activity 97,
Defender Operational 95), with 14 per-channel health records. All recovered
records and ten C++ envelope fixtures pass canonical JSON Schema 1.0.
Security accurately reports ERROR_ACCESS_DENIED (5); TaskScheduler and DNS Client
Operational accurately report disabled. Backlog replay remains visible and
continuity unverified; writer PID is never promoted to subject identity. Evidence:
`demo-run/winevt/winevt-runtime-f2d6628f871f4518afbf4b1d18df0ff8/report.json`.
Modern 36-property Defender contract preservation also passes the pending Manager
check (1 passed, 29 deselected, 4.09 s). No broad Detection Engine scenario was run.
See [Windows logs](WINDOWS_EVENT_LOG.md) for scope and remaining gates.

A fresh Release build and all 32 native CTest entries also pass (22.41 s).
The separate 12 s Release executable run recovers 2,933 canonical records,
including 2,819 native log records across the same five channels, with 23
per-channel health records. All recovered originals and ten fixtures pass
canonical JSON Schema, and second stopped-spool readback is identical. Evidence:
`demo-run/winevt-release/winevt-runtime-504361ddd25e403a9676a13048972829/report.json`.
These short runs are functional evidence, not throughput budgets or soak proof.
Final rebuild after collection-boot metadata and stopped-worker health hardening
passes all 32 native entries in both Debug and Release (final Release 17.64 s).
The final ten C++ log fixtures also pass the common Manager EndpointRecord model
without schema or Detection changes. The current Release binaries and valid
Microsoft VC runtime were packaged with SHA-256 manifest for the dedicated guest
under `C:\Users\Acer\Documents\Panopticon-Windows-Validation\staging\build-20261006-233721`.
Guest installation/execution remains pending; packaging is not deployment proof.

Dedicated VirtualBox Windows 11 validation VM was created without modifying
the existing Linux or Windows analysis VMs. Its 4 GiB/four-vCPU/80 GiB dynamic
disk/EFI/TPM/NAT/read-only staging configuration is verified. Official Microsoft
LTSC evaluation image download completed (5,112,850,432 bytes), its local SHA-256
and official HTTPS provenance were recorded, and protected unattended installation
was prepared. Following explicit user authorization to run concurrently under
memory pressure, the owned guest was started headless with four vCPUs and
4096 MiB RAM. Windows 11 installation was visually observed at 11 percent;
Guest Additions, guest tests and qualified baseline snapshot remain pending.
Download and guest workflow are tracked in [Windows VM](WINDOWS_VM.md).
The default 5 GiB startup gate remains, with an explicit override. Host page-file
capacity is not proof of guest performance. Prepared scripts are not VM runtime evidence.
PowerShell helper parsing and the refusing resource gate were exercised. The
Microsoft VC runtime installer downloads successfully and its publisher
Authenticode signature is valid. No A–AN domain is complete.

Defender independent-state increment: MSVC x64 build and all 31 native CTest
entries pass (24.75 s). Native tests preserve Boolean false/true versus invalid
raw values, uint32 high bits and age sentinel, uint8, CIM mismatch, null/BYREF/
array refusal, embedded NUL, raw malformed/odd BSTR bytes, per-property/row copy
bounds, raw DATETIME and incompatible caller apartment ownership. All 30 Manager
endpoint-record tests pass (24.05 s), preserving native and decoder/refusal
records through schema, duplicate ingestion, immutable readback and unchanged
Detection data. Actual owned runtime reads all 33 selected Defender properties
without getter failures, then preserves the exact snapshot and record-bound
health through abrupt exit/reopen alongside all eleven state sources and 22
accepted capture transitions. Unread stdout/stderr recovery retains 127 durable
records and 41 health records across all eleven state sources. Provider-reported
properties do not verify protection. Subsequent malformed-text hardening retains
exact ERROR_NO_UNICODE_TRANSLATION alongside raw bytes; Defender/freshness native
checks pass (2 tests, 0.70 s) and the Manager Defender preservation check passes
(1 test, 1.11 s). Scoped Ruff and whitespace checks pass. Live Server/service-account/ARM64,
provider-fault/deadline/resource and full compatibility/soak gates remain open in
[Defender status](DEFENDER_STATUS.md); no capability domain is complete.

Security Center platform-provenance increment: final MSVC x64 build and all 30
native CTest entries pass (20.06 s). Injected native version cases cover client,
Server/domain-controller, pre-Vista client, unknown product type, nonzero success,
NTSTATUS refusal and unresolved version API. Unsupported WSC contract platforms
still perform and retain descriptive category queries; trusted report fields stay
null while raw outputs/native query quality remain intact. Only the narrow WSC
capability is unsupported; full security-product Server visibility remains a
required unavailable capability. All 29 Manager endpoint-record tests pass
(20.02 s), preserving platform/error and outside-contract evidence through schema,
duplicate ingestion, immutable readback and unchanged Detection data. Scoped Ruff
passes. Actual owned client runtime reports native NTSTATUS 0, version 10.0 build
26220/product type 1, contract eligibility true and platform_qualified false;
the exact snapshot/health and all ten state domains recover after abrupt exit.
Unread output recovery retains 121 records and 38 health records across all ten
state domains. Live Server, resolver/NTSTATUS fault injection, Server fallback,
attestation and full compatibility qualification remain open in
[Security Center state](SECURITY_CENTER.md).

Security Center category increment: MSVC x64 build and all 30 native CTest entries
pass (22.71 s); further poor-report/query-quality, unusual success HRESULT and
invalid S_FALSE fallback regressions pass (0.14 s). Six independent provider
masks, recognized/unknown/sentinel output, HRESULT failures, absent API and
service-unavailable interpretation are covered. Native PE import inspection
confirms officer-agent.exe has no static Wscapi.dll dependency. All 28 Manager
endpoint-record checks pass (21.41 s), including published-schema validation,
duplicate retention, immutable readback and unchanged Detection data without an
invented actor/product identity. Actual owned runtime/reopen retains six S_OK
category results, exact snapshot and matching record-bound health, all ten state
domains and 20 accepted capture transitions. A separate unread-output runtime
recovers 124 durable records and 41 health records across all ten state domains.
Six successful reports do not verify protection or enumerate individual products.
Native missing-DLL/service-stop/fault injection, Server fallback, Defender/ASR/
SmartScreen/tamper/exclusions, native notifications and full OS/resource/soak
qualification remain open in [Security Center state](SECURITY_CENTER.md).

State transition quota-refusal/reopen increment: native MSVC build and the
state-freshness/source-history/journal regressions pass (3 tests, 0.90 s).
A subsequent state-freshness regression verifies the exact retention-quota
error branch (0.21 s). An owned journal refuses the oldest canonical gap at a
payload limit one byte below its size, with zero pending records; later sampled
blind/recovered transitions do not overwrite that pending front. Reopening with
sufficient quota accepts its identical bytes and the ordered outage/recovery;
a second reopen preserves all three original bodies exactly. All 27 Manager
endpoint-record tests pass (18.76 s), including the actual retained/decrypted
retry bodies through published schema validation, duplicate ingestion, immutable
readback and unchanged Detection data. Both transition fixture modes pass again
after the exact quota-error assertion (2 tests, 0.85 s). Scoped Ruff passes. This establishes the
controlled payload-quota refusal and reopen path; actual full-disk, DPAPI,
corruption, abrupt pre-commit loss, emergency reserve and full endpoint gates
remain open. See [state freshness](STATE_FRESHNESS.md).

State capture transition history increment: MSVC x64 build and all 29 native
CTest entries pass (19.75 s); subsequent per-source absent-sample and encoded-byte
bound regressions pass (0.14 s). Native checks preserve the pending front across
blind/recovery samples, update observed anchors without duplicate healthy
transitions, retain chronological reports, separate count/byte bounds and retain
an ordered two-report omission summary with null native loss count. All 26 Manager
endpoint-record checks pass (21.47 s), including published-schema validation,
duplicate retention, immutable readback and unchanged Detection data for transition
and omission fixtures. Scoped Ruff passes. Actual owned runtime/reopen preserves
18 exact accepted state capture transition records alongside all nine state
domains and matching health; these live records cover initial eligibility and
fresh captures, not a six-minute live overdue experiment. Unread-output runtime
recovers 121 durable records and 41 health records across all nine state domains.
Real state-history journal refusal, volatile pending-history crash loss, emergency
reserve, emitter-blockage delivery and full qualification remain open in
[state freshness](STATE_FRESHNESS.md).

Periodic state freshness increment: final MSVC x64 build and all 29 native CTest
entries pass (21.50 s). Native clock regressions cover all nine state domains,
the exact 360,000 ms boundary, stalled next collection, late durable acceptance,
missing/noncanonical/overflow/out-of-order clock evidence, disabled/unsupported
state preservation and new-capture recovery. Committed native query evidence
remains unchanged and process-event coverage stays independent. All 25 Manager
endpoint-record tests pass (22.71 s), including published-schema validation,
duplicate ingestion, immutable readback and unchanged Detection data for seven
native freshness fixtures. Scoped Ruff passes. Actual owned runtime/reopen checks
record-bound capture/commit ages across all nine sources, preserving complete
accepted pages/manifests and durable health. Unread-output runtime recovers 104
records, all nine current state domains and 42 health records with diagnostic
accounting after owned abrupt exit. A live six-minute blocked-collector trial,
suspend/reboot/distributed-age proof and whole-endpoint qualification are not
established by these runs. See [state freshness](STATE_FRESHNESS.md).

Firewall rule extensions increment: MSVC x64 build and all 28 native CTest
entries pass (21.56 s). A subsequent build with updated coverage scope and the
firewall rule regression passes (4.40 s). Native detached-object tests verify
edge option 3, IPsec requirement 4 and descriptive owner text without registering
any rule. Injected extension queries preserve E_NOINTERFACE versus E_ACCESSDENIED,
leave dependent getter HRESULTs null/unattempted, continue base getters and
distinguish successful null interfaces from native failures. All 24 Manager
endpoint-record tests pass (22.17 s), including retention of all 25 getter slots
and independent extension interface evidence. Scoped Ruff passes. Final owned
runtime/reopen checks retain 1,201 rule rows across 19 pages, matching manifest
and health, with the expanded getter surface explicitly checked. A separate
unread-output runtime recovers 106 durable records across all nine state domains,
including 44 health records and diagnostic accounting after owned abrupt exit.
Interface support and descriptive fields do not establish effective packet or
principal authorization, rule lifetimes or complete policy provenance. Native
getter failure/unknown-output, COM resource/deadline and full OS/soak qualification
remain open; see [rule inventory](FIREWALL_RULES.md).

Firewall rule inventory increment: final MSVC x64 build and all 28 native CTest
entries pass (19.08 s); all 24 Manager endpoint-record tests pass (18.95 s).
Native checks cover byte-driven paging, duplicate descriptive names, exact
accepted prefixes after consumer refusal, oversized rows, unavailable
enumeration and actual read-only native collection. Published-schema validation,
individual ingestion/readback and unchanged Detection data retain native getter
evidence, ordered capture relationships and null rule/process identities.
The owned agent captures 1,201 caller-visible rule objects in 19 durable pages;
its stopped journal retains the exact begin/pages/manifest and matching
record-bound health after abrupt exit. With stdout and stderr unread, a separate
owned runtime recovers 99 durable records across all nine current state domains,
including 37 health records and diagnostic accounting. Scoped Ruff and diff
checks pass. Enumeration and base getter success do not establish an atomic or
complete inventory, verified rule lifetimes or effective packet enforcement.
Extended properties, policy provenance, change coverage and full qualification
remain open in [rule inventory](FIREWALL_RULES.md).

Firewall exclusions increment: MSVC x64 build/all 27 native CTest entries pass
(16.33 s); additional firewall/response/journal checks pass (3 tests, 1.17 s),
with a subsequent partial-exclusion-refusal regression passing (0.19 s). Owned
COM arrays exercise UTF16/odd-byte lossless retention, embedded NULs, scalar
and BYREF refusal, duplicates, lower bounds, item/string/aggregate limits,
multiple dimensions and lock release. All 23 Manager endpoint-record checks
pass (14.46 s), scoped Ruff passes and actual owned runtime/reopen retains the
full updated firewall state and matching health. The native three exclusion
getters returned successful HRESULT 0 with VARTYPE 0; each remains degraded,
its list unknown and excluded_interfaces_collected false. No live nonempty
exclusion-list qualification, policy alteration or zero-exclusion claim follows
from this run. Full firewall/full endpoint qualification remains open. See
[firewall state](FIREWALL_STATE.md).

Firewall profile state increment: MSVC x64 build and all 27 native CTest entries
pass (16.51 s). Native property-fault regressions preserve HRESULTs, multiple
active profiles, separate query masks, invalid/sentinel/unknown outputs, partial
failures and nonzero successful HRESULTs. Additional native COM apartment
conflict/caller-ownership regression passes (0.24 s). All 23 Manager endpoint-record tests
pass (14.09 s), including published-schema validation, duplicate retention,
immutable readback and unchanged Detection data with no invented actor. Actual
owned runtime/reopen retains all 20 successful native getter results and matching
record-bound firewall health with the other seven state domains. Unread output
pipe runtime recovers 77 records across all eight current state domains and 36
health records after owned abrupt exit. Scoped Ruff passes. Local policy getter
coverage remains distinct from effective firewall enforcement and full inventory;
all missing qualification remains open in [firewall state](FIREWALL_STATE.md).

Source supervision history increment: MSVC x64 build and all 26 native CTest
entries pass (16.06 s). Added count/encoded-byte history bounds, pending-front
immutability, statistics outage/restoration and stop/resume retention, individual
counter availability and null restored-zero deltas. Further native source/journal/
response regression checks pass (3 tests, 0.86 s), including actual owned journal
quota refusal, acceptance of identical retry bytes after reopen, and exact
three-record retention on another reopen. Actual owned runtime/reopen passes
with all seven current state domains (454 process descriptors, 795 SCM rows,
30 IP interface rows and 90 route rows). Successful live source outage/fault
injection is not established by the current access-denied runtime. Volatile
history/crash/emergency-reserve/source continuity qualification remains open.
All 22 Manager endpoint-record checks pass (9.65 s), including native omission
fixtures validated against the published schema, duplicate ingestion, original
record retention and unchanged Detection data without fabricated actors/counts.
Scoped Ruff and diff checks pass.

Diagnostic isolation increment: MSVC x64 build and all 26 native CTest entries
pass (15.31 s). New owned-pipe tests cover blocked native output, in-flight count
bounds, cancellation, exact framing, borrowed handle ownership and exact native
closed-reader errors. An owned runtime with both output pipes unread recovered
77 records after abrupt exit, including all seven current state domains and 37
health records with bounded/reconciled diagnostic accounting. Normal file-output
runtime capture/reopen also passes (435 process descriptors, 795 SCM rows, 30 IP
interface rows and 90 route rows). This closes one main-loop console blocking
gap; startup/library logs, full resource/OS/fault qualification and full endpoint
DoD remain open. See [diagnostic output](DIAGNOSTIC_OUTPUT.md).

Independent IP interface census increment: final MSVC x64 build and all 25 native
CTest entries pass (14.89 s); all 21 Manager endpoint-record tests pass (10.40 s),
scoped Ruff and diff checks pass. Native regressions enumerate both families
without any route source, preserve independent posture and null lifetime
references, refuse copied-count mismatch and count/copy bounds before reads,
distinguish unsupported/access-refused families, and account only the accepted
page prefix. Missing successful native tables preserve native error 0 plus a
separate validation refusal; both route and interface collectors now use this
provenance distinction, with regressions for each. Actual owned runtime
abrupt-exit/reopen retains 30 independent interface rows (15 per family) in two
exact durable pages, manifest and record-bound per-family health alongside host,
process, service, driver, socket and route captures. IPv6 query/field admission
is narrowly healthy; IPv4 remains degraded for 14 raw site-prefix-64 rows,
also observed by independent GetIpInterfaceTable rather than only later lookup.
No cause, persistent association, effective route or complete compartment census
is inferred. Manager published-schema validation, exact accepted-body
readback/digest and Detection preserve independent table provenance without an
actor. Continuous interface changes, reconciliation/lifetimes, complete
compartment and link-layer/physical state, freshness, native allocator/deadline
and fault/crash/loss intent, OS/ARM64/resource/soak and analyst assembly remain
open. See [IP interface state](IP_INTERFACE_STATE.md). Full network or endpoint
Definition of Done completion is not established.

Route-associated IP interface increment: final MSVC x64 build and all 24 native
CTest entries pass (13.94 s); all 20 Manager endpoint-record cases pass (9.00 s),
scoped Ruff and diff checks pass. Native regressions preserve full DWORD/ULONG64
metric/identifier/zone values, unknown raw flags and setting-only behavior
sentinels, refuse truncated interface rows, verify a full-width metric sum while
keeping effective metric null, cache one query across 513 rows/pages, retain
routes after independent query refusal, and enforce 512 unique lookup attempts
without erasing the remaining rows. Partial-page accounting uses the actual
accepted page prefix under both byte and row bounds. Actual owned runtime
abrupt-exit/reopen retains all 90 routes in two pages, their later interface
facts, exact manifest/query health and state.route_ip_interface coverage. It
reports 30 successful unique native queries, 60 cached row reuses, zero failures
and zero unattempted rows. Fourteen successful IPv4 lookups report site-prefix
length 64, outside the documented IPv4 bound; values remain raw and degraded
without substituting a prefix or inferring a cause. Aggregate interface-query
coverage is degraded, although route-field table coverage is narrowly healthy.
Manager preserves the published canonical evidence and exact accepted-body
digest/readback; Detection still receives no invented actor. Full independent
interface census, lifetime/compartment/effective-path proof, change coverage,
freshness/deadlines/fault/crash/loss intent and OS/resource/soak qualification
remain open. See [route state](ROUTE_STATE.md). No full endpoint completion is
established.

Route-state increment: final MSVC x64 build and all 24 native CTest entries
pass (13.49 s); all 20 Manager endpoint-record cases pass (8.36 s), scoped Ruff
and diff checks pass. Native row regressions preserve full-width LUID/index,
metric/lifetime sentinels, unknown protocol/origin/BOOLEAN values and invalid
prefixes, refuse truncated rows and excessive reported counts, retain synthetic
native query denial and account only accepted pages after prefix refusal.
Actual read-only queries and owned runtime abrupt-exit/reopen retain 90 routes
(46 IPv4, 44 IPv6) in two exact durable pages, their manifest and record-bound
query/coverage health. Both family queries narrowly report healthy recognized
fields and complete reported-row admission; aggregate route state remains
degraded, inventory_complete and all_compartments_complete remain false.
Interface/route instance references and effective route metric stay null.
Manager published-schema validation, exact accepted wire-body readback/digest
and Detection preserve those distinctions without a process actor. Microsoft
now documents the compartment getter as reserved/not for use; collection does
not call it or change compartments. Native allocator extent/size is trusted
from the OS and unbounded before copied-row limits, explicitly exposed in the
manifest. Continuous notifications, native lifetime/compartment/effective-path
verification, full interface metrics, reconciliation, deadlines/allocator faults,
crash/gap intent, freshness, privilege/OS/ARM64/resource/storm/soak and analyst
capture assembly remain open. See [route state](ROUTE_STATE.md). No full network
domain or endpoint Definition of Done completion is established.

Socket-state increment: final MSVC x64 build and all 23 native CTest entries
pass (11.83 s); all 221 Manager tests pass (22.92 s), including 19 endpoint-record
cases. Scoped Ruff and diff checks pass. Native tests verify owned loopback TCP
listeners and UDP endpoints in both IPv4 and IPv6, all four SDK row layouts,
full raw DWORD fields, unknown TCP states, truncated buffers, exact native access
denial, bounded repeated resize and oversized requests, and consumer refusal
after one accepted page without counting rejected rows. Published canonical
schema validation, exact accepted-body immutable readback/digest and Detection
preserve rows with null process/socket-instance references. Final owned runtime
abrupt-exit/reopen retains 385 socket rows across two pages, the exact manifest
and record-bound table health, alongside independent host/process/service/driver
state. TCP4/TCP6 queries preserve 42/15 raw state-0 rows as unknown/degraded;
UDP4/UDP6 narrowly report healthy query/page admission. All four tables finish
with accepted counts matching reported rows, while full network coverage remains
degraded and inventory_complete false. Continuous activity, verified native
lifetimes/actors, deadlines, crash/gap intent, freshness, reconciliation,
privileged visibility, OS/ARM64/resource/storm/soak and analyst capture assembly
remain open. See [socket state](SOCKET_STATE.md). No endpoint domain or overall
Definition of Done is qualified complete by this increment.

Loaded-driver increment: final MSVC x64 build and all 22 native CTest entries
pass (14.13 s); all 18 Manager endpoint-record tests pass (9.29 s), scoped Ruff
and diff checks pass. Classifier regressions distinguish NULL-only blindness,
mixed visibility and full pointer-width raw values. Actual native collection
preserves owned-token privileges before/after and rejects consumer delivery
without counting uncommitted rows. The final owned runtime reports 272 NULL
address slots across two durable pages; loaded-driver coverage is blind. Exact
pages, manifest, per-query status and bound health survive abrupt exit/reopen,
alongside independent host/process and 795 SCM service records. Manager immutable
readback and Detection retain this independent domain with no guessed process,
SCM, file or module-instance association. Native non-null name/path execution,
buffer/API fault injection, load/unload/address reuse, signer/code integrity,
privilege-qualified collection, deadlines and OS/resource/soak qualification
remain open. See [loaded-driver state](LOADED_DRIVER_STATE.md).

Selected service security increment: MSVC x64 build and all 21 native CTest
entries pass (12.76 s); all 17 Manager endpoint-record tests pass (11.82 s).
Native regressions distinguish null/absent/empty DACLs, retain owner/group SID
components and unknown opaque ACE bytes, refuse outside/shared malformed SIDs,
ACL lengths, zero ACE sizes and absolute descriptor flags, and retain captured
bytes on validation refusal. Detailed ACE count is bounded without discarding
the full bounded ACL. Actual owned-process abrupt-exit/reopen retains 795 service
descriptors across sixteen pages, 790 selected security query successes and five
READ_CONTROL open refusals, with exact manifest, counters and bound health.
The larger capture exceeded the old single-batch verification reader: new bounded
read-only journal inspection traverses every pending record without ACK or data
reduction. Mixed-protocol order, byte/count paging, sequence holes, invalid/too-small
limits, no retirement and reopen are verified. Complete security/effective access,
SACL/labels, object-instance binding, source fault/deadline, live inspection and
OS/resource/soak qualification remain open. See [service security](SERVICE_STATE.md)
and [journal inspection](DURABLE_JOURNAL.md).

Service trigger increment: final MSVC x64 build and all 21 CTest entries pass
(12.27 s); all 17 Manager endpoint-record tests pass (7.95 s), scoped Ruff and
scoped diff checks pass. Native decoder regressions cover GUID byte ordering,
full-width unsigned keywords and unknown type/action codes, malformed/odd
UTF-16 with retained raw bytes, empty typed values, outside payloads, huge and
unaligned arrays, unused zero-count pointers, reserved non-null pointers and
overlapping-payload/text-segment expansion bounds. Actual owned-process
abrupt-exit/reopen retains 795 service/driver descriptors across eleven pages
with exact manifest, per-level accounting and record-bound health. All 795
trigger queries succeed natively; 43 records remain degraded for unqualified
type 7/30 semantics. A separate live read observes 118 records with configured
triggers, with zero structural validation failures or collection bounds hit.
Local SDK names for 7/30 are preserved without treating labels as semantic
qualification. Manager and Detection retain exact native domain data with no
guessed process association. Trigger firing/changes, instance identity, complete
system-state/aggregate semantics, security descriptors, source fault/deadline
and OS/resource/soak qualification remain open. See [trigger scope](SERVICE_STATE.md).

Optional service configuration increment: MSVC x64 builds; all 21 native tests
pass (10.48 s), with the subsequently added page-ceiling/undelivered-query
regression passing separately (1.91 s). All 17 Manager endpoint-record tests
pass (7.65 s) and scoped Ruff passes. Bounded decoder tests preserve full-width
unknown launch/SID/action codes, raw nonzero BOOL bits, null versus configured
privilege lists, MULTISZ bounds, outside description pointers, huge/unaligned
action arrays, partial scalar evidence and null action pointers. Actual read-only
SCM querying retains 795 descriptors across ten durable pages. Ten description
queries fail independently; Task Scheduler reports action type 4, which remains
raw, uninterpreted and degraded because documented action types cover 0–3.
All selected per-level counters and capability states match exact page facts and
the committed manifest, and abrupt exit/reopen preserves those records and
health unchanged. The read probe now explicitly rejects partial single-batch
readback instead of presenting a transport ceiling as journal loss. Hidden
services, running-instance association, security descriptors/triggers, native
API fault injection, deadlines and OS/resource/soak qualification remain open.
See [service configuration scope](SERVICE_STATE.md).

Service/driver inventory increment: MSVC x64 build and all 21 native CTest
entries pass (10.39 s). All 17 Manager endpoint-record tests pass after explicit
UTF-8 decoding of native probes (5.08 s),
the full Manager suite passes 219 tests (19.01 s), and scoped Ruff passes.
Actual owned-process abrupt-exit/reopen retains 795 caller-visible SCM descriptors
across four pages, exact manifest and record-bound service health, alongside host
and process state. Unicode comparison exposed cp1252 decoding in the verification
subprocess; explicit UTF-8 readback restores exact source text. Small native
enumeration buffers exercise SCM resume paging; count/byte/consumer refusals,
malformed UTF-16, pointer bounds and missing terminators are tested. Manager
readback preserves original body bytes/digest and rejects wrong-agent access;
Detection retains service facts with null process attribution. This does not
qualify hidden-service coverage, service instance identity, lifecycle, loaded
driver provenance, native fault/deadline behavior or OS/performance/soak coverage.
See [service state](SERVICE_STATE.md).

Process architecture increment: final MSVC x64 build and all 20 CTest entries
pass (9.56 s); all 16 Manager endpoint-record tests pass (3.47 s), and changed
Python passes Ruff. The owned held-object result matches actual IsWow64Process2
codes; classifier checks preserve not-WOW zero, separate x86/x64 and x64/ARM64
machine pairs, full-width unknown codes and an unknown native host without
architecture guesses. Simulated code pairs do not prove actual emulation or
ARM64 execution. Native entrypoint resolution occurs once per capture and retries
next capture instead of caching lookup failures for the agent lifetime. Final
actual owned-process crash/reopen recovers 426 descriptors across three pages,
240 successful architecture reports and 186 unattempted process queries, with
aggregate architecture degraded and process events blind. Exact pages, manifest
architecture summary, token facts, independent host state and committed health
are retained. API absence/native-fault injection, real x86/ARM64/ARM64EC execution,
image/module ABI, exit/protected-target races, deadlines and resource/service/OS
qualification remain open. See [process architecture scope](PROCESS_STATE.md).

Primary-token context increment: final MSVC x64 build and all 20 CTest entries
pass (9.54 s); all 16 Manager endpoint-record tests pass (3.16 s), and changed
Python passes Ruff. Owned token SID/session/elevation/LUID/count facts match
independent native calls. Invalid held-handle access preserves Win32 6 without
caller-token fallback. Truncated/outside/unaligned/null SID pointers and excessive
subauthority headers are refused before native dereference; unknown integrity
RIDs and zero/future full-width elevation types remain raw and uninterpreted.
The actual TokenElevation zero-size probe returned Win32 24; corrected queries
start at the class structure size and bound resizes/bytes without suppressing
other errors. Final actual crash/reopen retains 410 descriptors across two pages,
224 opened tokens, one token-open refusal and 1,344 successful field queries;
185 process descriptors could not reach held-object security queries. Exact pages,
manifest token summaries, independent host state and record-bound health recover,
while selected-token coverage stays degraded and process event coverage blind.
These run-specific counts do not prove complete token/user/session state. Native
resize/size-fault injection, protected/privileged targets, context races, complete
groups/privileges/effective access, thread impersonation, deltas/reconciliation,
API deadlines and resource/service/OS qualification remain open. See
[primary-token scope and limits](PROCESS_TOKEN.md).

Process security-context increment: final MSVC x64 build and all 20 CTest entries
pass (9.31 s); all 16 Manager endpoint-record tests pass (2.61 s), and changed
Python passes Ruff. Owned held-object critical/protection values match native
queries; zero differs from the full-width NONE sentinel, and unknown/full-width
or documented unimplemented levels remain degraded with raw values. Query
summary counts match native pages and retain failed and unattempted queries.
An initial test incorrectly required the owned process to fit the bounded
single-prefix record; larger security rows exposed this assumption. Ownership
verification now streams paged enumeration while preserving prefix byte limits
and incomplete flags. An earlier actual crash run recovered 424 entries across
two pages exactly. The final runtime run recovers 409 entries on one page, with
224 successful queries per security API and 185 unattempted process queries;
aggregate security health correctly stays degraded and process event coverage
blind. Exact committed manifest security summary, pages, host state and health
survive abrupt exit. Counts and page counts describe their specific runs, not
a stable host census or complete protected-process visibility. Critical/PPL
target creation, native API failure/exit races, context changes, privileges,
service/OS compatibility, performance and full lifecycle remain unqualified.
See [process security query scope](PROCESS_STATE.md).

Unfinished process-capture discovery increment: all 218 Manager tests pass
(18.56 s); final expanded endpoint/migration checks pass all 21 tests (2.69 s),
and changed Python passes Ruff. Migration 17 backfills existing and orphaned
page records one body at a time, preserving exact payload/digest and Detection
disposition through upgrade/reopen. Transaction tests verify immutable collision
rollback removes both new evidence and its derived capture index entry. Native
compiled multi-page records pass discovery/count and exact per-record readback
with matching scope. Unfinished begins, delayed manifests, pagination, foreign
captures, boot mismatch, malformed page indexes, duplicate delivery, access
isolation and parameter bounds are exercised. Discovery does not infer crashes
or source loss from an absent manifest, and a retained manifest remains
unverified until separate assembly checks. Endpoint restart reconciliation,
capture resume, concurrent late-arrival convergence, index/query/resource and
fleet qualification remain open. No native implementation changed in this
increment. See [Manager capture API](../../../panopticon-manager/docs/PROCESS_SNAPSHOTS.md).

Paged process-state increment: final MSVC x64 build and all 20 CTest entries
pass (9.31 s), all 215 Manager tests pass (27.41 s), and changed Python passes
Ruff. Native checks cover multi-page enumeration, total/page limits, oversized
row refusal and consumer refusal without counting undelivered rows. A compiled
native producer emits multiple pages through actual authenticated Manager
ingestion; missing/reordered page references, token isolation and aggregate
verification-budget refusal cannot claim complete assembly. Individual retained
pages remain retrievable after budget refusal. The owned runtime crash fixture
recovers an exact 453-entry capture (one page on this host/run), its manifest,
independent host state and record-bound health; endpoint-reported enumeration
is complete while event process coverage stays blind. Multi-page producer
integration and single-page runtime recovery are separate evidence: runtime
large-capture/multi-batch recovery, query deadlines, protected/PID-reuse races,
incomplete-capture restart reconciliation, full lifecycle and resource/OS/soak
qualification remain open. See [process state scope](PROCESS_STATE.md) and
[Manager verification API](../../../panopticon-manager/docs/PROCESS_SNAPSHOTS.md).

Native process-inventory increment: final MSVC x64 build and all 20 CTest entries
pass (8.41 s); all 13 Manager endpoint-record tests pass (2.60 s). The compiled
producer passes published schema validation, authenticated immutable retention/
latest projection and unchanged Detection payload. Native tests compare the
owned process's full creation token and shared exact identity formula, require
no entity with absent boot scope, preserve undefined exit time as null, and
exercise descriptor-count/encoded-byte bounds. The actual owned-process agent
crash fixture recovers an exact 439-entry process snapshot, with enumeration
complete on this run, committed query summaries matching state, and independent
host/health recovery. Event process coverage correctly remains blind without a
subscribed source. Changed Python passes Ruff. The first runtime fixture exposed
a missing health notification after process commit; corrected notification and
collection-progress reporting remove the stale-uncommitted health condition.
This does not prove all process queries succeeded, PID-reuse/exit races, protected
process coverage, verified ancestry, full/paged enumeration under bounds,
persistent lifecycle/deltas, API deadlines, service/OS compatibility or storm/
soak qualification. See [process state scope and limits](PROCESS_STATE.md).

System audit-policy increment: MSVC x64 build and all 19 CTest entries pass
(9.67 s); all 12 Manager endpoint-record tests pass (2.14 s) with the actual
compiled native snapshot, published schema validation, authenticated immutable
retention/latest projection and exact Detection state payload. Changed Python
passes Ruff. Native tests classify success/failure/NONE, zero, contradictory and
unknown/full-width masks without guessing effective settings. Actual read-only
enumeration returns 60 subcategories on this host; AuditQuerySystemPolicy fails
with Win32 1314. No policy or privilege is changed; the value remains null and
audit query coverage unavailable. The owned-process live/crash fixture reports
25 fields and preserves source/error domain/code, enumerated count and scope in
record-bound health and exact durable state recovery. Elevated/service-account
successful row acquisition, native malformed/duplicate/count faults, API timeout,
per-user/token effective policy, audit options, Security event delivery, changes,
shared snapshot budgets and OS/fault qualification remain open. See
[native host state audit scope](HOST_STATE.md).

Handoff contention correction: a four-producer, 4,000-event one-attempt check
exposed 3,027 try-lock refusals despite capacity for all events. Replaced that
policy with a preallocated ring and short mutex section; no handler I/O runs
under the lock and no slot/deque allocation occurs during admission. Final MSVC
x64 build and all 19 CTest entries pass (8.77 s). Concurrent tests admit/complete
all 4,000 values once with zero refusal, both with a lightweight handler and a
handler blocked during submission. A separate pressure run reports submitted
4,000/admitted 4,000/completed 4,000/refused zero. Two-slot wrap/reuse tests retain
FIFO and reject stale replay. Live crash/reopen verifies fixed ring storage,
retired contention policy, accounting/bounds and exact durable health; changed
Python passes Ruff. Exception refusals are named explicitly rather than presumed
allocation failures. Ring memory is separately observed; neither the charge nor
the test proves total RSS, bounded scheduler/mutex latency, actual source storm
throughput, fairness, full native callback isolation or crash-safe RAM intent.

Decoded-event handoff increment: MSVC x64 build and all 19 CTest entries pass
(7.42 s). New native tests block the downstream real journal handler using an
owned test gate, exercise count and byte limits independently while the in-flight
event remains charged, verify no pre-commit durable count, then recover exact
downstream bytes. Reserved string capacities are tested via move ownership;
registry/cache fields, oversize/closed refusal and worker exception continuation
are checked. The first test run exposed a test copying away reserved capacity;
the corrected test exercises production move semantics. The actual runtime/crash
fixture verifies handoff accounting/bounds, degraded coverage and exact durable
handoff health recovery; changed harness passes Ruff. This live host had no
ETW subscription, so runtime checks do not validate active sensor storms or
inject a real callback loss. Native rendering/decoding and console shutdown
deadlines, source fairness, allocation/RSS budgets, crash-safe volatile intent,
durable emergency loss accounting, privileged faults and soak remain open.
See [callback handoff scope and tests](CALLBACK_HANDOFF.md).

Sampled storage-admission increment: MSVC x64 build and all 18 CTest entries pass
(8.52 s). Native tests lower configured physical/headroom admission limits without
filling or modifying the host volume: new encrypted observations, commands,
outcomes, generation metadata and rejection reasons refuse while exact retained
observations/command intent survive reopen. Invalid rejection growth rolls back;
valid acceptance ACK still reclaims under pressure. Normal limits restore outcome
and handoff progress. Refusal counters explicitly reset on object recreation.
The actual offline agent exposes degraded storage safeguards with exact decimal
limits and caller-available bytes; the owned-process crash/reopen harness verifies
exact durable health recovery. Changed harness passes Ruff. The 1,000-event short
FULL/WAL/DPAPI preflight benchmark measures 1,030.87 events/s, p50 0.872 ms,
p95 1.046 ms, maximum 2.544 ms: below the approved 2,000 events/s target. This
is not a paired regression measurement, disk-full/NTFS quota/I/O fault test or
storm/soak qualification. Hard physical/aggregate budgets, reserved emergency
capacity, durable full-disk loss accounting and performance remain open. See
[journal admission scope and limits](DURABLE_JOURNAL.md).

Native volume inventory increment: MSVC x64 build and all 18 CTest entries pass
(7.45 s); all 12 Manager endpoint-record tests pass (1.21 s) with the actual compiled
host snapshot, schema validation, authenticated immutable retention/latest projection
and unchanged Detection state payload. Changed Python passes Ruff. The live host
enumerates four local volumes completely, with successful mount/filesystem/capacity
queries and zero retained child-query failures or bounds exceeded. Native tests
exercise multiple/empty mount lists, missing/trailing MULTISZ termination, 257-path
exhaustion, encoded volume-list bounds, exact decimal capacity types and restoration
of the caller thread error mode. These checks do not simulate native enumeration,
buffer-race/I/O or removable-media faults. The actual owned-process agent crash harness
passes with volume coverage degraded, query failure/bound metadata preserved in
record-bound health, and exact snapshot/health recovery after abrupt exit. Full
physical disk/extents, encryption, removable/network storage, deadlines, change
continuity, shared record budgets, spool physical budgeting/emergency reserve and
OS/privilege/fault/soak qualification remain open. See [host state](HOST_STATE.md).

Native TPM/default-Entra increment: MSVC x64 build and all 18 CTest entries pass
(8.96 s); all 12 Manager endpoint-record tests pass (2.15 s), including actual
compiled native host-state schema validation, authenticated retention/latest
projection and exact Detection transformation. Changed Python passes Ruff. Native
classification tests distinguish compatible TPM absence from service failure,
known/unknown TPM versions, S_OK scoped no-join, failing HRESULT, informational
S_FALSE, device/workplace/unknown join type and bounded text loss. They classify
injected native result values, not real joined-tenant/service faults. On the live
development host, TPM query reports version 2.0 (structure version 1); Entra returns
S_FALSE with no information and is degraded/unknown, never failed or proven unjoined.
The actual agent owned-process crash harness passes: 24 fields, exact state/health
recovery, per-field source/error/status and capability states bound to the committed
record, TPM healthy, Entra degraded, ETW unavailable and process visibility blind.
Host-field coverage and health publication share their mutex; independent overall
health components remain non-atomic. API calls remain synchronous without qualified
deadlines. Attestation/readiness/PCRs, all-user/all-tenant identity, joined-service
account/OS/privilege matrices, state deltas, fault injection, Console and full DoD
remain open. See [host state](HOST_STATE.md).

Structured process-execution evidence increment: MSVC x64 build and all 18 native
CTest entries pass (8.22 s), Manager's complete scoped suite passes 213 tests
(18.16 s), Response Engine's suite passes 122 tests (0.23 s), and changed Python
passes Ruff. Contracts fixture validation now explicitly includes valid/invalid
version-2 execution evidence and passes. Actual compiled native serialization for
injected signaled/timeout/failed completion classifications passes the published
schema and authenticated Manager retention with unchanged structured facts. These
fixtures do not perform OS termination or prove live transport; the separate
owned-child test continues to verify real termination. Native tests also prove
that contradictory structured facts refuse serialization and inconsistent internal
state omits conclusive evidence while preserving uncertainty. Python rejects
unknown/coerced/overflowing facts and contradictory outcomes. Manager rejects
process execution evidence for a non-process queued action, preserves exact
evidence immutably, rejects changed same-ID facts and replays a receipt seeded
with the pre-extension canonical digest. A fixture initially tried enrollment
with a new key for every command and correctly failed; it now reuses one enrolled
identity. Full target/provenance, other-action typed facts, mixed-version negotiation,
Console, trusted response HTTPS, action reconciliation and OS/fault/soak remain open.

Typed process-execution increment: MSVC x64 build and all 18 native CTest entries
pass (8.45 s). The actual held-handle test still rejects self, missing/wrong boot
and wrong creation token, then terminates only its owned inert child and verifies
typed succeeded/initiation/observed-completion facts against the signaled object.
Completion classification checks inject WAIT_TIMEOUT, WAIT_FAILED and an unexpected
wait status into the same classifier used after TerminateProcess; all preserve
indeterminate, and only WAIT_FAILED retains its native error. Changing diagnostic
wording does not change outcome. Contradictory success/failure state with unobserved
initiated action cannot become definite success/failure. Serialized version-2
outcomes preserve indeterminate and target refusal becomes rejected. These injected
classification checks do not simulate the OS or qualify actual wait faults/delayed
termination/PPL/critical targets. Named stage/initiation/completion/error facts still
use bounded detail text; structured execution evidence, typed other-action APIs,
deadlines, reconciliation and full operational DoD remain open.

Durable command-inbox increment: all 18 native CTest entries pass (latest 7.68 s), and
Manager's complete scoped suite passes 199 tests (17.25 s). Changed Python passes
Ruff. Schema-3 journal tests cover encrypted immutable commands/outcomes, exact
reopen, compare-and-transition across handles, quota refusal and replay tombstones.
An owned child abruptly exits after queued and executing commits; both states
recover. A production-worker regression rejects expired queued work, reports
interrupted intent as indeterminate, hands both exact outcomes to the outbox,
refuses a competing scope owner and suppresses duplicate terminal delivery.
No OS action or network request executes in that worker fixture. Manager tests
prove durable redelivery and acceptance cutoff alongside legacy poll behavior.
Health now samples inbox state counts and command-channel poll/decode failures.
Leases/fencing, action reconciliation, actual native HTTPS redelivery/result
integration, OS-action crash, disk/reboot/soak, aggregate budgets and Console remain
unqualified. The complete capability matrix and DoD remain open. See
[command inbox](COMMAND_INBOX.md).

The actual native response HTTPS refusal fixture passes using an owned Manager
server and self-signed certificate, with strict response TLS verification enabled
and no trust-store mutation. WinHTTP reports ERROR_WINHTTP_SECURE_FAILURE (12175);
poll failure is visible, Manager retains zero result receipts, and the exact
committed indeterminate outcome remains pending across retry and runtime reopen.
Run Manager's `tools/verify_endpoint_https.py --response-tls-refusal` after building
`officer-response-runtime-tests`. This qualifies that fixture's refusal/retention
path only; successful response delivery over trusted TLS remains open. The shared
telemetry HTTPS fixture also passes after native error-code preservation: six
retained/detected/acknowledged records, zero pending/dead/invalid receipts, and
capture-age acknowledgment healthy. The actual agent host/crash harness passes
with all 24 inventory fields, exact durable state/health recovery and correct
unavailable/blind/degraded/disabled coverage. These checks do not establish reboot,
live sensor or full operational qualification.

A production dispatch regression also supplies a previously successful gate
receipt for an expired process command and verifies expiry refusal before OS action.
The worker rechecks expiry after best-effort network acceptance. Wall-clock rollback,
deadline enforcement throughout OS handlers and signed monotonic leases remain open.

Durable result-outbox increment: 17 native CTest entries pass (8.75 s), Manager's
scoped suite passes 198 tests (19.71 s), and Response Engine passes 101 tests
(0.21 s). Changed Python files pass Ruff. Native regressions verify encrypted
journal reopen/retry with exact result bytes, matching retention acknowledgment,
and missing/legacy/ambiguous receipt refusal. Manager migration 16 retains the
complete correlated version-2 payload immutably, rejects changed same-ID outcomes,
and accepts late indeterminate evidence without rewriting expiry. Result schema 2
is published separately from the legacy schema. These checks do not qualify actual
HTTPS outbox transport, execution-to-result crash recovery, command inbox/leases,
disk failure, scope migration, aggregate resource budgets or Console late-result
display. See [result outbox](RESULT_OUTBOX.md).

An initial native regression failed a temporary-path equality check because of a
Windows trailing separator; resolved directory identity now verifies containment
before cleanup and the full suite passes. One test-owned directory with zero pending
records and one acknowledged result remains retained after execution policy rejected
cleanup. No other checkout or temporary directory was removed.

Canonical response-recommendation increment: Manager's complete scoped suite
passes 196 tests (15.40 s), Response Engine passes 100 tests (0.25 s), and changed
Python files pass Ruff. The real production DET-CRED-001 rule, canonical adapter,
DetectionRun and AlertSink stage a boot-bound native target at analyst approval
tier; no destructive action auto-executes. Authorization preserves schema 2 and
the actual compiled Windows decoder confirms exact scope/token. A changed enrolled
host while pending rejects the recommendation with zero commands. Response unit
regressions cover maximum uint64, digest/boot/actor mismatch, source-scoped and
unresolved refusal without legacy fallback. No endpoint binary changed in this
increment. This does not qualify live capture-to-action transport, Console, leases,
durable outcomes or response crash/reboot behavior. Full DoD remains open.

Boot-bound process-command increment: 17 native CTest entries pass (7.61 s),
Manager's complete scoped suite passes 194 tests (20.02 s), and Response Engine
passes 91 tests (0.25 s). Changed Python files pass Ruff. New checks preserve the
full uint64 maximum as decimal text, refuse malformed/overflowing/native-numeric
tokens and absent/invalid boot, and order bounded UTC fractions exactly. An actual
Manager-authorized stored/polled schema-2 command passes the new published schema
and compiled native decoder with unchanged boot and exact token. This regression
found the previous rejection of real Manager fractional timestamps, now fixed.
The owned-child execution test refuses wrong/missing boot and still proves exact
held-handle termination on the current boot. No Linux source is modified. Automatic
canonical recommendations, Console, capability negotiation, leases/results,
reboot and the OS/protection/fault matrices remain unqualified. See
[process response](PROCESS_RESPONSE.md).

The actual native runtime/crash harness also passes with process-response coverage
`disabled` when unconfigured, ETW `unavailable`, process visibility `blind`, and
host inventory `degraded`; the exact committed 24-field snapshot and health reopen
successfully after test-owned abrupt exit. This does not qualify configured response
fault health or reboot recovery.

Process-response safety increment: 17 native CTest entries pass (8.61 s) after
the MSVC x64 build. A real inert test-owned child rejects a mismatched creation
token without exiting, then is terminated through the retained verified handle
and its exit is observed. Self-target refusal, winlogon basename protection and
raw creation-tick retention pass. Strict command/poll regressions reject duplicate
action/escaped PID/poll keys, unknown poll fields and excessive nesting while
allowing the same field names in separate objects. No system process is targeted.
These checks do not qualify boot-bound targets, critical/PPL/image query failures,
delayed completion, leases, durable results or reboot recovery. Manager's current
poll envelope was inspected and returns exactly `commands`; no Manager contract
change was needed for strict duplicate-key handling. The complete response
contract migration remains open. See [process response](PROCESS_RESPONSE.md).

Native host-state increment: 16 native CTest entries pass (7.73 s), Manager's
scoped suite passes 188 tests (17.33 s), and changed Manager files pass Ruff.
The read-only native collector returns 24 fields with explicit per-query state,
null unavailable values and a non-atomic collection window. One separate current
sample took 78 ms. These values do not establish full inventory/resource or
cross-platform qualification.

The actual non-elevated agent runtime continues with ETW unavailable, process
coverage blind and host coverage degraded. Its test-owned process is terminated
abruptly only after state/health commit; reopening the owned encrypted spool
recovers the exact emitted host snapshot plus health. The harness exits 0 and
cleans its verified temporary directory. Manager validates/projects a real native
snapshot, preserves incomplete/null fields, and exposes current ordering with
unverified observation freshness; Detection adaptation preserves the full domain
without a process actor. See [host state](HOST_STATE.md). TPM/Entra/storage/
virtualization, state deltas/watchers, query deadlines/faults, compatibility,
performance/soak and full state/rule/fleet integration remain open.

Decoded-fact preservation increment: all 15 native CTest entries pass (7.74 s),
Manager's scoped suite passes 187 tests (13.96 s), and changed Manager files pass
Ruff. Updated C++ canonical fixtures pass contract validation and eight standalone
canonical Engine tests. The real WinHTTP HTTPS harness exits 0 with six retained/
detected/acknowledged records, exact decoded native tokens, a real benign fixture
rule alert, and zero pending/dead/invalid receipts or challenge failures.

New native regressions verify actual malformed-hash normalizer refusal; unchanged
original hash despite successful normalization; all five decoded families; exact
uint64/signed timestamp bounds; embedded NUL/empty/false/null distinction;
malformed UTF-8 byte preservation; exact identity despite failed metadata; durable
failure-evidence reopen; separate observed/cached context; and rejection of cache
facts from another provider. Six native failure-evidence artifacts pass Manager
typed/schema validation, authenticated ingest/replay, exact fact retention and
the actual Detection worker without guessing unresolved actors. These fixtures
do not qualify live collector fault paths, original native bytes, allocation or
large-record capture, disk exhaustion, stage recovery or enlarged-payload resource
budgets. See [source facts](SOURCE_FACTS.md).

Source-supervision increment: 14 native CTest entries pass (6.97 s); Manager's
complete scoped suite passes 185 tests (15.24 s), and changed Manager tests pass
Ruff. New native regressions cover unknown startup history, separate event/buffer
units, counter decrease/reset ambiguity, unavailable-query intervals, stopped
consumers, subscription/decode/sink counters, unchanged sample deduplication and
canonical gap provenance. The native gap producer passes Manager typed/schema
validation, authenticated retention/duplicate replay and vendored Detection
transformation with null process identity and unchanged loss facts. This does not
qualify source faults, timing, complete pipeline accounting or crash-safe pending
gaps. Live ETW and Sysmon probes both returned Access denied in the current
non-elevated process (exit 2); successful source-statistics queries and fault
injection remain unqualified. See [source supervision](SOURCE_SUPERVISION.md).

Capture-freshness increment: 13 native CTest entries pass (7.49 s).
Manager's complete `tests` directory passes 184 tests (16.06 s); Detection
Engine's standalone suite passes 187 tests with two existing optional
`OFFICER_AGENT_BIN` artifact-stream skips
(6.56 s). Changed Python files pass Ruff. Contract fixture validation passes,
including C++-produced identity digests. Native boot query
probe reports available and consistent on this host. Real WinHTTP HTTPS fixture
integration passed: six Manager records, six Detection dispositions, a real
benign fixture rule alert preserving exact creation ticks, six durable acknowledgments, zero
pending/dead-letter records and zero invalid receipts, with latest health/state
readback. Run `panopticon-manager/tools/verify_endpoint_https.py` using Manager's
Python environment after building `officer-endpoint-tests`; it uses only owned
temporary DB/spool/certificate/credentials and never installs certificates.

Bare `pytest -q` from Manager also collected vendored engine tests and failed due
to competing `tests` packages. The repository-scoped invocation is
`python -m pytest tests -q`; this is the verified Manager suite.
Live-sensor/system qualification, full domain rules/state, graph persistence,
response/Console and operational qualification remain open. Canonical Detection
regressions prove same-timestamp PID reuse and cross-boot separation,
activity-before-creation, unresolved parent/activity isolation, exact token/raw
provenance preservation, UTC independence and pruning, agent-scoped SHA-256
alert replay, mixed-protocol claim fairness, poison isolation, stale recovery,
composite agent/record disposition and migration-12 evidence backfill without
rewriting retained records. Tests do not prove full host graph durability.

Generation allocation additionally survives reopen, separate journal handles and
abrupt child-process termination. Manager regressions cover wall-clock rollback,
old offline replay, sequence reordering, old-domain invalidation, generation/epoch
fork rollback, installation replacement history and legacy unordered records.
The real HTTPS harness verifies current ordering plus unverified observation
freshness, preventing a receipt from being presented as live health. Updated
schema/C++ fixtures pass contract validation and all eight canonical engine tests.

Eight capture-age regressions additionally cover fresh-to-stale aging, old offline
capture, one-use nonce and duplicate replay, challenge expiry, Manager process
restart, boot/installation/generation/epoch mismatch, future uptime, unsupported
elapsed clocks, malformed/duplicate context keys and uint64/pairing bounds. The
native HTTPS harness exits successfully with capture-age acknowledgment healthy,
zero challenge failures, six accepted/detected records, and fresh capture plus
unverified observation metadata. One earlier successful functional run failed
temporary cleanup on a transient Windows file lock; the harness now retries only
its resolved verified owned directory. The leftover owned files were removed and
the complete harness rerun passed. No live-sensor, suspend/reboot/VM or fleet
freshness qualification claim.

Latest run after transactional retention/state counter additions: all 12 tests
pass in 7.18 s; the same 1,000-event benchmark measured 1,529 events/s,
median commit 0.552 ms, p95 0.738 ms, max 3.442 ms, and 3,356,896 journal
file bytes. Both short runs remain below sustained throughput qualification.

2026-10-06: Windows x64 development host, MSVC 19.44 toolset/Windows SDK, `build-verify-x64`. Native CMake build and 12 CTest entries pass. Includes new journal tests and existing core/collector/delivery/segment-spool/response/keypair/query tests. These are component/fixture tests, not full endpoint or live Manager qualification.

New regression coverage proves byte-exact journal reopen, encrypted DB/WAL bodies, encrypted retained rejection inspection, acknowledgment validation and atomic disposition, duplicate receipt accounting, quota refusal without eviction, immutable/idempotent legacy import with torn-tail gaps, acceptance refusal after stop, HTTPS-only transport, and recovery after a child test process terminates itself without destructors or orderly database close. GUID/PID disagreement and PID reuse cannot transfer cached image/user context. Runtime coverage snapshot includes all 40 approved domains and supports a distinct blind state.

Reproduce from an MSVC developer shell:

```powershell
cmake --build build-verify-x64
ctest --test-dir build-verify-x64 --output-on-failure
build-verify-x64\officer-journal-tests.exe --benchmark
```

First short commit benchmark, before transactional health-counter additions: 1,000 unique observations, 1,008,890 plaintext bytes, one producer, user-scoped DPAPI per observation, FULL/WAL SQLite commit. Elapsed 0.603 s; 1,659 events/s; median commit 0.511 ms; p95 0.641 ms; max 2.076 ms; journal files 3,348,656 bytes. This sub-second development run does not establish sustained throughput, CPU/RSS, callback safety, ingestion latency or storm/offline budgets. It falls below the proposed 2,000 events/s sustained workload target and supports further encryption/commit batching and collector isolation work. Benchmark artifacts are isolated under a test-owned temporary directory and removed after the run.

Open qualification gates: exact canonical process instances and source relationships, new contracts/Manager/Detection/Response/Console E2E, source loss/bookmarks, current host state, real forensics, response leases/outcomes, IPv6 isolation/recovery, service/installer/update, signed drivers where justified, OS/security configuration matrix, attack simulations, disk-full/corruption/reboot/power-loss, 24-hour offline, sustained/burst resource budgets and 7-day soak. No completion claim.
