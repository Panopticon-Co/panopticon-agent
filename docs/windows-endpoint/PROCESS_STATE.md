# Native process inventory

After attempting event subscriptions, the runtime starts an independent process
inventory worker. It commits a canonical `process_inventory_begin`, then streams
`process_inventory_page` records from one pinned Toolhelp process-list snapshot.
Each page retries stable serialized bytes and its record identity until journal
acceptance before collection advances. A final `process_inventory` manifest lists
the exact ordered committed page IDs and uses the begin record ID as capture ID.
Refresh occurs five minutes after manifest acceptance. Health exposes capture ID,
committed page count, collection progress and pending acceptance; query summaries
bind to the last committed manifest. A crash can leave a durable begin and pages
without a manifest. Restart reconciliation, pending RAM state and API deadlines
remain unqualified; no unfinished capture is promoted to a complete census.

[Toolhelp](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
provides snapshot descriptors: PID, reported parent PID, thread count, base priority
and image basename. Later OpenProcess calls can open a replacement after PID reuse.
Descriptors therefore remain separate from `later_pid_query`, with their instance
relation explicitly unverified. Reported parent PID never becomes a parent entity;
Microsoft documents [parent PID reuse](https://devblogs.microsoft.com/oldnewthing/20150403-00/?p=44313).

Each successful PID query retains one PROCESS_QUERY_LIMITED_INFORMATION handle
across GetProcessId, [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[QueryFullProcessImageNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)
and the security queries below.
Only these held-object facts share identity. Full creation ticks use the existing
host/boot/PID/token entity formula; absent boot/token means unresolved/unscoped with
no guessed entity. All 64-bit timing values remain decimal strings. Exit time is
not interpreted because it is undefined for a live process; liveness is unverified.
Image is a queried path, not a verified file identity/signature. Invalid UTF-16 text
retains its original bytes as UTF-16LE hex. Queries request no terminate, VM-read or
debug rights, and do not change policy or privilege state.

[IsProcessCritical](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocesscritical)
returns a critical-process Boolean only on query success. On failure the fact is
null with the immediately captured Win32 error. The held process also supplies
[GetProcessInformation/ProcessProtectionLevelInfo](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessinformation).
Its full-width raw level remains a decimal string with a documented symbol when
known. Zero is WINTCB_LIGHT, never an unprotected default; only NONE maps to
`not_protected`. Unknown values and the documented unimplemented WINTCB,
CODEGEN_LIGHT and AUTHENTICODE levels remain degraded and uninterpreted.
[Documented protection levels](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_protection_level_information)
do not establish internal signer/type bits, file signing or the agent's own
PPL/ELAM readiness. Fields are non-atomic same-object observations, not proof
that security context remained unchanged throughout collection or afterward.

The manifest's `security_query_summary` and last committed query health preserve
successful/failed queries, uninterpreted protection results and process queries
not attempted because OpenProcess/GetProcessId could not establish a held
object. Any unattempted descriptors make aggregate security state degraded
when some results exist; no successful result means unavailable. Counts cover
queried/assembled rows, including rows omitted after a bound/refused delivery;
they are not retained membership, lost events or full host coverage. Individual
successful facts remain healthy for their scoped query. Paged state version 1.4
also includes selected primary-token context and architecture; the single-prefix
compatibility API uses version 1.3. See [primary token scope and bounds](PROCESS_TOKEN.md).

[IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)
queries the same retained process handle, preserving process/native host machine
codes as exact decimal WORD strings with recognized SDK symbols. A zero process
code is the API's not-WOW64 sentinel, not an inferred x86 architecture. Unknown
codes, including an unknown native host, remain raw and degraded. WOW64 follows
the API's zero/nonzero process-code contract. No image/module ABI or ARM64EC
hybrid semantics are inferred from these reports. Recognition of a machine code
does not establish platform support or successful ARM64 execution qualification.

The native entrypoint is resolved from the loaded Kernel32 module once per capture;
lookup failures are retried next capture. Missing entrypoint with Win32
ERROR_PROC_NOT_FOUND means this query is unsupported, with null value and explicit
reason. Other lookup/call failures are unavailable with the exact captured Win32
status. The rest of process collection continues. There is no image-name,
collector-bitness or coarse Boolean fallback promoted to exact machine codes.
Manifest-bound health separates successful, failed, unsupported and uninterpreted
architecture reports; process queries not attempted still make aggregate coverage
partial. These are report/refusal counts, not literal native call or lost-event
counts. API absence/fault injection, x86/ARM64/ARM64EC live execution, protected/
exit races, query deadlines and OS/resource qualification remain open.

Enumeration and individual query errors retain exact native error/source facts.
Runtime pages have at most 2,048 descriptors and 512 KiB encoded entries, with
65,536 total entries and 4,096 pages per capture. A row that crosses a page byte
boundary retains its already queried facts on the next page. An oversized single
row, total/page cap, consumer refusal or enumeration failure stops explicitly
with incomplete enumeration and an unknown remaining set. Entries delivered
count accepted pages only; produced pages can include a refused attempt. Child
query failures and exact query references are query/assembly facts, including
queries whose rows were not delivered, rather than retained membership or lost
event counts. The old single-prefix API remains for compatibility tests. All
snapshots say inventory_complete=false and non_atomic. Protected/exited process
queries may fail while descriptors survive. Holding the snapshot during durable
retry does not make later queries contemporaneous with its descriptors.

Manager retains each immutable record and offers authenticated manifest verification
and individual page retrieval, checking full endpoint, collector epoch/generation,
capture ID, page index, begin record and entry count. Missing or mismatched records
cannot produce complete assembly. The aggregate scan is capped at 64 MiB; budget
refusal does not remove records or prevent page retrieval. Assembly proof and
endpoint-reported enumeration are distinct from native coverage and lifecycle
proof. A derived Manager capture index discovers begins and retained page claims
before a manifest arrives, with bounded metadata pagination and original-record
readback. Missing manifests stay unverified; they do not prove a crash or lost
events. Resumable verification, endpoint incomplete-capture reconciliation, total
memory/disk budgets, signed configuration, query deadlines and large-host qualification remain
required. See [Manager page API](../../../panopticon-manager/docs/PROCESS_SNAPSHOTS.md).

Host/process inventory continues when event subscriptions fail. This is a snapshot
capability, not event continuity: process event coverage remains blind without an
active sensor. Full token/group/privilege contents, thread impersonation/effective
access, full architecture/ABI qualification, signatures/full protection semantics,
modules/handles/threads,
verified ancestry, creator/requested-parent distinction, exits/deltas and persistent
lifecycle remain open. Runtime scope stays degraded; no domain is complete.

Native tests compare the owned test process's full creation token and canonical
entity formula, reject absent-boot alias promotion, and exercise count/byte limits,
multi-page continuity, total/page caps and consumer refusal. The compiled paged
producer passes authenticated immutable ingestion, missing-page/reordering/scope,
token isolation and verification-budget checks. Existing single-snapshot tests
validate the published schema and unchanged Detection payload without making a
state snapshot a process actor. The owned-process crash harness verifies every
committed page, manifest and record-bound health exactly. These checks do not
simulate genuine PID reuse, protected-process/exit races or prove elevated/service/
OS compatibility, large-host resource bounds or storm/soak behavior.

Owned-process security values are compared against actual native queries.
Classifier checks cover the zero/NONE distinction, full-width unknown values
and documented unimplemented levels. Larger rows exposed the old single-prefix
test's assumption that its owned process must fit; ownership checks now stream
paged enumeration without changing the prefix byte limit or completeness flags.
Critical-process/PPL creation, genuine protected-target access and native API
fault/exit races, context changes and OS/privilege compatibility remain unqualified.
