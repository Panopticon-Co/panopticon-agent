# Process response verification

This is a partial P0 safety implementation, not response qualification. Windows
schema-2 process commands name enrolled host, native boot digest, PID and exact
creation ticks. Ticks use canonical positive uint64 decimal strings, including
the full uint64 range; PID is a positive uint32. Manager preserves schema 2 and
scope during authenticated dispatch. Windows process handlers requery current
native boot before opening the target and refuse missing/mismatched/unavailable
boot. Legacy schema-1 process targets are refused by both Windows process actions;
other legacy actions and the Linux contract remain in place. No boot scope is
invented for old commands or inferred by Manager from latest host state.

Both command versions accept UTC timestamps with optional 1-9 fractional digits.
Creation/expiry ordering retains nanosecond precision within a second. The existing
expiry gate still uses whole seconds conservatively and can refuse less than one
second early. Dispatch checks expiry again after the acceptance request; an earlier
gate success cannot authorize an already expired action. This does not enforce a
deadline throughout target verification/action or supply a monotonic signed lease.
Manager canonicalizes schema-2 expiry to UTC without losing fractions;
naive schema-2 expiry is invalid. The real dispatch/decoder regression exposed
and fixed the prior rejection of Manager-produced microsecond timestamps.
Committed inbox intent and durable result handoff are implemented; leases and
action-specific crash reconciliation remain required.

Termination opens one process handle with query, terminate and synchronize rights.
The handle remains open through verification, action and completion observation;
there is no PID-based reopen between verification and action. Full native creation
ticks must match. Unknown image, failed critical/protection query, Windows critical
status, any protection level other than `PROTECTION_LEVEL_NONE`, the endpoint
itself, PID 0/4 and guarded system basenames all refuse termination. The basename
list includes winlogon and is only an additional guard, not an exhaustive Windows
critical-process policy.

The held object must still be alive before execution. A successful
`TerminateProcess` call is followed by a five-second wait on that same handle.
Success is returned only when exit is observed. The native API now returns typed
refused/failed/succeeded/indeterminate state, named action stage, initiation and
completion facts, and optional native error. Refusal means no OS action was initiated;
API failures before initiation remain failed with explicit stage. Timeout, wait
failure and unexpected wait status after initiation are indeterminate. Win32 errors
are captured immediately; timeout never inherits stale GetLastError. Receipt mapping
uses typed facts, never summary keywords, and refuses contradictory success/definite
failure claims when initiated action completion was not observed. Named stage,
initiation/completion facts and uint32/null native error now survive in a closed
version-2 `execution` object. Manager validates consistency and queued KILL_PROCESS
binding before immutable retention. Unknown recovery facts omit the object;
contradictory internal facts preserve uncertainty and omit conclusive evidence.
Full target provenance, mixed-version negotiation and Console interpretation remain open.
The legacy result
contract now reports version-2 `indeterminate` and commits serialized outcomes to
an encrypted outbox before delivery. The durable inbox conservatively recovers
interrupted intent as indeterminate without repeating the action; actual OS-action
crash qualification and reconciliation remain open. See [command inbox](COMMAND_INBOX.md)
and [result outbox](RESULT_OUTBOX.md). Protection state can change after its query; this is not an atomic
policy guarantee. Missing native query APIs refuse execution rather than bypass
verification. Cross-platform availability remains unqualified.

Read-only process reobservation now retains exact native creation ticks in its raw
record. Toolhelp parent PID remains an unverified snapshot hint, not an exact parent
instance. Existing response evidence still uses the legacy envelope and requires
canonical evidence/provenance migration.

Command and poll JSON reject duplicate object keys before DOM replacement,
including escaped equivalent names and nested command target keys. Nesting is
bounded to 32 and the poll envelope accepts only `commands`. Repeated keys in
different objects are valid; duplicate command execution is a separate replay
concern. These checks do not supply command signatures or leases.

The native process-action regression creates one inert copy of its own executable
with no window, observes its exact creation token, refuses a mismatched token,
confirms it remains alive, then terminates that owned process and observes exit.
Wrong/missing boot, self-target refusal and raw tick preservation are also checked. Cleanup uses only
the handle obtained from the test's own CreateProcess call. No system process is
targeted. Schema-2 dispatch is also verified against the published schema and
the actual compiled Windows decoder using Manager's authorized stored/polled wire
payload with the maximum uint64 token. Parsing proves preservation, not execution
against a process with that artificial token. Canonical Detection recommendations
now reach schema-2 targets through Response Engine: exact subject digest and
recommendation PID/ticks must agree. Source-scoped, unresolved, contradictory or
invalid context refuses mapping without legacy fallback. Manager checks enrolled
agent/host when staging and rechecks the retained alert/target and enrollment at
authorization. A changed host binding rejects pending recommendations. Legacy
recommendations remain version 1 and Windows refuses unscoped process actions.
Console and full live response
integration remain open. Component tests do not qualify critical/PPL targets, access-denied/image
faults, delayed termination, reboot or command lifecycle recovery.

Windows API contracts: [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess),
[IsProcessCritical](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocesscritical),
[GetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessinformation)
and [protection-level values](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_protection_level_information).

## Bounded file hash evidence

`COLLECT_FILE` now hashes bytes read from a held Windows file handle rather
than reopening a canonicalized pathname through the C++ stream library. The
configured root and target are opened with reparse-point inspection; the root
must be a directory, the target must be a regular non-reparse file, and the
target handle's normalized final path must remain below the held root handle's
final path. The target handle allows readers but not new writers or deleters.
The handler reads at most 16 MiB in bounded chunks, checks for unexpected extra
bytes, then compares volume/file identity, size, last-write time and normalized
path on that same handle. A mismatch or unsupported identity query fails
closed. Raw content is cleared from bounded process buffers on success or error;
only the handle-resolved path, size and SHA-256 enter the response evidence.

This closes the prior path-reopen race for collection and rejects target/root
reparse points. Existing writable handles can still modify the file; before-and-after
identity and metadata checks detect common changes but do not provide a
filesystem snapshot or prove content stability against a writer that changes
bytes and restores metadata. This source change is not built or exercised on
Windows yet.

## Quarantine movement and partial outcomes

`QUARANTINE_FILE` now holds the source handle with read, delete and security
rights while refusing new write/delete opens. It verifies a stable volume/file
identity, a non-reparse regular file, and the held final path beneath the held
collection-root handle. The destination must be an accessible non-reparse
directory on the same volume; cross-volume copy/delete fallback is refused.
The handler applies a protected DACL to the source handle before moving it:
Everyone is denied write, execute, delete and security-descriptor changes,
while the source owner and SYSTEM retain read access. A handle-relative
`FileRenameInfo` operation moves it atomically with replacement disabled, so
an existing destination is never overwritten.

Before source mutation, a unique metadata staging file recording the original
path and stable file identity is created with `CREATE_NEW`, protected, written
and flushed. It is an intent record, not proof that the move completed. After
the source rename, that file is atomically renamed to its final metadata name
without replacement; the durable command result records completion.
The optional `QuarantineOutcome` reports `refused`, `failed`, `partial` or
`completed` and explicit source-security, source-removal, destination-protection
and metadata-flush facts. If protection succeeds but source rename fails, the
source remains at its original path with the restrictive DACL and the typed
state is `partial`. If the source moved but metadata promotion fails, the
source is in quarantine and the pending metadata file remains; the state is
also `partial`. The response dispatcher must translate either partial state
to `indeterminate`, never success or a claim of no action. Successful
serialized results are prepared before mutation and emitted only after both
the source rename and metadata rename succeed.

Metadata file contents are flushed before rename, but Windows directory-entry
power-loss durability is not proved here. The durable command inbox/outbox
records its result after the handler; a crash before that commit must recover
conservatively as indeterminate. The configured quarantine parent directory
is not itself made tamper-proof, so privileged or parent-directory access can
still remove/replace artifacts. The DACL does not revoke access already held
through an open handle or an existing image mapping. ACL changes can also be
reverted by an administrator or kernel-level actor. This implementation has not been built,
tested or exercised on Windows, and response dispatcher integration plus
runtime crash/ACL/volume/permission validation remain pending.
