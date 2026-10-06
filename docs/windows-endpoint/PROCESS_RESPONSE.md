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
