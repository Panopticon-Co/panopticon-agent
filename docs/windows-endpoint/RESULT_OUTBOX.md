# Durable response result outbox

This increment protects completed serialized outcomes after local commit. It is
not a qualified command lifecycle. The live durable inbox now provides committed
intent and conservative recovery; see [command inbox](COMMAND_INBOX.md).

The Windows response runtime uses a separate DurableJournal below
`<spool>/response-results/<SHA256 of length-prefixed agent and host identifiers>`.
Result bodies and their scope wrapper use the existing user-scoped DPAPI,
protected-directory ACL and FULL/WAL commit. No telemetry uploader reads this
journal. The runtime commits before submitting the outcome and drains up to 32
pending results before each poll, including when polling fails. Restart opens the
same scoped outbox and retransmits the exact committed payload. Re-enrollment to
a different agent/host selects a different directory; migration/recovery of old
scopes is an explicit remaining requirement, not a cross-host replay.

Result schema 2 includes mandatory command correlation and one of `succeeded`,
`failed`, `rejected`, or `indeterminate`. Indeterminate means the action may have
occurred but completion cannot be proven. A process termination whose bounded wait
did not observe exit now reports it. The native process API returns typed state,
stage, initiation/completion facts and optional Win32 error; the live worker maps
that state directly without diagnostic-string matching. Inconsistent success or
definite failure claims with unobserved initiated actions become indeterminate.
The result envelope now retains stage/facts/error in optional closed `execution`
evidence as well as detail text. Serialization validates consistency, and Manager
binds this representation to KILL_PROCESS and retains it immutably. Recovery with
unknown execution facts omits the object instead of inventing them. Existing results
without evidence retain their old digest; explicit null/contradictory/coerced evidence
refuses. Typed outcomes for other handlers, complete target provenance, mixed-version
negotiation and Console consumption remain open. Result IDs are `result_` plus the SHA-256 of command ID,
which stays bounded even for the longest accepted command identifier.

HTTP 200 alone is insufficient. The native client requires an unambiguous exact
three-field object with matching `result_id`, Boolean `accepted:true`, and Boolean
`retained:true`. Missing, duplicate, malformed, mismatched or legacy acknowledgments
retain the local outcome. Non-acknowledged outcomes have no retry-count expiry.
Manager migration 16 stores complete canonicalized result payloads with immutable
agent/command/result identity and SHA-256 before returning that receipt. Reusing
the result ID with another payload returns 409. Authenticated correlated version-2
outcomes can be retained after command expiry; expiry or earlier terminal lifecycle
is not overwritten by late/different evidence. Version-1 behavior is preserved.

If inbox outcome commit fails after action, one serialized result remains in memory
and the response loop refuses further execution until its inbox commit retry succeeds.
That memory is not crash durable; committed execution intent survives and recovery
reports indeterminate if no outcome was committed. Startup inbox/outbox failure disables response and exposes
unavailable coverage while telemetry/inventory continue. Health includes sampled
durable pending count and commit/receipt failure counters; its response state
remains degraded. Counters reset on restart and no complete failure accounting or
live backlog delivery claim is made. Replay tombstones suppress repeated execution;
the inbox preserves committed outcomes and conservative recovery of interrupted intent.

The coordinated durable poll now redelivers before acceptance, and the inbox
preserves intent/outcome. Its recovery reports indeterminate without repeating
interrupted OS actions. Open P0 gaps include action-specific reconciliation,
leases/fencing/cancellation and mixed-version rollout. Full native HTTPS
result-outbox/redelivery integration and abrupt OS-action crash/disk
fault/soak qualification remain open. The separate outbox has the journal's default
16-GiB plaintext retention ceiling, not a shared physical-disk reserve or fleet
policy. Permanent rejection, corrupt-head isolation, aggregate budgets, fair
scheduling, account/scope migration and Console late-result display remain open.

The strict native response TLS refusal fixture now passes: an owned self-signed
Manager certificate produces WinHTTP secure failure 12175, zero Manager result
receipts and exact retained local outcome across retries/reopen. No certificate is
installed or verification bypassed. Successful response transport over trusted TLS
is still unqualified. Native send/receive diagnostics preserve the Windows error code.

Native regression verifies reopen with exact result bytes, retention after a
retryable sender, matching receipt validation and ambiguous/legacy receipt refusal.
Manager regressions verify immutable collisions, duplicate retention and a late
indeterminate outcome without rewriting expiry. These are component/integration
checks and do not qualify all response behavior.
