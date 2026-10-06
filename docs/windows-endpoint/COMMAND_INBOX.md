# Durable command inbox and conservative recovery

The live response worker now admits each parsed command's canonicalized wire JSON
to an identity-scoped encrypted inbox before OS execution. Journal schema 3 adds
immutable command bodies, scope/digest, state and encrypted result. This is not a
complete leased command protocol or full action reconciliation.

States are `received`, `executing`, `result_ready`, and `outboxed`. Admission,
execution intent, outcome and outbox handoff commit separately with FULL/WAL.
Only one transaction can change a given received row to executing. The runtime
holds a native exclusive file handle for its response scope; a second live worker
cannot act in that same scope. File existence alone is never treated as ownership.
Bodies and results use DPAPI with scope/key entropy. Same-key changed scope/body
or changed committed result refuses without replacing evidence. Final rows remain
replay tombstones. Admission is bounded to 65,536 retained commands and the journal
plaintext quota; overflow refuses instead of eviction. Typed policies and rotation
of tombstones remain open. Command canonicalization is not original HTTP bytes or
a command signature.

The worker processes retained work before polling. A received command commits
intent before gate/action. Expired or mismatched commands reject. Expiry is checked
again immediately before OS action dispatch, because best-effort acceptance can
consume the remaining lifetime. This is a whole-second wall-clock check, not a
signed lease or deadline enforcement throughout a multi-stage OS handler. A recovered
executing row never repeats the OS action: it reports `indeterminate`. A retained
legacy acceptance marker also prevents repeating an unproven old action. The flat
legacy ledger is loaded only as a migration guard; new execution does not append
to it. Committed outcomes copy to the durable result outbox, then inbox handoff
commits. Crashing between those commits may copy identical bytes again; the outbox
deduplicates pending copies and Manager's immutable result ID handles retries.

If outcome commit fails while the worker is alive, its in-memory exact result
retries into the inbox before recovery processing. A crash loses that memory but
preserves execution intent, so subsequent recovery reports uncertainty rather
than guessing success or repeating an action. Result serialization or action
exceptions similarly leave an intent for conservative recovery. `outboxed` means
durable local handoff, not a remote acknowledgment or full action qualification.

Native polling opts into `delivery_mode=durable`. Manager redelivers authorized or
dispatched commands until acceptance, terminal outcome or expiry. Delivery marks
the first dispatch time without changing legacy default one-shot behavior. Native
acceptance happens only after inbox/intent commit. This closes loss before local
receipt for the coordinated mode; there is no lease token, fencing, cancellation
or bounded distributed ownership yet. Mixed-version rollout and actual native
successful trusted HTTPS/redelivery fault tests remain open. The owned self-signed
HTTPS fixture proves strict native certificate refusal (WinHTTP error 12175), visible
poll failure and exact outbox retention across retries/reopen without trust-store
changes. It does not qualify successful response transport.

Health reports exact stored state counts, retained plaintext bytes, poll/decode
failures and last valid poll uptime. Missing initial valid polling is unavailable;
a failed poll/decode after prior valid polling marks the command channel blind.
Successful sampling remains degraded with explicit lease/freshness qualification
limits. Inbox query failure is unavailable and unknown stored states are blind.
Health is sampled and non-atomic across these components; failure counters reset
on restart. Per-stage admission/commit/transport loss accounting, hung action/poll
watchdogs and immediate fault notification remain open.

Native tests exercise immutable admission/outcomes, encrypted DB/WAL, shared
handle compare-and-transition, quota refusal and exact reopen. An owned child
terminates abruptly after queued and executing commits; reopen distinguishes both.
The production response worker test reopens those kinds of states, rejects an
expired queued process command, converts interrupted intent to indeterminate,
verifies both outcomes in the outbox, refuses a competing live owner and suppresses
duplicate terminal delivery. It runs no collectors, network polling or destructive
OS actions. Manager tests prove repeat polls and acceptance cutoff. Full OS-action
crash, signing, disk/reboot, service/account/scope migration, corrupt-head isolation,
fairness, Console and fleet qualification remain open. Separate inbox/outbox
journals use independent default 16-GiB plaintext quotas, not an aggregate physical
disk budget or emergency reserve.
