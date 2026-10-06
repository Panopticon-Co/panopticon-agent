# Durable state capture freshness

Each of the eleven periodic state workers records its capture start before native
queries or begin/page journal writes. After durable manifest/snapshot acceptance,
it binds that start and a separate commit uptime to the last committed record ID.
A new collection start never replaces the previous committed capture's start.
Pending journal retries retain the same capture; accepting it late cannot refresh
the observation time. Health retains the original committed native query status.

Health emission evaluates a copied snapshot with GetTickCount64 in this runtime
uptime domain. Every state source reports capture and commit ages, last committed
record ID, evaluation uptime, nominal five-minute interval and one-minute
scheduling tolerance. Age above 360,000 ms is blind; the exact boundary remains
within the configured limit. Missing records or invalid/missing/out-of-order
unsigned decimal timestamps make age unavailable with a separate reason. No
wall clock subtraction, negative-age clamping or cross-boot join is used. See
[GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64).

Healthy freshness only means a durably accepted capture began within the age
limit. It does not make its query quality healthy, attest a complete/atomic
inventory, prove event continuity or establish Manager receipt freshness.
Overdue healthy/degraded state and matching coverage become blind; unknown age
makes them unavailable. Original reported state/reason and committed query
evidence remain available. Disabled, unsupported, unavailable and already-blind
states are preserved, with independent freshness evidence. A new accepted capture
can restore age eligibility on the next copied health snapshot; it cannot erase
an independent native query failure.

Mappings cover host and its selected field/posture/identity capabilities,
process inventory, services/configuration/security, loaded drivers, socket tables,
routes and later interface lookups, independent IP interfaces, firewall profiles/
exclusions, rule inventory, Security Center category reports and independent Defender WMI status. Security-product domain coverage combines fresh partial reports from either source without claiming full protection; each source retains its own freshness and refusal evidence. Firewall domain coverage depends on both profile
and rule capture ages. Process event-source coverage is independent of process
inventory freshness. A stalled new capture or manifest commit cannot extend the
previous capture's age. No native operation is cancelled by this policy.

The unit clock cases exercise the exact deadline, all eleven source mappings,
stalled-next-capture metadata, late commit, missing/overflow/noncanonical values,
clock rollback/order, preserved disabled/unsupported states, unchanged committed
query evidence, unaffected event coverage and recovery after a new capture.
Canonical native fixtures check contract/Manager/Detection retention, and the
owned runtime checks fresh record-bound ages across all ten sources and recovery
of their durable health. A live six-minute collector-stall experiment, suspend/
resume/reboot matrix, per-capability policy configuration, shorter native call
deadlines, field-specific ages within long captures, transition intent/loss
durability, guaranteed immediate delivery, Console presentation and full resource/
soak qualification remain open. Whole-agent/health-emitter failure still requires
remote heartbeat freshness; endpoint self-report cannot prove its own liveness
while the process or health emitter is stopped.

The health emitter also keeps a single-owner transition history. Each source's
observed eligibility state/reason and observation time advance on every sampled
health report, even while the oldest report awaits journal acceptance. Initial
samples report unknown prior history; state/reason changes retain previous/current
freshness, record anchors and per-source sample times. Repeated healthy snapshots
do not produce a transition solely because their record ID or age changes.
Native lost-event counts and ranges stay null: a coverage transition cannot
establish how many native events were missed or the exact outage onset.

History defaults to 128 reports/256 KiB of encoded gap data. The front canonical
gap retries identical record identity/bytes; only durable acceptance removes it.
Each health emission attempts one queued gap, independently of diagnostic output,
then exposes queued/accepted/commit-refused and omitted-report counts. Count/byte
overflow preserves an ordered omission summary after retained reports, with
first/last omitted sample times. Omitted units are transition reports, never
native events. Observed baselines, queued history and pending canonical bytes
remain volatile until journal acceptance; bounds exclude JSON/allocator/baseline/
canonical memory and counters reset on restart. Crash-safe fault intent, emergency
storage reserve, guaranteed transition delivery during health-emitter blockage,
exact provider loss reconciliation and broader native storage fault qualification
remain open. The durable journal and immutable readback retain accepted gaps as
independent historical evidence after a current snapshot recovers.

An owned native journal regression sets its payload quota one byte below the
initial canonical gap, verifies rejection with zero retained records, and samples
blind/recovered eligibility while that front remains pending. After closing that
journal, a reopen with sufficient quota accepts the identical canonical bytes,
then accepts the queued outage and recovery in order. A second reopen verifies
all three original bodies exactly. The returned fixture uses those decrypted
retained bodies for schema/Manager/readback/Detection validation. This qualifies
this controlled payload-quota refusal/reopen path, not actual full-disk, DPAPI,
corruption, abrupt pre-commit loss or emergency-reserve behavior.
