# Durable local process lifecycle history

Current schema is 6: [process graph](PROCESS_GRAPH.md) adds an atomic derived
identity/parent index and bounded ancestry/rebuild APIs over these originals.
The schema-5 evidence below records the archive introduction. Schema-5 binaries
cannot open current journals. Derived graph evidence remains partial and does
not turn archive retention into complete source coverage or verified creation.

Journal schema 5 retains the exact encrypted originals of canonical-tagged process
birth (`category=process`, `data.event.type=start`) and stop observations in a
separate local archive. The archive and delivery observation commit in the same
FULL/WAL transaction. A checkpointed append also commits its source cursor in
that transaction. Quota, encryption, physical-admission or cursor refusal rolls
all of these back together. Delivery acknowledgment and retained rejection do
not delete archived lifecycle evidence. Identical body retries do not duplicate
archive rows, including retries after acknowledgment.

This is evidence retention, not a trusted graph projection or a new envelope
validator. Exact bodies preserve endpoint/boot/source identity, native tokens,
GUID scope, unresolved references, clocks and parent claims. The archive does
not join different identities by PID, resolve a parent using a current PID, turn
a stop into birth evidence, or invent ancestry/continuity. Network/image/file
process context and inventory descriptors are not archived as lifecycle events.
Consumers must validate retained claims before deriving graph relationships.

`inspect_process_history` returns bounded pages in archive-local order (maximum
1,000 records/8 MiB). Its cursor is neither source sequence nor event-time order.
An oversized first record is explicitly refused rather than skipped. Inspection
does not retire records. `officer-host-inventory-tests --read-process-history-lines`
streams all originals from an existing stopped owned journal; normal journal
opening can perform a schema migration. Separate pages are not an atomic snapshot
of an active writer.

Archived logical bytes are charged to the same retention quota as pending/dead
observations, commands and source checkpoints. A newly archived lifecycle record
initially charges two copies; delivery retirement leaves the archive charge.
Both copies use user-scoped DPAPI. Durable archive count/bytes appear separately
in journal health with explicitly degraded scope. Physical admission remains a
sampled estimate, not a reservation or hard physical disk budget.

Schema 4 migration adds the archive transactionally without pretending to recover
previously retired evidence. Pre-upgrade pending originals are preserved; an
identical append retry can archive them without duplicating delivery. There is
no automatic retrospective backfill. Schema-4 binaries cannot open schema-5
state: use the current staged package with upgraded journals. Runtime-account
migration still requires explicit DPAPI-compatible export/migration.

## Evidence and open work

Fresh Debug/Release builds pass all 37 CTest entries (23.06/18.44 seconds).
Journal regressions verify retirement/reopen, byte-exact encrypted originals,
duplicate retries, page bounds, shared quota accounting, checkpoint rollback,
actual schema-4 layout migration and actual abrupt child-process termination
after lifecycle acknowledgment. The lifecycle contents in these regressions are
fixtures; they are not live kernel notification evidence.

An owned 20-second Release host runtime recovers 13,762 unchanged originals
after abrupt exit. They pass endpoint Schema 1.0 and Manager native-data
preservation. Twenty-five durable health records report zero archived lifecycle
records with degraded archive scope, and archive readback is empty. ETW remains
access-denied on this host. Evidence:
`demo-run/history-runtime/persistence-runtime-4f0f684e7b794609ad5997de3cbfe778/history-report.json`.
This verifies the refusal/health path, not positive live ETW capture. The guest
harness now reads the archive twice and requires its owned native stop identity
in both pending and archived evidence when the lifecycle fixture is requested.
Guest execution remains pending.

Durable graph materialization/rebuild is now implemented and component-tested;
positive live ancestry remains unverified. Still required:
source/native alias evidence, late/reordered and missed-event reconciliation,
archive origin/coverage manifests, explicit bounded retention/export policy with
observable historical gaps, quota fairness and storage-pressure recovery,
long-running resource measurement, corruption/power-loss and OS/guest
qualification. No automatic eviction exists; archive exhaustion refuses growth
and can block the shared journal. B/AG remain partial.
