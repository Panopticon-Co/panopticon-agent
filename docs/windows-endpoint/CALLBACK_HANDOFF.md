# Decoded-event callback handoff

ETW and Sysmon deliver owned decoded `RawEvent` values to one bounded worker.
The callback performs capacity charging and enters a short queue mutex section;
it does not perform normalization, canonical serialization, DPAPI, journal commit
or stdout writes. Callback error notifications update coverage and signal health;
they no longer synchronously write diagnostics to stderr. Native rendering,
decoding, ETW metadata queries and process-cache enrichment still occur inside
the collector callback and require further isolation and cost qualification.

The runtime admits at most 8,192 owned events and a 64 MiB charge. Ownership
includes the event being processed, so a stalled journal cannot free capacity
merely by dequeuing work. Charge covers variant objects and all owned string
capacities, including source fields and separate cached process context. It
excludes allocator bookkeeping, worker scratch copies, canonical/DPAPI
buffers and total RSS. Large reserved string capacities count even when their
logical contents are short. The ring preallocates its slots before collectors start;
health separately reports fixed ring storage bytes. Admission moves owned values
into those slots without deque/slot allocation. Configured event capacity is bounded
at 65,536. Neither budget is a complete process memory cap.

Admission is volatile ownership, **not durable capture**. Only successful worker
completion follows journal acceptance. Refused ownership throws back through
the collector sink so the corresponding source records a sink failure. Count,
byte and closed-queue refusals are counted, with admission exceptions separately
reported as `exception_refused`; their cause is not assumed to be allocation.
The retired `contention_refused` health field remains zero with explicit policy
scope. The previous try-lock policy refused 3,027 of 4,000 one-attempt submissions
in a four-producer test despite spare count/byte capacity. Waiting for the short
preallocated-ring mutex section removes that avoidable loss. It never waits for
capacity or executes handler I/O under the queue lock. Scheduler/mutex delays mean
this is still not a hard callback latency guarantee.
Worker exceptions are counted and do not terminate later processing. A worker
exception can occur after a record committed, so failed completion is not claimed
as a known lost native event. Refused events and failed completions receive a
canonical gap with distinct units/scopes. One stable serialized pending gap is
retried until the journal accepts it; committed baselines advance only then.

Health exposes admitted volatile, completed durable, failed/refused, owned and
charged counts, limits and pending gap state as exact decimal strings. Coverage
stays degraded. Counters are current runtime lifetime only. An abrupt exit can
lose owned events and uncommitted gap metadata without a recoverable count;
durable admission intent, emergency reserve and restart loss accounting remain
P0 gaps. Callback return must never be used as a durable acceptance receipt.

Shutdown stops producers before closing/draining the worker, then emits final
health before stopping delivery. Committed evidence remains journaled. A blocked
handler/console output can still delay orderly shutdown; operation deadlines,
drain leases and console isolation remain open. There is one shared worker/queue;
source fairness, priority evidence lanes and storm/soak qualification remain open.

Native tests block a real journal handler behind a test-owned synchronization
gate, prove the in-flight event remains volatile/charged and a further submission
refuses without waiting for storage, then verify exact bytes after commit. They
also exercise reserved string capacity, cache/registry fields, oversize refusal,
worker exception continuation and closed ownership. They do not prove real
privileged ETW/Sysmon storm performance or abrupt-exit loss recovery.

Concurrent tests make 4,000 unique one-attempt submissions from four producers,
both with a lightweight handler and with the handler blocked throughout submission.
Every admitted value must complete once; spare-capacity refusal is a regression.
Two-slot wrap/reuse tests verify FIFO and absence of stale slot replay. These are
controlled queue/handler tests, not native provider or journal throughput claims.
