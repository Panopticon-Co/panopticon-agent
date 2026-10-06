# Clock-independent endpoint state ordering

The journal commits an installation-scoped uint64 collector generation before
collection starts. Every new factory requires that committed nonzero generation;
provenance carries it as a decimal string alongside its random collector epoch
and ordered sequence. FULL/WAL allocation is transactional across separate
journal handles and survives reopen/abrupt process exit. Reserved metadata names
cannot be allocated through the random-identifier API. Corrupt/exhausted counter
metadata fails startup rather than silently reusing a generation.

Manager migration 14 stores generation/epoch bindings, the active installation
stream, and projection ordering metadata. A generation cannot bind two collector
epochs: a fork rolls back the request with 409 and acknowledges nothing. Within
the active installation, higher generations supersede lower ones; within a
generation, higher sequences supersede lower ones. Client wall-clock values never
choose the current projection. All accepted originals remain in history, even
when an old offline record cannot change a projection.

The first authenticated ordered stream establishes the active installation.
Another installation's records remain history and cannot silently reactivate
state. This is conservative replacement behavior, not a complete replacement
workflow: controlled enrollment/installation activation and recovery from lost
journal identity remain open. A generation conflict detects some copied/reset
counter states; it does not constitute full clone prevention or a distributed
single-writer lease.

`/api/v2/endpoint/<agent>/latest` returns retained projection records plus
`projection_status` for each. Ordering is `current`, `superseded`,
`inactive_installation` or `unverified`. Advancing to a new generation invalidates
old domain projections even before that domain supplies a replacement. Old
records without generation are supported as explicitly unverified projections;
they cannot displace an ordered projection. Consumers must consult the status,
not interpret the retained raw capability snapshot alone as current health.

Ordering is not freshness. A latest-in-order record may still have spent a day
offline. Every response currently reports `observation_freshness: unverified`;
receipt time is never a live observation proof. Boot-scoped canonical capture age
now uses authenticated uploader facts and a bounded one-use challenge; see
[capture freshness and limitations](CAPTURE_FRESHNESS.md). Native event freshness,
truthful sensor continuity, distributed/restart freshness, policy budgets and
Console stale/blind rendering remain open P0 work. Capture proof expires or
becomes unverified across Manager restarts; it never upgrades source continuity.

Tests cover full uint64 generation transport, allocation across handles, restart,
abrupt child-process termination, clock rollback, reverse arrival, old offline
replay, domain invalidation, installation replacement history and whole-request
fork rollback. The native WinHTTP harness verifies generation-aware projection
ordering through the actual Manager. Backup rollback, power-loss/storage faults,
single-writer lifecycle, history retention budgets and fleet qualification remain
open. The schema adds an optional generation field for old record compatibility;
all new Windows records supply it.
