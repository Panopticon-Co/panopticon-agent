# Durable process graph and retained ancestry

Journal schema 6 indexes process identity and parent claims from the encrypted
immutable lifecycle archive. New archive rows, their derived index, pending
delivery and optional source cursor commit in the same FULL/WAL transaction.
Acknowledgment cannot erase graph evidence. The index stores only archive ordinal,
SHA-256 entity/parent references and interpretation quality; raw source bodies
remain user-scoped DPAPI originals. These derived metadata are not independently
authenticated or a self-protection boundary.

`process_graph_fact` rederives exact process references from decoded source facts
and checks canonical provenance, identity and operation agreement. Native
boot/PID/creation FILETIME identities remain distinct from source-scoped GUID
identities. Parent edges require an observed parent PID and GUID in the exact
source namespace. PID-only parent descriptors remain unresolved. No live PID
lookup, time proximity, cross-source alias promotion or inferred creator identity
is performed. Refused interpretations retain their original archive evidence.

`process_ancestry` takes one SQLite read transaction over index and originals.
Every returned relation is rederived from decrypted evidence and checked against
its indexed entity/parent digest. Births and stops arriving out of order remain
separate evidence for the same exact identity; stop-only nodes do not acquire
invented births. Missing parents become placeholders. Conflicting parent claims
are retained. Cycles are detected over the returned edge set, including shared
ancestor branches. Source-reported parentage may be spoofed and is not proof of
the actual creator. Liveness remains null even when a stop is retained.

Queries accept only canonical entity IDs and explicit limits (up to 256 nodes,
64 depth, 1,000 evidence records and 8 MiB). Bound exhaustion is observable;
output byte overflow is refused. Retained-evidence traversal completeness means
only the indexed archive was traversed within those bounds. It does not mean
source continuity, host lifecycle completeness or absence of other processes.
Decryption/JSON allocation and synchronous native calls lack hard deadlines.

Schema-5 originals migrate without rewriting; existing archive rows remain a
visible index backlog until `rebuild_process_graph` indexes bounded ordered
pages. The health supervisor attempts 32 records/2 MiB per pass outside its output
mutex. It still holds the journal mutex during native work and is not a fully
isolated worker. An oversized head is refused rather than silently skipped.
Indexed and unresolved/refused counts are durable; graph health remains degraded.
Old schema-5 binaries cannot open schema-6 journals. Backfill cannot recover
previously retired or missed observations. Index storage uses sampled physical
admission, not an independently reserved quota.

## Validation and remaining work

Fresh Debug/Release builds pass 39 CTest entries (25.80/22.28 seconds). Component
regressions exercise reordered births/stops, ACK retirement, reopen, actual
schema-5 migration, bounded idempotent rebuild, exact original preservation,
PID reuse, source namespace separation, forged-reference refusal, index digest
mismatch refusal, unresolved parents, conflicting claims, cycle and query bounds.
Positive graph contents in these tests are fixtures, not live ETW/Sysmon evidence.

An owned 20-second Release Windows host runtime recovers 7,945 byte-identical
originals after abrupt exit. All pass Schema 1.0 and Manager native-body
preservation. Twenty-three durable graph health records report degraded state.
The archive is empty because host ETW is access-denied; a query for an absent
fixture identity returns one empty placeholder, no edges and null liveness.
`tools/validate_process_graph.py` verifies this distinction. Evidence:
`demo-run/process-graph/persistence-runtime-715aca2c54b841589d0aaef8103f7e53/process-graph-report.json`.

B/AG remain partial. Still required: positive privileged native/guest ancestry,
verified native/source aliases, creator/requested-parent distinctions, missed-event
reconciliation, archive coverage/retention-gap manifests, product forensic query
integration, resource/large-host measurement, storage-pressure recovery, tamper
and power-loss qualification, cross-version/source qualification and durable
origin/coverage authority. This API is an evidence projection, not a complete
production process tree.

Subsequent dedicated-guest evidence closes the live retained-lifecycle gap for
one owned target: nine native ETW births and nine stops are recovered byte-exact
after abrupt exit. The ping target's held-process PID/creation FILETIME and native
exit code match its archived stop; ancestry readback returns its exact birth and
stop, zero backlog and null liveness. ETW supplies no verified parent GUID edge,
so this is not positive parent ancestry or creator evidence. All 21 selected
component executables return zero in the guest. Exported records and package
hashes verify with `tools/verify_windows_guest_evidence.py`. See the consolidated
guest entry in [validation](VALIDATION.md). B/AG remain partial.

Next native identity investigation: the current host provider manifest exposes
`ProcessSequenceNumber` and `ParentProcessSequenceNumber` on birth versions 3/4,
and `ProcessSequenceNumber` on stop version 2. These are UInt64 source fields,
not GUIDs or creation FILETIME. The collector now retains them with exact
TDH type/read status and decimal carriers. Live guest birth version 4 and stop
version 2 are verified, including the owned target's matching lifecycle sequence.
See [native process fields](NATIVE_PROCESS_FIELDS.md). Sequence alias resolution
and parent edges are not implemented by this retention wave.
Manifest evidence:
`demo-run/native-process-metadata/5d2a36cd56824414b58aebd57d39263a/kernel-process-manifest.json`.
The manifest is metadata evidence only; the separate guest report supplies live
scalar payload evidence. Qualified boot/source scope, alias coassertion/conflict
rules, older-version fallback and live parent semantics still require verification
before these fields can support edges.
