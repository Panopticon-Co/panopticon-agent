# Phase 9 (telemetry durability): `SegmentSpool`

## Outcome

Closes the gap `docs/architecture/phase-6-delivery.md` documented and
anticipated: `Uploader::flush()` used to log a failed batch (transport error
or non-200 response) to stderr and drop it. There was no disk spool, so a
manager outage or network blip could silently lose telemetry.

```text
Uploader::enqueue() (unchanged: collector threads only ever touch this)
  -> [background thread] batch assembled
  -> SegmentSpool::append(batch_id, body)     durable BEFORE any network attempt
  -> SegmentSpool::peek_ready() / report_outcome()
       -> HttpClient::post() -> manager /api/v1/ingest
       success -> cursor advances, never re-sent
       failure -> bounded exponential backoff, retried in place
       exhausted -> logged, counted dead, skipped (never retried forever)
```

This mirrors the persist-before-deliver pattern the Detection Engine's
`AlertSpool`/`StreamingPipeline` and the Linux agent's own spool/retry/queue
primitives already use — the three components now share understandable,
compatible reliability semantics (bounded, retried, at-least-once, never
silently dropped) even though each implementation is platform-appropriate
rather than a shared library.

## Design

- **Append-only segment files** (`segment-NNNNNN.dat`) under a configurable
  `spool_directory` (default: `spool`, relative to the process's working
  directory). One record = one already-assembled NDJSON batch body plus its
  `X-Panopticon-Batch-Id`, framed as
  `[u32 length][u32 CRC32][u16 batch_id_len][batch_id][body]`.
- **Head-of-line delivery.** Records are read and delivered strictly in
  order. `peek_ready()` / `report_outcome()` is the only interface: a
  success durably advances a persisted read cursor (`spool.cursor`, written
  via temp-file-plus-atomic-rename); a failure schedules a bounded
  exponential backoff (`spool_base_backoff_ms` .. `spool_max_backoff_ms`)
  and re-serves the *identical* record once it elapses — it is never
  silently skipped ahead. Once `spool_max_delivery_attempts` is exhausted,
  the record is logged, counted in `stats().dead_records`, and skipped —
  bounded retry, never an infinite loop, never resurrected.
- **Bounded disk.** `spool_max_segment_bytes` caps one segment (default 8
  MiB, matching `panopticon-manager`'s ADR 002 batch ceiling); once
  exceeded, a new segment is started. `spool_max_total_bytes` caps the whole
  spool (default 64 MiB); if appending would exceed it, the oldest segment
  that is not the currently-active write segment is deleted, logged
  explicitly (`quota exceeded, evicting segment N`). If eviction removes a
  segment still awaiting delivery, that telemetry is genuinely lost — this
  is the documented, unavoidable cost of a hard disk bound under a
  sustained outage, never a silent or unbounded failure mode. Fully
  delivered segments are also proactively deleted as soon as the read
  cursor moves past them, ahead of quota pressure.
- **Crash-safe recovery.** `recover()` scans the spool directory, resumes
  from the last durably persisted cursor (falling back to the oldest
  surviving segment if the cursor is stale, missing, or out of range —
  always safe, since replay is idempotent downstream), and tolerates a
  truncated/torn tail (a crash mid-write: treated as clean end-of-data, not
  corruption) and a corrupted record's checksum mismatch (quarantined —
  logged, counted in `stats().corrupt_records_skipped`, and skipped using
  its still-trusted length field, without losing any record after it).
- **At-least-once, not exactly-once.** A crash between a successful HTTP
  response and the cursor being persisted replays that one batch again on
  restart. This is intentional and safe: `panopticon-manager`'s ADR 002 already
  dedups by the agent-assigned deterministic `event_id`
  (`INSERT OR IGNORE`), so a replayed batch collapses onto itself for free.
  This spool does not invent a second, incompatible identity scheme — it
  relies entirely on that existing mechanism.
- **Single-writer, single-reader by contract.** Only `Uploader`'s own
  background thread ever touches a `SegmentSpool` instance (after one
  `recover()` call at the very start of that thread's loop). Collector
  callback threads never see it — they only ever touch the pre-existing
  in-memory `pending_` batch buffer under its own mutex, unchanged. This was
  a deliberate simplicity choice: a second sender thread able to race with
  segment rotation or the read cursor was considered and rejected in favor
  of the existing single-thread ownership model already used for `flush()`.

## Configuration

Added to `DeliveryConfig` (`delivery/config.hpp`), all with safe, validated
defaults — `SegmentSpool`'s constructor throws `std::invalid_argument` for
an unsafe configuration (zero byte limits, `max_total_bytes` smaller than
`max_segment_bytes`, zero delivery attempts, or an invalid backoff range)
rather than silently clamping it:

| Field | Default | Meaning |
|---|---|---|
| `spool_directory` | `"spool"` | Where segment/cursor files live |
| `spool_max_segment_bytes` | 8 MiB | Cap on one segment file |
| `spool_max_total_bytes` | 64 MiB | Cap on total on-disk spool size |
| `spool_max_delivery_attempts` | 8 | Bounded retries before a record is dropped |
| `spool_base_backoff_ms` / `spool_max_backoff_ms` | 1000 / 60000 | Bounded exponential backoff range |

## Verification status

**The spool component itself (`spool.hpp`/`spool.cpp`) uses no Windows-only
API — only `<filesystem>`, `<fstream>`, `<chrono>`, standard C++20 — and was
compiled and run in this development environment with MinGW-w64 g++
(`g++ -std=c++20 -Wall -Wextra`), not just written and reasoned about.** Its
dedicated test suite (`tests/spool_tests.cpp`, 11 cases covering write/read,
crash-mid-write recovery, corruption quarantine, bounded retry/backoff,
head-of-line non-starvation, permanent-failure dead-lettering, quota
eviction, and segment rotation) passed cleanly and repeatably (8 consecutive
runs, zero flakiness) during this work. This exercise found and fixed one
real bug before it ever reached the repository: a failed delivery's read
cursor was not being rolled back, causing a retried record to be silently
skipped rather than re-served.

**The full `Uploader` integration (`uploader.cpp`, which links `winhttp.lib`
and `bcrypt.lib` and includes `<windows.h>`) was written and reviewed against
the existing CMake/MSVC conventions but has NOT been compiled or run** — this
development environment has no Visual Studio/MSVC/vcpkg toolchain (confirmed:
only MinGW g++ is present, and this repository's own build instructions
require MSVC + vcpkg, not MinGW). Before trusting the end-to-end path:

```powershell
# From an Arm64 or x64 Developer PowerShell for Visual Studio, per README.md
cmake -S . -B build-officer --preset <as documented in README.md> ...
cmake --build build-officer
ctest --test-dir build-officer -R "officer-delivery-tests|officer-spool-tests"
```

`officer-spool-tests` is expected to reproduce this session's already-passing
results verbatim under MSVC (the code is toolchain-agnostic C++20). Whether
`officer-delivery-tests`' new
`test_failed_batch_is_persisted_to_the_spool_not_dropped` case passes depends
on the real WinHTTP transport-failure path, which has never been exercised in
this environment either — that dependency predates this phase.
