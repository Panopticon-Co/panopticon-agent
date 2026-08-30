# Phase 6/7 (network delivery): the `officer-delivery` library

## Note on numbering

This work spans `docs/roadmap.md`'s Phase 6 ("durable spool" — this document
deliberately supersedes that phase's SQLite proposal with a flat-file segment
spool, added in a later increment) and Phase 7 ("secure delivery and
configuration"), not Phase 3, which is unrelated in-process
queue/backpressure work. The manager-side project this pairs with numbers its
own phases 0–8 independently — see `panopticon-manager/docs/ROADMAP.md`.

## Outcome (tracer bullet increment)

Officer gained an optional second sink for its normalized events: an HTTPS
POST to a Panopticon manager, alongside — never instead of — its existing
unconditional stdout output.

```text
collector callback thread
  -> RawEvent -> enrichment -> normalize_*_event() -> serialize_event()
  -> stdout (unconditional, unchanged)
  -> Uploader::enqueue() (only if --manager-url was given)
       -> [background thread] batch -> HttpClient::post() -> manager /api/v1/ingest
```

No flag changes today's default behavior: `officer-agent.exe` with no
arguments is byte-for-byte what it was before this library existed.

## `officer-delivery` (new static library)

- `delivery/config.hpp` — `DeliveryConfig{manager_url, verify_tls,
  batch_max_events, flush_interval_ms}`. Identity (agent_id/agent_key from
  enrollment) and durable spool config are not here yet — Phase 4/5 scope.
- `delivery/http_client.hpp` / `.cpp` — a minimal synchronous WinHTTP POST
  wrapper. One call = one connect + request + response, no pooling. Returns
  `std::nullopt` only on a transport-level failure (DNS, connect, TLS
  handshake, timeout); a non-2xx HTTP status is a normal `HttpResponse` the
  caller inspects. Zero new vcpkg dependencies — `winhttp.lib` and
  `bcrypt.lib` are OS-shipped, linked via `#pragma comment(lib, ...)` plus
  CMake `target_link_libraries`.
- `delivery/uploader.hpp` / `.cpp` — an in-memory batcher with its own
  background thread. `enqueue()` is the only thing collector callback
  threads touch: a mutex-protected `push_back`, nothing else. The
  background thread wakes on a count threshold or a flush-interval timeout,
  swaps out the pending batch, and POSTs it. A failed batch (transport error
  or non-200) is logged to stderr and dropped — there is no disk spool yet,
  so this phase can lose events across a manager outage. That gap is closed
  in Phase 5 (`SegmentSpool`), not before.

This threading split matters: **no network call ever happens on an ETW or
Sysmon callback thread.** A slow or unreachable manager therefore cannot
stall telemetry collection — it can only make the in-memory buffer grow
until a batch flush finally succeeds or is dropped.

## CLI surface

```
officer-agent.exe                                        # unchanged: stdout only
officer-agent.exe --manager-url https://host:8443         # stdout AND network delivery
officer-agent.exe --manager-url https://host:8443 --insecure-tls  # bring-up only, warns
```

`--insecure-tls` skips WinHTTP certificate validation
(`WINHTTP_OPTION_SECURITY_FLAGS`) and is meant for first bring-up only —
real certificate pinning is Phase 8 scope.

## What this does not do yet

No enrollment, no bearer auth, no `X-Panopticon-Batch-Id` idempotency replay
(nothing retries yet, so nothing needs to replay), no durable spool, no
backoff/retry, no `429` backpressure handling, no config fetch, no check-in.
See `panopticon-manager/docs/adr/002-wire-protocol-ack-semantics.md` for the
target design these will fill in.

## Verification status

Written against this repo's existing WinHTTP-free codebase and reviewed
against the CMake/MSVC conventions already in use, but **not yet compiled or
run** — this environment has no Windows/MSVC/vcpkg toolchain. Before trusting
this code: `cmake --build` on the Windows VM, run `ctest` (new
`officer-delivery-tests` target), and do the cross-machine proof in
`panopticon-manager`'s Phase 1 plan (VM agent -> Mac manager -> rows in
SQLite).
