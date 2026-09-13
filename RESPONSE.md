# Response boundary

The Manager's Response Engine authorizes commands; this agent only authenticates, validates,
target-checks, replay-checks, dispatches a closed action set, executes, receipts, and audits --
the same division of responsibility as `panopticon-linux-agent`, adapted to Win32 APIs.

## Current status

Response is opt-in (`--enable-response`, requires `--manager-url`) and additive: an operator
who never passes the flag gets byte-identical behavior to the telemetry-only agent that shipped
before this pass -- no new files, no new outbound calls, no new threads.

When enabled, the agent loads (or, given `--bootstrap-token-path`, bootstraps and persists) an
enrolled bearer identity (`panopticon::officer::response::EnrolledIdentity`), then runs a
background thread that every `--response-poll-interval-ms` (default 15s) does one full
poll -> gate -> accept -> execute -> result cycle, mirroring `panopticon-linux-agent/src/main.cpp`'s
control flow exactly:

- `ResponseTransportClient::poll_commands` -- `GET /api/v1/agents/{agent_id}/commands`, built on
  the same `WinHTTP`-based `HttpClient` the existing telemetry `Uploader` uses (`delivery/http_client.hpp`'s
  new generic `request()` verb entry point), not a second HTTP stack. Always verifies the TLS
  certificate chain -- `ResponseTransportClient` has no insecure-TLS constructor at all, unlike the
  telemetry path's `--insecure-tls` bring-up flag.
- `parse_command_json` / `parse_command_poll_response` -- decode only the Manager's closed
  schema-1 envelope via `nlohmann::json` (already a dependency here): an exact known top-level
  key set, a `target` shape fully determined by `action`, UTC-only RFC 3339 timestamps, and a
  closed 7-action enum. Unknown fields, unknown actions, or a mismatched target shape are all
  rejected outright rather than tolerated -- see `tests/response_tests.cpp` for the specific
  malicious/malformed inputs exercised (smuggled extra fields, non-UTC offsets, oversized
  payloads, wrong target shape per action).
- `CommandGate::validate_and_mark` -- agent/host binding, expiry, in-memory *and* durable
  (`ReplayLedger`, a newline-delimited file, survives a process restart) replay protection, and
  protected-PID/-image rejection for `KILL_PROCESS` before the command is ever dispatched.
- Immediately after a command passes the gate and before this agent executes it, a best-effort
  `POST /api/v1/agents/{agent_id}/commands/{command_id}/accept` moves Manager's lifecycle state
  `DISPATCHED -> ACCEPTED`. Its outcome is never checked and never blocks execution, matching the
  Linux agent and the Manager contract (`docs/RESPONSE_ENGINE_STATE.md`'s ACCEPTED-state notes):
  Manager still accepts a result submitted straight from `DISPATCHED`.

All 7 actions in the closed set are dispatched to a real, typed Win32 implementation:

- `KILL_PROCESS` -- `reobserve_process` re-checks the PID's `GetProcessTimes` creation-time
  tuple against the command's `start_time_ticks` (defeats PID reuse), refuses PID 0/4 and a
  hardcoded critical-image list (`csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`,
  `smss.exe`), re-checks the creation time once more on the freshly reopened
  `PROCESS_TERMINATE` handle (narrows, does not eliminate, the reopen-to-terminate TOCTOU
  window -- there is no atomic "terminate iff creation-time == X" Win32 primitive), and only
  then calls `TerminateProcess`.
- `COLLECT_PROCESS_INFO` -- same re-observation, fed through the *existing* `normalizer`/
  `serializer` pipeline (`pipeline::normalize_process_event` / `serialize_event`) so response
  evidence is Schema 0.3-shaped exactly like live telemetry, not a second wire format.
- `COLLECT_NETWORK_CONNECTIONS` -- bounded `GetExtendedTcpTable`/`GetExtendedUdpTable` (v4 and
  v6). `owner_pid` is always populated (the `*_OWNER_PID` table classes always carry it on
  Windows) but stays a nullable wire field for parity with Linux, where the kernel doesn't
  always supply one.
- `COLLECT_FILE` -- `resolve_within_allowed_root` refuses absolute paths and anything whose
  canonicalized resolution lands outside the configured allow-listed root (`..` traversal,
  drive-letter escapes), reads a bounded (16 MiB) regular file, hashes it with the *existing*
  CNG-backed `core::sha256_hex` (newly exposed from `core/entity_id.cpp`, not a second crypto
  dependency), and returns only path/size/hash -- raw content never leaves the local read.
- `QUARANTINE_FILE` -- same root-jailing, then `MoveFileExW` (atomic same-volume rename;
  `MOVEFILE_COPY_ALLOWED` falls back to copy+delete cross-volume) into the quarantine root,
  followed by a `SetNamedSecurityInfoW` DACL denying `Everyone` execute/write/delete on the
  quarantined copy -- the Windows-specific hardening step beyond what a plain restrictive move
  needs on Linux.
- `ISOLATE_HOST` / `RELEASE_HOST_ISOLATION` -- `build_isolation_plan` is a pure function
  (no Win32 calls, fully unit-tested) that derives deterministic WFP object GUIDs from fixed
  names, so isolate/release are idempotent without needing a separate state file. `apply_isolation`/
  `release_isolation` then call `FwpmEngineOpen0`/`FwpmSubLayerAdd0`/`FwpmFilterAdd0`/
  `FwpmFilterDeleteByKey0` to add (or remove) a default-block sublayer at
  `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`, with a single
  higher-weight permit filter scoped to the configured `--manager-exception-host` address --
  **no SSH/RDP break-glass and no general ESTABLISHED/RELATED bypass**, mirroring the Linux
  isolation ADR's "the sole carve-out is the one channel that can release the isolation" rule
  exactly. See "Environment-blocked" below for what is and is not verified about this path.

Every command result is a typed, bounded receipt (`serialize_command_result`) submitted to
`POST /api/v1/agents/{agent_id}/command-results`. No command ever reaches an unbounded
filesystem read, `system()`/`ShellExecute`, or an arbitrary executable path.

## Architectural decisions a reviewer should double-check

1. **No separate privileged-helper process.** Unlike the Linux agent's `AF_UNIX`-IPC-separated
   `panopticon-isolation-helper`, this pass keeps isolation (and every other handler) in the
   single `officer-agent.exe` process. `officer-agent.exe` already requires an elevated token for
   ETW/Sysmon subscription (a pre-existing requirement, not new here), so there is no
   least-privilege gap being newly introduced by *also* calling WFP APIs from the same already-
   elevated process. If a future pass wants the Linux-style split (a narrowly-scoped helper that
   holds only the WFP/firewall privilege and nothing else), it is additive, not a rearchitecture.
2. **Response only starts if at least one telemetry collector started.** `main()`'s existing
   `if (started == 0) { ...; return 4; }` gate runs before the new response-bootstrap block, so on
   a host where neither ETW nor Sysmon can start (e.g. unelevated), response never starts either
   -- even though none of the 7 response actions actually depend on either collector being active.
   This was the simplest integration into the existing control flow; a reviewer may prefer response
   to be able to run standalone.
3. **`agent_id`/`host_id` reused from the existing machine-GUID-derived identity.** This agent had
   no enrollment concept before this pass (Phase 1 delivery only sent an `X-Panopticon-Agent-Id`
   header derived from the registry `MachineGuid`, with no bearer token). Response enrollment now
   reuses that same `officer-<machine-guid>` / `<machine-guid>` pair as the `agent_id`/`host_id`
   sent to `POST /api/v1/agents/enroll`, so a single machine has one consistent identity across
   telemetry and response. A reviewer should confirm this is the desired coupling (vs. a fully
   independent response identity).
4. **Evidence for `COLLECT_NETWORK_CONNECTIONS`/`COLLECT_FILE`/`QUARANTINE_FILE` is emitted through
   the same stdout+`Uploader` path as telemetry** (`ResponseRuntime::emit_line`), not a dedicated
   evidence-submission endpoint -- there isn't one in the current Manager contract. `COLLECT_PROCESS_INFO`
   evidence is the one exception that is genuinely Schema-0.3-shaped (via the normalizer); the
   other three are plain evidence JSON lines. Worth revisiting once/if Manager grows a dedicated
   evidence-ingestion endpoint.

## Environment-blocked

This development environment has a real MSVC/vcpkg toolchain (verified: full build + all tests
below actually ran and passed) but:

- **No elevation available.** The interactive session's token has `BUILTIN\Administrators` as
  deny-only (unelevated, non-interactive -- no UAC prompt can be answered here). ETW/Sysmon
  collector start already fails today in this environment for the same reason (pre-existing,
  confirmed by a live `officer-agent.exe --enable-response ...` smoke run: it printed "Officer is
  not elevated", failed to start the ETW collector, and exited via the pre-existing `started == 0`
  path before response ever got a chance to run). This means the *live* enrollment/poll/accept/
  result HTTP round trip, live `KILL_PROCESS`/`TerminateProcess` against a real elevated target,
  and live WFP `FwpmEngineOpen0` (which itself requires an elevated token) have **not** been
  exercised end-to-end in this environment -- only unit-tested in isolation (see below).
- **No live non-loopback network or running Manager instance.** Real WFP filter *enforcement*
  (i.e., proving a permit/block filter actually changes what traffic reaches the wire on a live
  adapter) cannot be demonstrated here, matching the Linux agent's own ADR-004 de-risking-spike
  caveat for its netlink/nftables isolation path. What **is** verified without a live network:
  `build_isolation_plan`'s determinism/idempotency (pure function, unit-tested), and that
  `apply_isolation`/`release_isolation` compile against the real `fwpmu.h`/`Fwpuclnt.lib` API
  surface with correct structure layouts (`FWP_V6_ADDR_AND_MASK::prefixLength`, not `mask` --
  caught by the compiler, not assumed).

## What was verified in this environment (real command output, not paraphrased)

- Full CMake configure (Ninja + the existing `vcpkg.json` manifest, `x64-windows` triplet) and
  build succeeded with zero warnings introduced by this pass beyond one `[[nodiscard]]`-discard
  warning in the new test file, which was fixed.
- `ctest --output-on-failure` in `build-officer-x64`: **9/9 tests passed**, including the 5
  pre-existing suites (unchanged) and the new `officer-response-tests` (18 assertions covering
  command decode/reject cases, `CommandGate` idempotency/replay/expiry/protected-PID/wrong-agent,
  a durable-ledger-survives-restart simulation, `is_protected_process`, isolation-plan purity, and
  file-evidence path-traversal rejection / hash-only-evidence collection).
- `officer-agent.exe --help` prints the new `--enable-response`/identity/root/exception flags
  alongside the existing ones.
- A live (unelevated) smoke run of `officer-agent.exe --source etw --manager-url https://127.0.0.1:1
  --enable-response --bootstrap-token-path <file>` confirmed the *existing* elevation requirement
  and exit path are unaffected by adding `--enable-response` (see "Environment-blocked" above for
  what this run could not reach).

No CI changes were needed: `.github/workflows/ci.yml` already runs a full `cmake --build` +
`ctest --test-dir build-officer-x64` on Windows for every push/PR, and both automatically pick up
the new `officer-response` target and `officer-response-tests` executable without modification.
