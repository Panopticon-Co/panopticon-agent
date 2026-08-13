# Officer

Officer is the Windows endpoint telemetry agent for the Panopticon EDR/XDR
project. It is written in C++20 and is being developed as a set of independently
testable collectors, enrichment stages, pipelines, queues, and transports.

## Phase 1 status

The original EyeTrace Query v0.1 implementation is preserved by the Git tag
`eyetrace-query-v0.1` and has moved to `tools/query/` as `officer-query`.

Phase 1 defines the source-neutral process telemetry contract, separates raw
facts from enrichment, normalizes process-start telemetry into Panopticon event
schema 0.1, and validates strict JSON serialization. Stable process identities
are derived with Windows CNG SHA-256 from the host ID, PID, and process start
time so PID reuse cannot merge unrelated processes.

See [the Phase 1 design](docs/architecture/phase-1-contracts.md), the
[process identity decision](docs/adr/003-process-entity-id.md), and the frozen
[JSON Schema](schema/event.schema.json).

There is still no live collector, Windows service, network transport, durable
spool, detection engine, or response executor. The executable reports the
implemented contract version and exits.

## Repository boundaries

This repository owns the endpoint agent only:

- Windows telemetry collection through ETW and WEVT adapters.
- Raw source-neutral telemetry structures.
- Enrichment and normalization into versioned Panopticon events.
- Internal queues, batching, durable SQLite spooling, and HTTPS delivery.
- Agent identity, configuration, health, and Windows service lifecycle.

The Panopticon server, detection engine, console, and arbitrary command
execution are out of scope.

## Targets

- `officer-core`: source-neutral contracts, identity, normalization, and JSON boundary.
- `officer-agent`: Officer agent runtime bootstrap linked to `officer-core`.
- `officer-core-tests`: Phase 1 identity, normalization, and contract tests.
- `officer-query`: historical Sysmon query and diagnostic utility.
- `officer-tests`: sanitized parser tests for the query utility.

## Native ARM64 build

Run from an Arm64 Developer PowerShell for Visual Studio:

```powershell
cmake -S . -B build-officer-arm64 -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/18/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=arm64-windows

cmake --build build-officer-arm64
ctest --test-dir build-officer-arm64 --output-on-failure
```

See [tools/query/README.md](tools/query/README.md) for historical Sysmon query
usage. Never commit raw telemetry: command lines, usernames, paths, URLs, and
tokens can appear in endpoint records.
