# Officer

Officer is the Windows endpoint telemetry agent for the Panopticon EDR/XDR
project. It is written in C++20 and is being developed as a set of independently
testable collectors, enrichment stages, pipelines, queues, and transports.

## Phase 0 status

The original EyeTrace Query v0.1 implementation is preserved by the Git tag
`eyetrace-query-v0.1` and has moved to `tools/query/` as `officer-query`.

The root `officer-agent` executable is currently a bootstrap target. Agent
contracts and the Panopticon event schema are the next implementation phase.
There is no live collector, service, network transport, detection engine, or
response executor in this phase.

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

- `officer-agent`: Officer agent runtime, currently a Phase 0 bootstrap.
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
