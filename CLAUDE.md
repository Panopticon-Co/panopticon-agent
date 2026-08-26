# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This is **panopticon-agent**, internally named **"Officer"** — the Windows endpoint agent for the Panopticon&Co EDR platform (a separate polyrepo project; see `../CLAUDE.md` if present for cross-repo context). It is a C++20 agent that collects Windows process-creation telemetry via ETW and Sysmon, normalizes it, and emits it as **Panopticon Schema 0.2** NDJSON on stdout for consumption by the separate `panopticon-detection-engine` repo. This repo does not depend on that repo, and should not gain such a dependency.

## Build

Requires vcpkg (via Visual Studio's bundled vcpkg or standalone) and Ninja. Currently only built/documented against the **`arm64-windows`** triplet — `x64-windows` has not yet been validated in this repo; do not assume it works without testing.

```powershell
cmake -S . -B build-officer-arm64 -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/18/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=arm64-windows

cmake --build build-officer-arm64
ctest --test-dir build-officer-arm64 --output-on-failure
```

For an x64 build, swap `-DVCPKG_TARGET_TRIPLET=x64-windows` and use an x64 Developer PowerShell / vcpkg triplet — this is unvalidated territory, expect to debug it. There is no `CMakePresets.json`; triplet/toolchain are always passed explicitly at configure time. `vcpkg.json` declares only `nlohmann-json` and `tinyxml2` as dependencies (no triplet list). Build is MSVC-only (no clang/GCC path in `CMakeLists.txt`).

Build outputs (in the build dir): `officer-agent.exe` (the live agent — **note the executable is `officer-agent.exe`, not `officer.exe` or `panopticon-agent.exe`**), `officer-core-tests.exe`, `officer-collector-tests.exe`, plus `officer-query.exe` and its own tests from the `tools/query/` subproject.

## Run

Requires an elevated (Administrator) PowerShell for ETW/Sysmon access.

```powershell
.\build-officer-arm64\officer-agent.exe --source all   # or: --source etw | --source sysmon
```

Stop with Ctrl+C. If a session is orphaned afterward, clean it up with:

```powershell
logman stop Panopticon-Officer-Process -ets
```

## Test

No third-party test framework — `tests/contract_tests.cpp` and `tests/collector_tests.cpp` are standalone executables with hand-rolled `main()` assertions, wired into CTest (`officer-core-contract-tests`, `officer-live-collector-decoder-tests`, `officer-agent-cli-help`). `tools/query/` has its own CTest cases (`officer-query-parser-tests`, `officer-query-cli-help`, two `WILL_FAIL` negative-argument tests). Run all via `ctest --test-dir <build-dir> --output-on-failure`. There is no CI configured (`.github/workflows/` does not exist) — tests are currently only run locally/manually.

## Architecture

Data flow (`src/main.cpp` wires this together):

```
EtwProcessCollector / SysmonEventCollector   (src/collectors/)
        -> telemetry::RawProcessEvent         (via RawEventSink callback, std::variant)
        -> enrichment::EnrichedProcessEvent    (filename extraction, sha256 passthrough, user/domain split)
        -> pipeline::normalize_process_event() (src/pipeline/normalizer.cpp)
        -> pipeline::serialize_event()         (src/pipeline/serializer.cpp)
        -> one NDJSON line to stdout per event; warnings/errors to stderr
```

- `src/collectors/` — `etw_process_collector.cpp`, `sysmon_event_collector.cpp`, `sysmon_process_decoder.cpp`. Real Windows API code: ETW session/consumer setup + TDH property parsing, `EvtSubscribe`-based Sysmon subscription + XML decoding (via tinyxml2). Not stubs.
- `src/core/entity_id.cpp` — process entity ID derivation (host + PID + start time; see `docs/adr/003-process-entity-id.md`).
- `include/panopticon/officer/` mirrors `src/` and additionally holds the wire types: `telemetry/{raw_process_event.hpp, panopticon_event.hpp}`, `enrichment/enriched_process_event.hpp`.
- `schema/event.schema.json` — the authoritative **Panopticon Schema 0.2** definition (JSON Schema draft 2020-12, `additionalProperties: false`). This is the API boundary with the Detection Engine repo — see the workflow note below before touching it.
- `tools/query/` — a separate CMake subproject, `officer-query.exe`: a historical/diagnostic Sysmon Windows-Event-Log reader (not live collection), preserved as "EyeTrace Query v0.1" (see git tag `eyetrace-query-v0.1`). Has its own `src/`, `tests/`, `README.md`, `docs/`.
- `docs/roadmap.md` — phase-by-phase status; this repo is currently at **Phase 2 (live ETW + Sysmon collection)**. Not yet implemented, by design: bounded event queue/backpressure, durable SQLite spooling, network delivery to a backend, Windows service lifecycle, non-process event schemas (network/file/registry/DNS/image-load/process-stop).
- `docs/architecture/` — `phase-1-contracts.md` (raw/enriched/normalized contract design), `phase-2-live-collection.md` (current phase design), `detection-ingestion-boundary.md` (states explicitly: Officer produces observations only, no detection logic belongs here).

## Changing the event schema

`schema/event.schema.json` is a cross-repo API boundary consumed by `panopticon-detection-engine`'s `OfficerIngestionAdapter`. Before changing it, check both the producer (`pipeline/serializer.cpp`) and this repo's contract tests, and be prepared to update the consumer repo in the same change — don't change it in isolation.
