# Officer

Officer is the Windows endpoint telemetry agent for **Panopticon**, a capstone
EDR/XDR platform. Its job is to observe security-relevant activity on a Windows
endpoint, turn source-specific records into a stable Panopticon event format,
and eventually deliver those events reliably to the Panopticon backend.

This repository contains the **agent only**. It does not contain Panopticon's
detection engine, ingestion API, investigation console, or response service.

## Where Officer fits

```mermaid
flowchart LR
    A["Windows endpoint"] --> B["ETW / Sysmon / Windows Event Log"]
    B --> C["Officer collectors"]
    C --> D["Raw source-neutral events"]
    D --> E["Enrichment and normalization"]
    E --> F["Versioned Panopticon events"]
    F -. "future delivery" .-> G["Panopticon ingestion"]
    G --> H["Detection and correlation"]
    H --> I["Analyst console and response"]
```

Different Windows telemetry sources describe similar activity in different
ways. Officer hides those differences behind source-neutral C++ contracts. The
rest of Panopticon should not need to know whether a process event originated
from ETW, Sysmon, or another supported adapter.

Officer will eventually own:

- Windows telemetry collection through independent source adapters.
- Source-neutral raw event contracts.
- Local enrichment such as file hashes and account resolution.
- Normalization into versioned Panopticon events.
- Bounded queues, batching, and durable local spooling.
- Authenticated delivery to Panopticon ingestion.
- Agent configuration, identity, health, and Windows service lifecycle.

Detection rules remain configurable on the Panopticon side. Collection code
does not contain detection logic, and source adapters do not produce JSON or
communicate with the server directly.

## Current status: Phase 1

Phase 1 establishes and tests the pipeline's contracts before live collection
introduces concurrency and operating-system lifecycle concerns.

Implemented now:

- A source-neutral raw process-start contract with source provenance.
- A separate enrichment contract so observed facts are not overwritten.
- Panopticon normalized process event schema `0.1`.
- Deterministic event IDs and PID-reuse-safe process entity IDs.
- Windows CNG SHA-256 identity derivation.
- Strict JSON serialization, deserialization, and malformed-input rejection.
- Native Windows ARM64 contract and parser tests.
- `officer-query`, the preserved EyeTrace v0.1 historical Sysmon reader.

Not implemented yet:

- A live ETW or Sysmon subscription inside `officer-agent`.
- The bounded event bus and backpressure handling.
- Durable SQLite spooling or network delivery.
- Windows service installation and lifecycle management.

The next phase should connect one live ETW process collector to the existing
`RawProcessEvent` boundary. It should not bypass the contracts by emitting JSON
from the collector.

See [the Phase 1 design](docs/architecture/phase-1-contracts.md), the
[process identity decision](docs/adr/003-process-entity-id.md), and the frozen
[JSON Schema](schema/event.schema.json).

## Build and test on Windows ARM64

Run these commands from an **Arm64 Developer PowerShell for Visual Studio**:

```powershell
cmake -S . -B build-officer-arm64 -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/18/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=arm64-windows

cmake --build build-officer-arm64
ctest --test-dir build-officer-arm64 --output-on-failure
```

The build produces:

- `officer-agent.exe` — the Phase 1 agent bootstrap linked to `officer-core`.
- `officer-core-tests.exe` — identity, normalization, and JSON contract tests.
- `officer-query.exe` — the historical Sysmon query and diagnostic utility.
- `officer-tests.exe` — sanitized Sysmon parser tests.

Running the current bootstrap confirms the compiled versions but does not start
collection:

```powershell
.\build-officer-arm64\officer-agent.exe
```

```text
Officer agent 0.1.0
Panopticon event contract 0.1
Phase 1 contracts are ready; no live collectors are started.
```

## Working telemetry example

The agent is not live yet, but `officer-query` can already retrieve historical
events from a running Sysmon installation. From an elevated PowerShell, query
the newest Sysmon process-creation event and write the same NDJSON to the
console and a temporary file:

```powershell
.\build-officer-arm64\tools\query\officer-query.exe `
  --event-id 1 `
  --limit 1 `
  --output "$env:TEMP\officer-process.ndjson"

Get-Content "$env:TEMP\officer-process.ndjson"
```

This proves the Windows Event Log acquisition and Sysmon parsing path. It is a
diagnostic utility, not the future live Officer pipeline. Event IDs `3`, `11`,
`12`, `13`, and `14` can also inspect network, file, and registry activity. See
[Officer Query usage](tools/query/README.md).

## Desired normalized event

The Phase 1 normalizer and tests already produce and validate the following
shape in memory. The values below are sanitized and formatted for readability;
the future live agent will emit one compact JSON object per event.

```json
{
  "schema_version": "0.1",
  "event": {
    "id": "evt_1111111111111111111111111111111111111111111111111111111111111111",
    "category": "process",
    "type": "start",
    "timestamp": "2026-08-13T20:15:42.123Z"
  },
  "agent": {
    "id": "agent-sanitized-001",
    "version": "0.1.0"
  },
  "host": {
    "id": "host-sanitized-001",
    "hostname": "OFFICER-LAB",
    "os": {
      "name": "Windows 11",
      "build": "26100"
    }
  },
  "user": {
    "name": "analyst",
    "domain": "LAB",
    "sid": "S-1-5-21-1000000000-1000000001-1000000002-1001"
  },
  "process": {
    "entity_id": "proc_2222222222222222222222222222222222222222222222222222222222222222",
    "pid": 4242,
    "name": "officer-demo.exe",
    "executable": "C:\\Sanitized\\officer-demo.exe",
    "command_line": "\"C:\\Sanitized\\officer-demo.exe\" --safe-test",
    "parent": {
      "entity_id": null,
      "pid": 1000,
      "name": "powershell.exe"
    },
    "hash": {
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }
}
```

The identifiers shown above are illustrative. Real `evt_` and `proc_` values
are deterministic SHA-256-derived identities, not repeated placeholder digits.

## Repository layout

```text
include/panopticon/officer/   Public agent contracts
src/core/                     Stable identity implementation
src/pipeline/                 Normalization and JSON boundary
schema/                       Versioned Panopticon JSON contract
tests/                        Sanitized Phase 1 contract tests
tools/query/                  Historical Sysmon diagnostic utility
docs/architecture/            Phase designs and boundaries
docs/adr/                     Architecture decision records
```

## Privacy and safety

Endpoint telemetry can contain usernames, command lines, paths, URLs, network
addresses, and secrets. Never commit raw XML, NDJSON, EVTX files, or captured
production telemetry. Repository fixtures and examples must remain sanitized.

The original EyeTrace Query v0.1 implementation is preserved by the Git tag
`eyetrace-query-v0.1`.
