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

## Current status: Phase 2

Phase 2 connects two independent live Windows sources to the Phase 1 contracts.
Both publish source-neutral process facts, then the agent normalizes and prints
one compact JSON object per observation.

Implemented now:

- A source-neutral raw process-start contract with source provenance.
- A separate enrichment contract so observed facts are not overwritten.
- Panopticon normalized process event schema `0.2` with source provenance.
- Deterministic event IDs and PID-reuse-safe process entity IDs.
- Windows CNG SHA-256 identity derivation.
- Strict JSON serialization, deserialization, and malformed-input rejection.
- Native Windows ARM64 contract and parser tests.
- Raw Windows ETW subscription to `Microsoft-Windows-Kernel-Process`.
- Live Sysmon subscription through Windows Event Log `EvtSubscribe`.
- Source provenance in Panopticon schema `0.2`.
- Clean Ctrl+C shutdown for both collector lifecycles.
- `officer-query`, the preserved EyeTrace v0.1 historical Sysmon reader.

Not implemented yet:

- The bounded event bus and backpressure handling.
- Durable SQLite spooling or network delivery.
- Windows service installation and lifecycle management.
- Network, file, registry, DNS, image-load, and process-stop payload schemas.

The next phase moves normalization off acquisition callback threads and onto a
bounded queue with explicit health and loss counters.

See [the Phase 2 design](docs/architecture/phase-2-live-collection.md), the
[roadmap](docs/roadmap.md), the
[future ingestion boundary](docs/architecture/detection-ingestion-boundary.md),
[the Phase 1 design](docs/architecture/phase-1-contracts.md), the
[process identity decision](docs/adr/003-process-entity-id.md), and the current
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

- `officer-agent.exe` - the live Phase 2 console agent.
- `officer-collectors.lib` - independent ETW and Sysmon acquisition adapters.
- `officer-core-tests.exe` - identity, normalization, and JSON contract tests.
- `officer-collector-tests.exe` - sanitized source-decoder and interface tests.
- `officer-query.exe` - the historical Sysmon query and diagnostic utility.
- `officer-tests.exe` - sanitized Sysmon parser tests.

## Build and test on Windows x64

Officer's build system is triplet-driven and contains no ARM64-specific or
x64-specific source code, so x64 is built the same way as ARM64 with a
different vcpkg triplet. Run these commands from an **x64 Developer PowerShell
for Visual Studio** (or any shell with `VCToolsInstallDir` set for the x64
host/target via `vcvars64.bat`):

```powershell
cmake -S . -B build-officer-x64 -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows

cmake --build build-officer-x64
ctest --test-dir build-officer-x64 --output-on-failure
```

This has been validated end-to-end on real x64 Windows hardware: vcpkg builds
`nlohmann-json` and `tinyxml2` from source for `x64-windows`, all 6 build
targets compile and link cleanly under MSVC 14.44 with no warnings, and all 7
CTest cases pass. Live ETW/Sysmon capture on x64 requires the same elevated
PowerShell as ARM64 (see below) and has not yet been demonstrated in CI or on
this particular machine — build/test validation and live-capture validation
are tracked separately.

## Run live collection

Open an elevated PowerShell. Start both sources, then launch Notepad from a
second terminal or the Start menu:

```powershell
.\build-officer-arm64\officer-agent.exe --source all   # or build-officer-x64, matching the build you ran
```

```powershell
Start-Process notepad.exe
```

Officer writes status and errors to stderr and one normalized JSON event per
line to stdout. Press Ctrl+C to stop both subscriptions and release the ETW
session. Use `--source etw` or `--source sysmon` to isolate one adapter.

Both sources may report the same process. Their events retain distinct source
provenance and event IDs while converging on one process entity ID when their
timestamps identify the same Windows process.

Elevation is required to control the system ETW session and read the protected
Sysmon channel. If the process is force-killed and leaves the fixed development
session behind, clean it from an elevated terminal with:

```powershell
logman stop Panopticon-Officer-Process -ets
```

## Historical telemetry utility

`officer-query` remains available to retrieve historical events from a running
Sysmon installation. From an elevated PowerShell, query
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

## Example normalized event

The values below are sanitized and formatted for readability. Live output is
compact NDJSON and will reflect the source fields actually available.

```json
{
  "schema_version": "0.2",
  "event": {
    "id": "evt_1111111111111111111111111111111111111111111111111111111111111111",
    "category": "process",
    "type": "start",
    "timestamp": "2026-08-13T20:15:42.123Z"
  },
  "source": {
    "kind": "sysmon",
    "provider": "Microsoft-Windows-Sysmon",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "record_id": 100
  },
  "agent": {
    "id": "agent-sanitized-001",
    "version": "0.2.0"
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
src/collectors/               Independent ETW and Sysmon adapters
src/core/                     Stable identity implementation
src/pipeline/                 Normalization and JSON boundary
schema/                       Versioned Panopticon JSON contract
tests/                        Sanitized contract and collector tests
tools/query/                  Historical Sysmon diagnostic utility
docs/architecture/            Phase designs and boundaries
docs/adr/                     Architecture decision records
```

See [the complete roadmap](docs/roadmap.md) for queues, additional typed event
schemas, enrichment, durable spooling, secure delivery, and Windows service
hardening.

## Privacy and safety

Endpoint telemetry can contain usernames, command lines, paths, URLs, network
addresses, and secrets. Never commit raw XML, NDJSON, EVTX files, or captured
production telemetry. Repository fixtures and examples must remain sanitized.

The original EyeTrace Query v0.1 implementation is preserved by the Git tag
`eyetrace-query-v0.1`.
