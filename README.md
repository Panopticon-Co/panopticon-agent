# EyeTrace Query

EyeTrace Query is a beginner-focused C++20 command-line reader for **recorded**
Sysmon process-creation events. It will query Windows Event Log, render the
source XML, parse selected Event ID 1 fields, and write normalized NDJSON.

## Status

Version 0.1 is implemented. EyeTrace Query retrieves bounded recorded Sysmon
events, renders XML, parses supported telemetry, and emits normalized NDJSON.
It is a historical reader, not a live collector or EDR.

## Milestone 1 prerequisites

- Windows 11 on Arm64
- Visual Studio 2026 with the **Desktop development with C++** workload
- CMake 3.20 or later
- vcpkg (bundled with this Visual Studio installation)

This workspace's CMake comes with Visual Studio. In an Arm64 Developer
PowerShell for Visual Studio, configure and build with:

```powershell
cmake -S . -B build-arm64-vcpkg -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/18/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=arm64-windows
cmake --build build-arm64-vcpkg
```

If `cmake` is not on `PATH`, use Visual Studio's bundled executable:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' -S . -B build-arm64-vcpkg -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/18/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=arm64-windows
```

`vcpkg.json` pins a registry baseline and declares TinyXML2 and nlohmann/json.
CMake's manifest mode installs them into the ignored build directory.

## Supported Sysmon telemetry

| Event ID | Telemetry |
| --- | --- |
| 1 | Process creation |
| 3 | Network connection |
| 11 | File creation |
| 12 | Registry create/delete |
| 13 | Registry value set |
| 14 | Registry rename |

Use `--event-id` to choose one event type. Sysmon must be configured to record
that type; in particular, network connection events are disabled by default.

## NDJSON usage

```powershell
.\build-arm64-vcpkg\eyetrace-query.exe --event-id 1 --limit 3 --output "$env:TEMP\eyetrace.ndjson"
```

The program writes the same NDJSON lines to the console and the optional output
file. `--limit` accepts an integer from 1 to 1000 and defaults to 20. Results
are newest first. Each JSON object has `schema_version`, `timestamp`, `source`,
`host`, `event`, `process`, and `parent` sections. Missing optional values are
JSON `null`; malformed XML or present-but-invalid numeric fields are errors.

Validate each local output line in PowerShell:

```powershell
Get-Content "$env:TEMP\eyetrace.ndjson" | ForEach-Object { $_ | ConvertFrom-Json | Out-Null }
```

To inspect the original XML instead, use `--format xml`. Telemetry is sensitive:
do not commit raw XML or NDJSON files.

Examples for other supported historical data:

```powershell
.\build-arm64-vcpkg\eyetrace-query.exe --event-id 11 --limit 10
.\build-arm64-vcpkg\eyetrace-query.exe --event-id 13 --limit 10
.\build-arm64-vcpkg\eyetrace-query.exe --event-id 3 --limit 10
```

## Exit codes and diagnostics

| Code | Meaning |
| ---: | --- |
| 0 | Successful query and output |
| 2 | Invalid command-line arguments |
| 3 | Windows Event Log acquisition failure |
| 4 | XML or telemetry parsing failure |
| 5 | Output-file failure |

Diagnostics include hints for a missing Sysmon channel, access denied, invalid
Event Log XPath, no matching events, XML parsing failures, and output failures.

## Tests

Run the sanitized parser and CLI validation tests after building:

```powershell
ctest --test-dir build-arm64-vcpkg --output-on-failure
```

Fixtures in `tests/fixtures/` and `docs/sample-output.ndjson` are sanitized.
Never replace them with live telemetry.

## How the first build works

`src/event_log_reader.cpp` includes `windows.h` and `winevt.h`, both supplied
by the Windows SDK installed with Visual Studio. They declare the Windows Event
Log API, including `EvtQuery`, `EvtNext`, and `EvtRender`. `CMakeLists.txt`
links `wevtapi`; on MSVC this selects the SDK import library `wevtapi.lib`,
allowing the linker to resolve those functions to the Windows Event Log
implementation at runtime. TinyXML2 parses rendered XML, and nlohmann/json
serializes the normalized event to NDJSON.

`/W4` enables a useful MSVC warning level, `/permissive-` uses more standard
C++ conformance, `/EHsc` enables normal C++ exception handling, and `/utf-8`
makes source-file encoding predictable.

## Current verification environment

Windows 11 Arm64 VM, Visual Studio Community 2026, MSVC 14.51, and Sysmon
15.21 (`Sysmon64a`) are installed. A user-run native ARM64 Milestone 2 check
retrieved raw Event ID 1 XML successfully. The Codex sandbox itself cannot
read the Sysmon channel because it runs under a separate Windows identity.

## Privacy

Sysmon telemetry can contain sensitive command lines, paths, and usernames.
Never commit raw telemetry. Only sanitized fixtures and sample output belong in
this repository.
