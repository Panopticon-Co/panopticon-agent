# EyeTrace Query

EyeTrace Query is a beginner-focused C++20 command-line reader for **recorded**
Sysmon process-creation events. It will query Windows Event Log, render the
source XML, parse selected Event ID 1 fields, and write normalized NDJSON.

## Status

Milestone 3 is implemented: EyeTrace Query retrieves a bounded number of the
newest recorded Sysmon Event ID 1 records and prints each one as raw XML. XML
parsing and NDJSON output are not implemented yet.

## Milestone 1 prerequisites

- Windows 11 on Arm64
- Visual Studio 2026 with the **Desktop development with C++** workload
- CMake 3.20 or later

This workspace's CMake comes with Visual Studio. In an Arm64 Developer
PowerShell for Visual Studio, configure and build with:

```powershell
cmake -S . -B build-arm64 -G Ninja
cmake --build build-arm64
```

If `cmake` is not on `PATH`, use Visual Studio's bundled executable:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' -S . -B build-arm64 -G Ninja
```

## Raw XML usage (Milestone 3)

```powershell
.\build-arm64\eyetrace-query.exe --limit 3 > "$env:TEMP\eyetrace.xml"
notepad "$env:TEMP\eyetrace.xml"
```

`--limit` accepts an integer from 1 to 1000 and defaults to 20. Results are
newest first. The XML contains sensitive telemetry, so the example writes it
to a temporary file instead of printing it in a shared terminal. Do not commit
the file.

## How the first build works

`src/main.cpp` includes `windows.h` and `winevt.h`, both supplied by the
Windows SDK installed with Visual Studio. They declare the Windows Event Log
API, including the `EvtQuery`, `EvtNext`, and `EvtRender` functions we will add
next. `CMakeLists.txt` links `wevtapi`; on MSVC this selects the SDK import
library `wevtapi.lib`, allowing the linker to resolve those functions to the
Windows Event Log implementation at runtime.

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
