# EyeTrace Query

EyeTrace Query is a beginner-focused C++20 command-line reader for **recorded**
Sysmon process-creation events. It will query Windows Event Log, render the
source XML, parse selected Event ID 1 fields, and write normalized NDJSON.

## Status

Milestone 1 establishes a native Windows build. The program does not query
events yet.

## Milestone 1 prerequisites

- Windows 11 x64
- Visual Studio 2026 with the **Desktop development with C++** workload
- CMake 3.20 or later

This workspace's CMake comes with Visual Studio. In a Developer PowerShell for
Visual Studio, configure, build, and run with:

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Debug
.\build\Debug\eyetrace-query.exe
```

If `cmake` is not on `PATH`, use Visual Studio's bundled executable:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' -S . -B build -G "Visual Studio 18 2026" -A x64
```

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

Windows 11 x64 VM, Visual Studio Community 2026, MSVC 14.51. Sysmon was not
installed when the project was initialized, so live Event ID 1 retrieval is
not yet verifiable.

## Privacy

Sysmon telemetry can contain sensitive command lines, paths, and usernames.
Never commit raw telemetry. Only sanitized fixtures and sample output belong in
this repository.
