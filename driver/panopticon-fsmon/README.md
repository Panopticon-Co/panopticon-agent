# panopticon-fsmon — Officer filesystem minifilter

`panopticon-fsmon.sys` is the FltMgr minifilter half of Officer's filesystem
sensor. It observes IRP-level file operations and forwards one bounded,
fixed-size record per operation to the user-mode `MinifilterCollector` over a
communication port. The wire contract is the shared header
[`../../include/panopticon/officer/minifilter/fsmon_protocol.hpp`](../../include/panopticon/officer/minifilter/fsmon_protocol.hpp),
compiled by both sides; the driver stamps `PANOPTICON_FSMON_PROTOCOL_VERSION`
and the collector refuses any mismatch.

## Scope and honesty

- **Observe-only.** No create is blocked and no data is altered. Pre callbacks
  emit an *attempt* (`phase=pre`); post callbacks emit the *completion* with the
  real `NTSTATUS` (`phase=post`).
- **Operations covered:** `IRP_MJ_CREATE` (open/create/overwrite, refined in the
  post callback by `FILE_CREATED`/`FILE_OPENED`), `IRP_MJ_WRITE` (attempt only),
  and `IRP_MJ_SET_INFORMATION` (set-information, rename, delete — rename resolves
  the destination via `FltGetDestinationFileNameInformation`).
- **Bounded.** Records come from an NPAGED lookaside list and a spin-lock queue
  capped at 4096 entries. On overflow (or no connected subscriber) the event is
  dropped and a global `dropped` counter advances, so the collector sees an
  explicit `events_lost`/continuity gap rather than silent loss.
- **Actor identity.** Each record carries the acting PID, TID and the actor's
  process *creation time* (100 ns FILETIME ticks via
  `PsGetProcessCreateTimeQuadPart`). The user-mode normalizer joins that native
  creation token to an ETW/Sysmon process start for `native_exact` attribution.
- **Not yet proven live.** Driver load and live interception are **VM-gated and
  test-signed only**. The CMake build compiles only the user-mode decoder and
  collector; the `.sys` is built with the WDK (below). Do not claim live
  filesystem capability from a successful user-mode build alone.

## Build (WDK)

Requires the Windows Driver Kit (validated: 10.0.26100.0) and the matching
Visual Studio C++ kernel toolset. From a WDK-enabled Developer prompt in this
directory:

```powershell
msbuild panopticon-fsmon.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\panopticon-fsmon\panopticon-fsmon.sys` and its `.inf`/`.cat`.

## Test-sign, install and load (VM only)

On the isolated validation VM, with test signing enabled
(`bcdedit /set testsigning on` then reboot):

```powershell
# 1. Create a one-off test certificate and sign the catalog + driver.
.\sign-test.ps1 -DriverDir .\x64\Release\panopticon-fsmon

# 2. Install the minifilter service from the INF (RunAs admin).
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\panopticon-fsmon.inf

# 3. Load it.
fltmc load panopticon-fsmon

# 4. Confirm the attachment and altitude.
fltmc filters
fltmc instances -f panopticon-fsmon
```

Then run the agent so the collector connects to the port:

```powershell
.\officer-agent.exe --source minifilter      # or --source all
```

Unload when finished:

```powershell
fltmc unload panopticon-fsmon
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 .\panopticon-fsmon.inf
```

## Altitude

The INF uses development altitude `385201` in the Activity Monitor band. A real
Microsoft-allocated altitude is required before any non-test deployment.
