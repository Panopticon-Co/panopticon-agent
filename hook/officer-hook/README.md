# officer-hook — Officer in-process API instrumentation

`officer-hook.dll` is injected into a monitored process to observe a small,
fixed set of file-related Win32 APIs and report each call to the agent's
`ApiHookCollector` over the named pipe `\\.\pipe\PanopticonOfficerHook`. The
wire contract is the shared header
[`../../include/panopticon/officer/apihook/apihook_protocol.hpp`](../../include/panopticon/officer/apihook/apihook_protocol.hpp),
compiled by both sides.

## What it observes

| API            | Operation | Phase | Notes                                   |
|----------------|-----------|-------|-----------------------------------------|
| `CreateFileW`  | open/create/overwrite (by disposition) | post | carries path + Win32 error |
| `WriteFile`    | write     | pre   | attempt only; handle path not resolved  |
| `DeleteFileW`  | delete    | post  | carries path + Win32 error              |
| `MoveFileExW`  | rename    | post  | destination = path, source = previous   |

Each record carries the hooked process's PID, thread, and creation time. The
collector verifies the PID and creation time **out of band** against the pipe
peer (`GetNamedPipeClientProcessId` + `GetProcessTimes`) and drops any record
whose claimed actor does not match — a record is never emitted on an unverified
identity.

## Mechanism and honest limitations

- **IAT hooking**, not inline trampolines. For each loaded module, the import
  thunk equal to a target API's resolved address is swapped to a detour. This
  cannot corrupt code or crash the host on an unexpected prologue — the trade is
  **coverage**:
  - Calls resolved dynamically via `GetProcAddress`, or issued as direct
    syscalls, are **not** seen.
  - Modules loaded *after* injection are not retro-patched (a periodic re-scan
    could be added; not implemented).
  - `WriteFile` is reported as an attempt without the target path.
- This is an **instrumentation sensor for telemetry, not a security boundary**.
  A hostile process can bypass it. Do not represent it as tamper-proof.
- **VM-gated.** Built and injected only on the isolated validation VM. Not part
  of the agent CMake build; the agent builds only the verified pipe-server
  collector. A successful DLL build does not prove live interception.

## Build (VS / MSBuild)

From an x64 Developer prompt in this directory:

```powershell
msbuild officer-hook.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\officer-hook.dll`.

## Run on the VM

1. Start the agent so the collector serves the pipe:

   ```powershell
   .\officer-agent.exe --source api_hook       # or --source all
   ```

2. Inject into a target process (e.g. a test `notepad.exe`):

   ```powershell
   .\inject.ps1 -Pid <target-pid> -DllPath .\x64\Release\officer-hook.dll
   ```

3. Exercise the target (open/save/delete/rename files) and observe `api_hook`
   records appear in the agent's NDJSON output, attributed to the target PID.
