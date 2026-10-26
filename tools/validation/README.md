# Live Sysmon process-context validation

Build `officer-sysmon-live-probe` in an existing MSVC x64 build directory. This is
an explicitly invoked validation tool, not an automatic CTest or production agent.

From a normal PowerShell session, request standard Windows UAC elevation for the
script with the built executable, an existing evidence parent directory and its
reviewed SHA-256. For example, from the repository root:

```powershell
$probe = (Resolve-Path '.\build-officer-telemetry-release\officer-sysmon-live-probe.exe').Path
$script = (Resolve-Path '.\tools\validation\run_sysmon_live_probe.ps1').Path
$parent = (Resolve-Path '..\..\output').Path
$hash = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash
$commit = git rev-parse HEAD
$arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $script +
    '" -ProbePath "' + $probe + '" -EvidenceParent "' + $parent +
    '" -ExpectedSha256 ' + $hash + ' -SourceCommit ' + $commit
Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
```

The script checks elevation, enabled-channel read access and the executable hash.
The native tool subscribes using `SysmonEventCollector`, creates one uniquely marked
benign `cmd.exe /d /c echo` child with no window, captures its actual EID1, normalizes
it through `EndpointRecordFactory`, and checks byte-identical encrypted-journal
recovery after reopening the journal. It waits at most 20 seconds for the event.

The script independently reads that exact native record ID, compares the child PID
and marker, compares all nine selected source fields with raw XML, and confirms
the channel's security descriptor and enablement are unchanged. It never installs
Sysmon, changes its configuration, weakens channel ACLs, stops the installed Officer
service or sends records/commands to the Manager.

Each new `sysmon-live-*` directory contains `native-event.xml`,
`canonical-record.json`, `report.json`, `manifest.json` and an encrypted `journal/`.
Failure files are retained when available. Full command/account/path fields remain
in local evidence; publish only the safe summary and hashes when appropriate.
`sysmon-live-probe-console.log` in the parent contains the latest probe console
output. The script uses a process-local execution-policy option, not a machine policy
change. Envelope identity is probe-local, not production enrollment or a verified
ETW/Sysmon native-instance alias. A successful single-event capture does not qualify
capture recall, all Sysmon families, VM compatibility or Manager/ML integration.

## Interactions and DNS

Build `officer-sysmon-extended-live-probe` and invoke
`run_sysmon_extended_live_probe.ps1` with the same four arguments/UAC pattern.
It creates a child copy of itself, opens a read-only query handle, starts one
thread at the child's existing system `ExitThread` export, and queries
`www.example.com` through DNS. It performs no remote writes or executable
allocations and only terminates its own retained child on cleanup.

The collector captures EIDs 8/10/22 for this probe/child, canonicalizes them,
reopens its encrypted journal, and saves all captured originals. The script
independently compares every EventData field against the exact native record ID
and checks channel permissions/enablement. `status: incomplete` and exit 3 mean
one or more families were not captured under the existing installed policy;
captured families still receive independent XML checks. Missing events are not
declared successful. No Sysmon/service configuration changes are made.
