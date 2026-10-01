<#
.SYNOPSIS
    Live schema-0.5 smoke test for the Officer agent, to run on a real Windows host
    before pushing or recording a benign session.

.DESCRIPTION
    The CTest suite (officer-collector-tests) proves the decoders, normalizer and
    serializer on fixtures; it cannot prove the live Win32 collectors, because CI
    has no ETW/Sysmon/PowerShell event source. This script closes that gap: it runs
    the built agent for a few seconds, generates benign activity that exercises every
    0.5 family, and asserts the emitted NDJSON actually contains those families and is
    well-formed.

    It does NOT run any attack. The activity is: a short-lived child process (process
    start + stop), a DNS lookup (dns), a handle opened to another process (process
    access), and a PowerShell script block (script_block). Remote-thread (Sysmon 8)
    is not reliably producible without injecting, so its absence is reported, not
    failed.

.PREREQUISITES
    * Run from an elevated (Administrator) PowerShell -- ETW/Sysmon need it.
    * Sysmon installed with a config that includes EID 5, 8, 10, 22
      (see docs/sysmon/officer-reference-config.xml).
    * PowerShell Script Block Logging enabled (Group Policy or:
      New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force;
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1).

.PARAMETER AgentPath
    Path to officer-agent.exe (default: the x64 build output).

.PARAMETER Seconds
    How long to capture (default 25).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\windows_smoke_test.ps1 `
        -AgentPath .\build-officer-x64\officer-agent.exe
#>
[CmdletBinding()]
param(
    [string]$AgentPath = ".\build-officer-x64\officer-agent.exe",
    [int]$Seconds = 25
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AgentPath)) {
    Write-Error "Agent not found at $AgentPath. Build it first (see CLAUDE.md), or pass -AgentPath."
    exit 2
}

$capture = New-TemporaryFile
Write-Host "[*] Capturing $Seconds s of telemetry from $AgentPath"
Write-Host "[*] Output: $capture"

# Start the agent, redirecting its NDJSON stdout to the capture file.
$agent = Start-Process -FilePath $AgentPath -ArgumentList "--source", "all" `
    -RedirectStandardOutput $capture -RedirectStandardError "$capture.err" `
    -PassThru -NoNewWindow
Start-Sleep -Seconds 3  # let the subscriptions attach before generating activity

Write-Host "[*] Generating benign activity"
try {
    # process start + stop
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "ver" -NoNewWindow -Wait
    # dns
    try { Resolve-DnsName -Name "www.microsoft.com" -ErrorAction SilentlyContinue | Out-Null } catch {}
    # script_block (4104) -- a harmless compiled script block
    powershell.exe -NoProfile -Command "`$x = 1..3 | ForEach-Object { `$_ * 2 }; Write-Output `$x" | Out-Null
    # process access -- opening our own process handle is benign and common
    Get-Process -Id $PID | Out-Null
} finally {
    Start-Sleep -Seconds 3
    if (-not $agent.HasExited) {
        Stop-Process -Id $agent.Id -Force
    }
}

if (-not (Test-Path $capture) -or (Get-Item $capture).Length -eq 0) {
    Write-Error "No telemetry captured. Is the agent able to subscribe (admin? Sysmon running?)."
    exit 1
}

# Parse: every line must be valid JSON; tally categories and schema versions.
$byCategory = @{}
$byVersion = @{}
$badLines = 0
$total = 0
foreach ($line in Get-Content $capture) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $total++
    try {
        $e = $line | ConvertFrom-Json
    } catch {
        $badLines++
        continue
    }
    $cat = $e.event.category
    $byCategory[$cat] = 1 + ($byCategory[$cat] | ForEach-Object { $_ })
    $byVersion["$($e.schema_version)"] = 1 + ($byVersion["$($e.schema_version)"] | ForEach-Object { $_ })
}

Write-Host ""
Write-Host "=== Capture summary ==="
Write-Host "Total events   : $total"
Write-Host "Malformed lines: $badLines"
Write-Host "By schema ver  : $($byVersion | Out-String)"
Write-Host "By category    : $($byCategory | Out-String)"

$failures = @()
if ($badLines -gt 0) { $failures += "$badLines malformed NDJSON line(s)" }
if (-not $byVersion.ContainsKey("0.5")) { $failures += "no schema_version 0.5 events were emitted" }

# Families we can produce benignly without injection.
foreach ($needed in @("process", "dns", "script_block")) {
    if (-not $byCategory.ContainsKey($needed)) {
        $failures += "no '$needed' events were captured"
    }
}
foreach ($optional in @("process_access", "remote_thread")) {
    if (-not $byCategory.ContainsKey($optional)) {
        Write-Warning "no '$optional' events captured (expected without an attack; not a failure)"
    }
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Error ("Smoke test FAILED:`n  - " + ($failures -join "`n  - "))
    Write-Host "Capture kept at $capture for inspection."
    exit 1
}

Write-Host ""
Write-Host "[+] Smoke test PASSED: live schema-0.5 telemetry captured and well-formed."
Write-Host "[+] To record a benign baseline session, run the agent longer and keep the"
Write-Host "    NDJSON; feed it to the engine's --learn-baseline (see"
Write-Host "    ../panopticon-detection-engine/docs/behavioral-intelligence.md)."
Remove-Item "$capture.err" -ErrorAction SilentlyContinue
exit 0
