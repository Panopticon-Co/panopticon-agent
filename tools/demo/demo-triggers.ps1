<#
.SYNOPSIS
  Panopticon live-demo trigger harness. Runs harmless commands in the Windows
  guest that each map to a known detection rule, with the benign control first.

.DESCRIPTION
  Run INSIDE the guest (PANO-NEW-WIN-01), elevated, while the agent is delivering
  to the manager. Each step prints an ISO-8601 UTC timestamp so time-to-alert can
  be measured against the alert's received time (W7).

  Contract (plan §6) — expected rule IDs:
    0  benign control (notepad + bare whoami) .... NO alert
    1  whoami /priv ................................ DET-PROC-008  (medium)
    2  schtasks /create + /delete ................. DET-PERS-002
    3  cmdkey /list ............................... DET-CRED-003  (high; KILL staged, not auto-run)
    4  certutil -urlcache -split -f ............... DET-PROC-003  (maybe DET-NET-006 / campaign)
    5  reg add Run + reg delete ................... DET-PERS-001  (needs Sysmon EID 13)

  Pass bar: steps 1-3 (plan numbering 2-4) produce alerts in the console within
  15 s; the benign control produces none.

.PARAMETER Only
  Comma-separated step numbers to run (e.g. -Only 0,1). Default: all.

.PARAMETER PauseSeconds
  Seconds to wait between steps so alerts can surface. Default 20.
#>
[CmdletBinding()]
param(
  [int[]] $Only = @(0,1,2,3,4,5),
  [int]   $PauseSeconds = 20
)

$ErrorActionPreference = 'Continue'

function Stamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
function Step($n, $label, $expect) {
  Write-Host ""
  Write-Host ("[{0}] STEP {1}: {2}" -f (Stamp), $n, $label) -ForegroundColor Cyan
  Write-Host ("        expect: {0}" -f $expect) -ForegroundColor DarkGray
}
function Pause { param($why) Write-Host ("        ...waiting {0}s ({1})" -f $PauseSeconds, $why) -ForegroundColor DarkGray; Start-Sleep -Seconds $PauseSeconds }

Write-Host ("Panopticon demo triggers — host {0} — start {1}" -f $env:COMPUTERNAME, (Stamp)) -ForegroundColor Green

# -------- Step 0: benign control (MUST produce no alert) --------
if ($Only -contains 0) {
  Step 0 'benign control: notepad.exe (launch+close) then bare whoami' 'NO alert'
  $np = Start-Process notepad.exe -PassThru
  Start-Sleep 2
  if ($np -and -not $np.HasExited) { Stop-Process -Id $np.Id -Force -ErrorAction SilentlyContinue }
  & whoami | Out-Host
  Pause 'confirm no alert appears'
}

# -------- Step 1: whoami /priv -> DET-PROC-008 --------
if ($Only -contains 1) {
  Step 1 'whoami /priv' 'DET-PROC-008 (medium)'
  & whoami /priv | Out-Host
  Pause 'alert should appear'
}

# -------- Step 2: scheduled task create+delete -> DET-PERS-002 --------
if ($Only -contains 2) {
  Step 2 'schtasks /create PanopticonDemo then /delete' 'DET-PERS-002'
  & schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f | Out-Host
  Start-Sleep 2
  & schtasks /delete /tn PanopticonDemo /f | Out-Host
  Pause 'alert should appear'
}

# -------- Step 3: cmdkey /list -> DET-CRED-003 --------
if ($Only -contains 3) {
  Step 3 'cmdkey /list' 'DET-CRED-003 (high; KILL_PROCESS staged for analyst approval, NOT auto-run)'
  & cmdkey /list | Out-Host
  Pause 'alert should appear'
}

# -------- Step 4: certutil urlcache download -> DET-PROC-003 --------
if ($Only -contains 4) {
  Step 4 'certutil -urlcache -split -f (harmless connecttest.txt)' 'DET-PROC-003 (maybe DET-NET-006 / campaign); Defender may block the download but the process-create alert still fires'
  $dst = Join-Path $env:TEMP 'ct.txt'
  & certutil -urlcache -split -f http://www.msftconnecttest.com/connecttest.txt $dst | Out-Host
  Remove-Item $dst -Force -ErrorAction SilentlyContinue
  Pause 'alert should appear'
}

# -------- Step 5: Run-key persistence -> DET-PERS-001 (Sysmon EID 13) --------
if ($Only -contains 5) {
  Step 5 'reg add HKCU Run value then reg delete' 'DET-PERS-001 (requires Sysmon EID 13)'
  & reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v PanopticonDemo /t REG_SZ /d notepad.exe /f | Out-Host
  Start-Sleep 2
  & reg delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v PanopticonDemo /f | Out-Host
  Pause 'alert should appear'
}

Write-Host ""
Write-Host ("Panopticon demo triggers — done {0}" -f (Stamp)) -ForegroundColor Green
Write-Host "Verify each alert in the console (severity, title, host, process, time) and that step 0 created none." -ForegroundColor Yellow
