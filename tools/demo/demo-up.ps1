<#
.SYNOPSIS
  Panopticon one-command demo bring-up, run from the Windows presentation host.

.DESCRIPTION
  Orchestrates the full live stack (plan §5 / W6):
    1. SSH to the manager VM and run tools/demo_up.sh behind nginx.
    2. Parse demo_up.sh output: console URL, manager URL, bootstrap-token path, agent command.
    3. Pull the bootstrap token from the manager and push it into the guest.
    4. Fresh-enroll + start the agent in the guest (new identity file, new spool dir).
    5. Poll demo_check.sh until green (<= 60 s from cold per DoD).
    6. Open the console URL.

  PRECONDITION (manual, per runbook): both VMs powered on and the guest logged in.

  STATUS: scaffold. Output parsing (step 2) and the exact agent flags (step 4) are
  finalized once panopticon-manager publishes demo_up.sh on demo/live-integration
  and MAC_STATUS.md posts "ready <sha>". Marked TODO(mac-contract) below.
#>
[CmdletBinding()]
param(
  [string] $ManagerHost   = '10.77.10.10',
  [string] $ManagerUser   = 'pano',
  [string] $SshKey        = 'C:\PanopticonLab\Keys\lab_ed25519',
  [string] $ManagerRepo   = '/opt/panopticon/panopticon-manager',   # TODO(mac-contract): confirm deploy path
  [string] $Bind          = '127.0.0.1:8000',
  [string] $StateDir      = '',                                     # set by W4 decision (fresh DB NOT on /dev/sdb)
  [string] $GuestHelper   = 'C:\PanopticonLab\tools-vm\guest.py',
  [string] $AgentExe      = 'C:\pano\officer-agent.exe',            # deployed binary (W2 output or v0.3.0 fallback)
  [string] $GuestSpool    = 'C:\pano\spool-demo',                   # NEW spool dir (W5)
  [string] $GuestIdentity = 'C:\pano\identity',                     # fresh identity (W5: deleted beforehand)
  [string] $GuestKeypair  = 'C:\pano\agent.key',
  [string] $GuestTokenPath= 'C:\pano\bootstrap.token',
  [switch] $WhatIf
)

$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[demo-up] $m" -ForegroundColor Cyan }
function Warn($m){ Write-Host "[demo-up] $m" -ForegroundColor Yellow }
function Die($m){ Write-Host "[demo-up] ERROR: $m" -ForegroundColor Red; exit 1 }

$ssh = @('-i', $SshKey, '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', "$ManagerUser@$ManagerHost")
function Ssh([string]$cmd){ & ssh @ssh $cmd }

# --- 1. Bring up the manager stack ---------------------------------------
Info "Starting manager stack on $ManagerHost (demo_up.sh --bind $Bind)"
$stateArg = if ($StateDir) { "--state-dir $StateDir" } else { '' }
$upCmd = "cd $ManagerRepo && tools/demo_up.sh --bind $Bind --fresh $stateArg"
if ($WhatIf) { Warn "WhatIf: would run over ssh: $upCmd" } else {
  $out = Ssh $upCmd
  $out | ForEach-Object { Write-Host "  mgr> $_" -ForegroundColor DarkGray }
  # TODO(mac-contract): parse these from demo_up.sh step-8 output.
  $script:ConsoleUrl = ($out | Select-String -Pattern 'console url[: ]+(\S+)' -AllMatches | ForEach-Object { $_.Matches.Groups[1].Value } | Select-Object -First 1)
  $script:TokenPath  = ($out | Select-String -Pattern 'bootstrap token[: ]+(\S+)' -AllMatches | ForEach-Object { $_.Matches.Groups[1].Value } | Select-Object -First 1)
  if (-not $ConsoleUrl) { Warn "could not parse console URL from demo_up.sh output (confirm contract)" }
}

# --- 2. Verify readiness before touching the agent -----------------------
Info "Waiting for demo_check.sh green"
if (-not $WhatIf) {
  $deadline = (Get-Date).AddSeconds(60); $green = $false
  while ((Get-Date) -lt $deadline) {
    $chk = Ssh "cd $ManagerRepo && tools/demo_check.sh"; $code = $LASTEXITCODE
    if ($code -eq 0) { $green = $true; break }
    Start-Sleep 3
  }
  if (-not $green) { Die "demo_check.sh not green within 60 s" }
}

# --- 3. Push bootstrap token into the guest ------------------------------
Info "Delivering bootstrap token to guest ($GuestTokenPath)"
if (-not $WhatIf) {
  $token = (Ssh "cat $TokenPath").Trim()
  if (-not $token) { Die "empty bootstrap token from manager" }
  $tmp = Join-Path $env:TEMP 'bootstrap.token'
  Set-Content -Path $tmp -Value $token -NoNewline -Encoding ascii
  & python $GuestHelper put $tmp $GuestTokenPath
  Remove-Item $tmp -Force
}

# --- 4. Fresh-enroll + start the agent in the guest ----------------------
Info "Starting agent in guest (fresh enrollment, new spool $GuestSpool)"
# W5: identity file deleted + new spool dir so enrollment is fresh (avoids 409/401).
$agentArgs = @(
  "--source all",
  "--manager-url https://$ManagerHost",
  "--enable-response",
  "--bootstrap-token-path $GuestTokenPath",
  "--identity-path $GuestIdentity",
  "--keypair-path $GuestKeypair",
  "--spool-directory $GuestSpool"
) -join ' '
$guestPs = @"
Remove-Item '$GuestIdentity' -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path '$GuestSpool' | Out-Null
Start-Process -FilePath '$AgentExe' -ArgumentList '$agentArgs' -WindowStyle Hidden -RedirectStandardError 'C:\pano\agent-demo.err.log'
Start-Sleep 3
'agent_pid=' + @(Get-Process officer-agent -ErrorAction SilentlyContinue).Id
"@
if ($WhatIf) { Warn "WhatIf: guest agent cmd: $AgentExe $agentArgs" } else { & python $GuestHelper ps $guestPs }

# --- 5. Confirm records flowing + open console ---------------------------
Info "Confirming ingest (demo_check.sh) and opening console"
if (-not $WhatIf) {
  Ssh "cd $ManagerRepo && tools/demo_check.sh" | ForEach-Object { Write-Host "  chk> $_" -ForegroundColor DarkGray }
  if ($ConsoleUrl) { Start-Process $ConsoleUrl } else { Warn "open the console manually (URL not parsed)" }
}
Info "demo-up complete. Run demo-triggers.ps1 inside the guest to fire the scenarios."
