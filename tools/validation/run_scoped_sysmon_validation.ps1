param(
    [Parameter(Mandatory=$true)][string]$ProbePath,
    [Parameter(Mandatory=$true)][string]$EvidenceParent,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Normal Windows elevation required.' }
$probe = (Resolve-Path -LiteralPath $ProbePath).Path
$parent = (Resolve-Path -LiteralPath $EvidenceParent).Path
if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ne $ExpectedSha256 -or $SourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'Source/build binding invalid.' }
$sysmon = Join-Path $env:windir 'Sysmon64.exe'
if (-not (Test-Path -LiteralPath $sysmon)) { throw 'Existing installed Sysmon64 required; this script never installs it.' }
$run = Join-Path $parent ('sysmon-scoped-policy-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
[void][IO.Directory]::CreateDirectory($run)
$channelBefore = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
function Read-Configuration([string]$stem) {
    $out = Join-Path $run ($stem + '.txt'); $err = Join-Path $run ($stem + '-stderr.txt')
    $process = Start-Process -FilePath $sysmon -ArgumentList '-c' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    if ($process.ExitCode -ne 0) { throw 'Installed Sysmon configuration query failed.' }
    # Sysmon writes UTF-16LE without BOM when redirected on this host.
    $bytes = [IO.File]::ReadAllBytes($out)
    $text = if ($bytes.Length -gt 1 -and $bytes[1] -eq 0) { [Text.Encoding]::Unicode.GetString($bytes) } else { [Text.Encoding]::UTF8.GetString($bytes) }
    [IO.File]::WriteAllText((Join-Path $run ($stem + '-utf8.txt')), $text, [Text.UTF8Encoding]::new($false))
    return $text
}
function Apply-Configuration([string]$path,[string]$stem) {
    $arguments = '-c "' + $path + '"'
    $process = Start-Process -FilePath $sysmon -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $run ($stem + '.txt')) -RedirectStandardError (Join-Path $run ($stem + '-stderr.txt'))
    if ($process.ExitCode -ne 0) { throw "Sysmon configuration operation failed: $stem" }
}
$before = Read-Configuration 'configuration-before'
$required = @('No rules installed','HashingAlgorithms:\s+SHA256','Network connection:\s+disabled','Image loading:\s+disabled','CRL checking:\s+enabled','DNS lookup:\s+enabled')
foreach ($pattern in $required) { if ($before -notmatch $pattern) { throw 'Baseline differs from the reviewed no-rules/SHA256 configuration; no changes made.' } }
$baseline = @'
<Sysmon schemaversion="4.91">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering/>
</Sysmon>
'@
$escapedImage = [Security.SecurityElement]::Escape($probe)
$validation = @"
<Sysmon schemaversion="4.91">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="owned-validation-remote-thread" groupRelation="or">
      <CreateRemoteThread onmatch="include"><SourceImage condition="is">$escapedImage</SourceImage></CreateRemoteThread>
    </RuleGroup>
    <RuleGroup name="owned-validation-process-access" groupRelation="or">
      <ProcessAccess onmatch="include"><SourceImage condition="is">$escapedImage</SourceImage></ProcessAccess>
    </RuleGroup>
    <RuleGroup name="owned-validation-dns" groupRelation="or">
      <DnsQuery onmatch="include"><Image condition="is">$escapedImage</Image></DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@
$baselinePath = Join-Path $run 'baseline-restoration.xml'
$validationPath = Join-Path $run 'scoped-validation.xml'
[IO.File]::WriteAllText($baselinePath,$baseline,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($validationPath,$validation,[Text.UTF8Encoding]::new($false))
$changed = $false; $restored = $false; $capturePassed = $false; $failure = $null
try {
    # Baseline is known and restoration bytes are durable before the mutation.
    $changed = $true
    Apply-Configuration $validationPath 'apply-validation'
    [void](Read-Configuration 'configuration-during')
    $captureScript = Join-Path $PSScriptRoot 'run_sysmon_extended_live_probe.ps1'
    $captureArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $captureScript + '" -ProbePath "' + $probe + '" -EvidenceParent "' + $run + '" -ExpectedSha256 ' + $ExpectedSha256 + ' -SourceCommit ' + $SourceCommit
    $captureProcess = Start-Process -FilePath (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $captureArguments -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $run 'capture-console.txt') -RedirectStandardError (Join-Path $run 'capture-console-stderr.txt')
    $nested = Get-ChildItem -LiteralPath $run -Directory -Filter 'sysmon-extended-live-*' | Select-Object -First 1
    if ($nested) {
        $capture = Get-Content -LiteralPath (Join-Path $nested.FullName 'manifest.json') -Raw | ConvertFrom-Json
        $capturePassed = $capture.status -eq 'passed' -and @($capture.verified_event_ids).Count -eq 3
    }
} catch { $failure = $_.Exception.Message }
finally {
    if ($changed) {
        try {
            Apply-Configuration $baselinePath 'restore-baseline'
            $after = Read-Configuration 'configuration-after'
            foreach ($pattern in $required) { if ($after -notmatch $pattern) { throw 'Restored Sysmon settings differ from the baseline.' } }
            $restored = $true
        } catch { $failure = 'RESTORATION FAILURE: ' + $_.Exception.Message }
    }
    $channelAfter = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
    $permissionsUnchanged = [string]$channelBefore.SecurityDescriptor -ceq [string]$channelAfter.SecurityDescriptor -and $channelBefore.IsEnabled -eq $channelAfter.IsEnabled
    $manifest = @{
        status=$(if ($capturePassed -and $restored -and $permissionsUnchanged -and -not $failure) { 'passed' } else { 'failed' });
        source_commit=$SourceCommit;probe_sha256=$ExpectedSha256;synthetic=$false;
        temporary_policy_applied=$changed;reviewed_no_rules_settings_restored=$restored;
        channel_permissions_unchanged=$permissionsUnchanged;capture_passed=$capturePassed;
        configuration_path_changed=$changed;configuration_change_events_expected=$true;
        host=$env:COMPUTERNAME;capture_directory=$(if ($nested) {$nested.FullName} else {$null});error=$failure
    }
    [IO.File]::WriteAllText((Join-Path $run 'manifest.json'),($manifest | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
if ($failure -or -not $capturePassed -or -not $restored -or -not $permissionsUnchanged) { throw 'Scoped validation or baseline restoration failed; inspect preserved evidence.' }
