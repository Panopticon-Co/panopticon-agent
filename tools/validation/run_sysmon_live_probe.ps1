param(
    [Parameter(Mandatory=$true)][string]$ProbePath,
    [Parameter(Mandatory=$true)][string]$EvidenceParent,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Live Sysmon log access requires normal Windows elevation on this host.'
}
$probe = (Resolve-Path -LiteralPath $ProbePath).Path
$parent = (Resolve-Path -LiteralPath $EvidenceParent).Path
if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ne $ExpectedSha256) {
    throw 'Probe executable differs from the reviewed build hash.'
}
if ($SourceCommit -and $SourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'Source commit must be a full Git SHA.' }
$run = Join-Path $parent ('sysmon-live-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$started = [DateTime]::UtcNow.ToString('o')
try {
    $channelBefore = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
    if (-not $channelBefore.IsEnabled) { throw 'Sysmon channel is disabled; validation will not enable it.' }
    $aclBefore = [string]$channelBefore.SecurityDescriptor
    $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
        'Microsoft-Windows-Sysmon/Operational', [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
    $query.ReverseDirection = $true
    $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    try {
        $accessRecord = $reader.ReadEvent([TimeSpan]::FromSeconds(1))
        if ($accessRecord) { $accessRecord.Dispose() }
    } finally { $reader.Dispose() }
    & $probe $run *> (Join-Path $parent 'sysmon-live-probe-console.log')
    if ($LASTEXITCODE -ne 0) { throw "Native live probe failed with exit $LASTEXITCODE; see $run" }
    $report = Get-Content -Raw -LiteralPath (Join-Path $run 'report.json') | ConvertFrom-Json
    if ($report.status -ne 'passed' -or $report.synthetic -ne $false) { throw 'Native live probe did not verify a real capture.' }
    $recordId = [string]$report.native_record_id
    if ($recordId -notmatch '^\d+$') { throw 'Invalid native Event Log record ID.' }
    $source = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventRecordID=$recordId]]" -MaxEvents 1
    $xmlText = $source.ToXml()
    [xml]$xml = $xmlText
    if ([int]$xml.Event.System.EventID -ne 1) { throw 'Captured native record is not EID1.' }
    $native = @{}
    foreach ($field in $xml.Event.EventData.Data) { $native[[string]$field.Name] = [string]$field.'#text' }
    if ([string]$native.ProcessId -ne [string]$report.owned_process_id -or
        -not ([string]$native.CommandLine).Contains([string]$report.marker)) {
        throw 'Native Event Log record does not bind to the owned marked process.'
    }
    foreach ($name in @('ParentCommandLine','IntegrityLevel','OriginalFileName','CurrentDirectory','LogonId','LogonGuid','TerminalSessionId','Hashes','UtcTime')) {
        if (-not $native.ContainsKey($name) -or [string]$report.fields.$name -cne [string]$native[$name]) {
            throw "Canonical field differs from the captured native XML: $name"
        }
    }
    [IO.File]::WriteAllText((Join-Path $run 'native-event.xml'), $xmlText, [Text.UTF8Encoding]::new($false))
    $channelAfter = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
    if ([string]$channelAfter.SecurityDescriptor -cne $aclBefore -or $channelAfter.IsEnabled -ne $channelBefore.IsEnabled) {
        throw 'Channel permissions or enablement changed during validation; unchanged state cannot be claimed.'
    }
    $hashes = @{}
    foreach ($name in @('report.json','canonical-record.json','native-event.xml')) {
        $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $run $name) -Algorithm SHA256).Hash
    }
    $manifest = [ordered]@{
        status='passed'; synthetic=$false; capture_started_utc=$started;
        capture_completed_utc=[DateTime]::UtcNow.ToString('o');
        source='Microsoft-Windows-Sysmon/Operational'; event_id=1;
        native_record_id=$recordId; owned_process_id=$report.owned_process_id;
        probe_sha256=$ExpectedSha256; probe_source_commit=$SourceCommit; fields_compared_exactly=$true;
        journal_restart_exact=$report.journal_restart_exact;
        read_access_verified=$true; channel_permissions_unchanged=$true;
        service_or_channel_configuration_changed=$false; artifacts=$hashes
    }
    [IO.File]::WriteAllText((Join-Path $run 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    exit 0
} catch {
    if (Test-Path -LiteralPath $run) {
        [IO.File]::WriteAllText((Join-Path $run 'capture-failure.json'),
            (@{status='failed'; error=$_.Exception.Message; synthetic=$false} | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    throw
}
