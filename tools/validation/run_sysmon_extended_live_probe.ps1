param(
    [Parameter(Mandatory=$true)][string]$ProbePath,
    [Parameter(Mandatory=$true)][string]$EvidenceParent,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Normal Windows elevation required.' }
if ($SourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'A full source commit is required.' }
$probe = (Resolve-Path -LiteralPath $ProbePath).Path
$parent = (Resolve-Path -LiteralPath $EvidenceParent).Path
if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Probe build hash mismatch.' }
$channel = 'Microsoft-Windows-Sysmon/Operational'
$before = Get-WinEvent -ListLog $channel
if (-not $before.IsEnabled) { throw 'Sysmon channel disabled; no configuration changes will be made.' }
$query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
$query.ReverseDirection = $true
$reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
try { $record = $reader.ReadEvent([TimeSpan]::FromSeconds(1)); if ($record) { $record.Dispose() } } finally { $reader.Dispose() }
$run = Join-Path $parent ('sysmon-extended-live-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$started = [DateTime]::UtcNow.ToString('o')
try {
    & $probe $run *> (Join-Path $parent 'sysmon-extended-live-console.log')
    $probeExit = $LASTEXITCODE
    if ($probeExit -ne 0 -and $probeExit -ne 3) { throw "Native probe failed ($probeExit); inspect $run" }
    $report = Get-Content -Raw -LiteralPath (Join-Path $run 'report.json') | ConvertFrom-Json
    $records = @(Get-Content -Raw -LiteralPath (Join-Path $run 'canonical-records.json') | ConvertFrom-Json | Where-Object { $null -ne $_ })
    $verified = @()
    foreach ($entry in $records) {
        $recordId = [string]$entry.provenance.native_record_id
        if ($recordId -notmatch '^\d+$') { throw 'Missing or invalid source record ID.' }
        $nativeEvent = Get-WinEvent -LogName $channel -FilterXPath "*[System[EventRecordID=$recordId]]" -MaxEvents 1
        $xmlText = $nativeEvent.ToXml(); [xml]$xml = $xmlText
        $eventId = [int]$xml.Event.System.EventID
        if ($eventId -notin @(8,10,22)) { throw 'Unexpected native event family.' }
        $fields = @{}
        foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
        $actorName = if ($eventId -eq 22) { 'ProcessId' } else { 'SourceProcessId' }
        if ([string]$fields[$actorName] -ne [string]$report.probe_pid) { throw 'Native actor is not this probe.' }
        if ($eventId -ne 22 -and [string]$fields.TargetProcessId -ne [string]$report.owned_child_pid) { throw 'Native target is not the owned child.' }
        $facts = $entry.data.source_facts.windows_event_data
        if (@($facts.PSObject.Properties).Count -ne $fields.Count) { throw 'Source field count mismatch.' }
        foreach ($name in $fields.Keys) {
            if ([string]$facts.$name -cne [string]$fields[$name]) { throw "Native field mismatch: $name" }
        }
        [IO.File]::WriteAllText((Join-Path $run ("native-event-$eventId.xml")), $xmlText, [Text.UTF8Encoding]::new($false))
        $verified += $eventId
    }
    $after = Get-WinEvent -ListLog $channel
    if ([string]$after.SecurityDescriptor -cne [string]$before.SecurityDescriptor -or $after.IsEnabled -ne $before.IsEnabled) {
        throw 'Channel permissions or enablement changed during validation.'
    }
    $hashes = @{}
    $installedSysmon = Join-Path $env:windir 'Sysmon64.exe'
    if (Test-Path -LiteralPath $installedSysmon) {
        # -c without a filename only displays the current configuration.
        & $installedSysmon -c *> (Join-Path $run 'installed-sysmon-configuration.txt')
    }
    Get-ChildItem -LiteralPath $run -File | ForEach-Object { $hashes[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    $manifest = [ordered]@{
        status=$report.status; synthetic=$false; source_commit=$SourceCommit; probe_sha256=$ExpectedSha256;
        capture_started_utc=$started; capture_completed_utc=[DateTime]::UtcNow.ToString('o');
        verified_event_ids=$verified; missing_event_ids=@($report.missing_event_ids);
        original_source_fields_compared_exactly=($verified.Count -gt 0); verified_record_count=$verified.Count;
        journal_restart_exact=$report.journal_restart_exact;
        read_access_verified=$true; channel_permissions_unchanged=$true; service_or_policy_changed=$false;
        artifacts=$hashes
    }
    [IO.File]::WriteAllText((Join-Path $run 'manifest.json'), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    exit $probeExit
} catch {
    if (Test-Path -LiteralPath $run) {
        [IO.File]::WriteAllText((Join-Path $run 'capture-failure.json'), (@{status='failed';error=$_.Exception.Message} | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    throw
}
