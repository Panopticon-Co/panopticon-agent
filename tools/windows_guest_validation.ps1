[CmdletBinding()]
param([string]$PackagePath = $PSScriptRoot, [switch]$ExercisePersistenceFixtures,
    [ValidateSet('etw','sysmon','all')][string]$ProcessSource = 'etw', [switch]$ExerciseProcessLifecycle, [switch]$ExerciseFileFixtures)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'PANOPTICON-WIN') { throw 'Guest validation is restricted to the dedicated Windows guest' }
if ($ExerciseProcessLifecycle -and $ProcessSource -eq 'sysmon') { throw 'Native FILETIME lifecycle fixture requires the ETW source' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest native validation requires an elevated administrator token' }
# Keep each original process handle before waiting. Windows PowerShell 5.1
# Start-Process can otherwise return a null managed ExitCode after WaitForExit.
# Never reopen a process by PID to obtain a validation result.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PanopticonGuestProcessResult {
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetExitCodeProcess(IntPtr process, out uint code);
}
'@
function Get-OwnedExitCode([IntPtr]$Handle) {
    [uint32]$code = 0
    if (![PanopticonGuestProcessResult]::GetExitCodeProcess($Handle,[ref]$code)) {
        throw "Owned process result query failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    return $code
}
$destination = Join-Path $env:ProgramData ('PanopticonValidation\run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $destination -ErrorAction Stop | Out-Null
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$manifest = Get-Content -LiteralPath (Join-Path $package 'SHA256.json') -Raw | ConvertFrom-Json
foreach ($entry in $manifest) {
    if ([IO.Path]::GetFileName($entry.File) -ne $entry.File) { throw 'Invalid package filename' }
    if ((Get-FileHash -LiteralPath (Join-Path $package $entry.File) -Algorithm SHA256).Hash -ne $entry.Hash) { throw "Package hash mismatch: $($entry.File)" }
}
Get-ChildItem -LiteralPath $package -File | Copy-Item -Destination $destination
$runtime = Join-Path $destination 'vc_redist.x64.exe'
$signature = Get-AuthenticodeSignature -LiteralPath $runtime
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Untrusted runtime installer' }
$installer = Start-Process -FilePath $runtime -ArgumentList '/install','/quiet','/norestart' -WindowStyle Hidden -PassThru
$installerHandle = $installer.Handle
if (!$installer.WaitForExit(180000)) { $installer.Kill(); $installer.WaitForExit(); throw 'Owned runtime installer timeout' }
$installerCode = Get-OwnedExitCode $installerHandle
if ($installerCode -notin @(0,1638,3010)) { throw "Runtime prerequisite failed: $installerCode" }
$results = @()
# These execute real OS response safety, durability, native state and log tests;
# destructive response/host isolation is restricted to later disposable clones.
foreach ($name in @('officer-usn-journal-tests','officer-process-graph-tests','officer-device-guard-tests','officer-windows-event-log-tests','officer-journal-tests','officer-process-action-tests','officer-response-runtime-tests',
    'officer-process-inventory-tests','officer-thread-inventory-tests','officer-memory-inventory-tests','officer-service-inventory-tests','officer-driver-inventory-tests','officer-host-inventory-tests',
    'officer-socket-inventory-tests','officer-route-inventory-tests','officer-ip-interface-inventory-tests','officer-defender-status-tests','officer-security-center-tests',
    'officer-persistence-inventory-tests','officer-identity-inventory-tests','officer-software-inventory-tests','officer-service-host-tests','officer-process-lifecycle-tests','officer-state-freshness-tests')) {
    $out = Join-Path $destination ($name + '.stdout.txt'); $err = Join-Path $destination ($name + '.stderr.txt')
    if ($name -eq 'officer-usn-journal-tests') {
        $test = Start-Process -FilePath (Join-Path $destination ($name+'.exe')) -ArgumentList '--require-live','--report',(Join-Path $destination 'usn-component-report.json') -WorkingDirectory $destination -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    } elseif ($name -eq 'officer-memory-inventory-tests') {
        $test = Start-Process -FilePath (Join-Path $destination ($name+'.exe')) -ArgumentList '--report',(Join-Path $destination 'memory-component-report.json') -WorkingDirectory $destination -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    } else {
        $test = Start-Process -FilePath (Join-Path $destination ($name+'.exe')) -WorkingDirectory $destination -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    }
    $testHandle = $test.Handle
    $timedOut = !$test.WaitForExit(90000)
    if ($timedOut) { $test.Kill(); $test.WaitForExit() }
    $results += [pscustomobject]@{Test=$name;ExitCode=(Get-OwnedExitCode $testHandle);TimedOut=$timedOut}
    $results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'component-results.json') -Encoding UTF8
    if ($timedOut) { throw "Owned guest test timeout: $name; partial component evidence retained" }
}
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'component-results.json') -Encoding UTF8
$taskName = 'PanopticonValidation-' + [Guid]::NewGuid().ToString('N')
$fixtureKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$fixtureCreated = $false
if ($ExercisePersistenceFixtures) {
    # Dedicated guest only: disabled task plus inert registry text. Neither is
    # executed. Native collector must retain exact definitions, not just count.
    if ($env:COMPUTERNAME -ne 'PANOPTICON-WIN') { throw 'Persistence fixture mutation is restricted to the dedicated Windows guest' }
    $settings = New-ScheduledTaskSettingsSet -Disable -Hidden -DisallowDemandStart
    $definition = New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'C:\PanopticonValidation\never-execute.exe' -Argument $taskName) -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $definition -ErrorAction Stop | Out-Null
    try {
        if (!(Test-Path -LiteralPath $fixtureKey)) { New-Item -Path $fixtureKey -ErrorAction Stop | Out-Null }
        New-ItemProperty -Path $fixtureKey -Name $taskName -Value ('C:\PanopticonValidation\never-execute.exe ' + $taskName) -PropertyType String -ErrorAction Stop | Out-Null
        $fixtureCreated = $true
    } catch { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false; throw }
}
$spool = Join-Path $destination 'spool'
$agent = $null
$lifecycleFixture = $null
$lifecycleExpected = $null
$fileFixtureExpected = $null
try {
    $agent = Start-Process -FilePath (Join-Path $destination 'officer-agent.exe') -ArgumentList '--source',$ProcessSource,'--spool-directory',$spool -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $destination 'agent.ndjson') -RedirectStandardError (Join-Path $destination 'agent.stderr.txt')
    Start-Sleep -Seconds 5
    if ($ExerciseFileFixtures) {
        # Only unique owned files inside this dedicated validation directory.
        $fileToken='PanopticonFileFixture-'+[Guid]::NewGuid().ToString('N')
        $fileBefore=Join-Path $destination ($fileToken+'-before.txt')
        $fileAfter=Join-Path $destination ($fileToken+'-after.txt')
        try {
            [IO.File]::WriteAllText($fileBefore,'benign native USN fixture')
            Set-Content -LiteralPath $fileBefore -Stream 'panopticon-fixture' -Value 'benign named stream fixture' -Encoding ASCII -NoNewline
            Move-Item -LiteralPath $fileBefore -Destination $fileAfter -ErrorAction Stop
            Remove-Item -LiteralPath $fileAfter -ErrorAction Stop
            $fileFixtureExpected=[pscustomobject]@{BeforeName=[IO.Path]::GetFileName($fileBefore);AfterName=[IO.Path]::GetFileName($fileAfter);Completed=$true}
            $fileFixtureExpected | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'usn-fixture-expected.json') -Encoding UTF8
        } finally {
            foreach($ownedPath in @($fileBefore,$fileAfter)){if(Test-Path -LiteralPath $ownedPath){Remove-Item -LiteralPath $ownedPath -ErrorAction Stop}}
        }
    }
    if ($ExerciseProcessLifecycle) {
        # A bounded native executable, with its process handle retained. Record
        # creation FILETIME before exit; never verify a stop by PID alone.
        $lifecycleFixture = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\ping.exe') -ArgumentList '-n','4','127.0.0.1' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $destination 'lifecycle-fixture.stdout.txt') -RedirectStandardError (Join-Path $destination 'lifecycle-fixture.stderr.txt')
        $lifecycleHandle = $lifecycleFixture.Handle
        $lifecycleExpected = [pscustomobject]@{Pid=$lifecycleFixture.Id;CreationTicks=$lifecycleFixture.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture);ExitCode=$null;Completed=$false}
        $lifecycleExpected | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'lifecycle-expected.json') -Encoding UTF8
        if (!$lifecycleFixture.WaitForExit(10000)) { throw 'Owned native lifecycle fixture did not exit within its bound' }
        $lifecycleExpected.ExitCode=Get-OwnedExitCode $lifecycleHandle; $lifecycleExpected.Completed=$true
        $lifecycleExpected | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'lifecycle-expected.json') -Encoding UTF8
    }
    Start-Sleep -Seconds 15
    if ($agent.HasExited) { throw 'Guest endpoint exited before runtime capture completed' }
} finally {
    if ($lifecycleFixture -and !$lifecycleFixture.HasExited) { $lifecycleFixture.Kill(); $lifecycleFixture.WaitForExit() }
    if ($agent -and !$agent.HasExited) { $agent.Kill(); $agent.WaitForExit() }
    if ($fixtureCreated) {
        Remove-ItemProperty -LiteralPath $fixtureKey -Name $taskName -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    }
}
$recoveredPath = Join-Path $destination 'recovered-records.ndjson'
$reopenPath = Join-Path $destination 'reopened-records.ndjson'
foreach ($outputPath in @($recoveredPath,$reopenPath)) {
    $probe = Start-Process -FilePath (Join-Path $destination 'officer-host-inventory-tests.exe') -ArgumentList '--read-spool-lines',$spool -WindowStyle Hidden -PassThru -RedirectStandardOutput $outputPath -RedirectStandardError ($outputPath+'.stderr.txt')
    $probeHandle=$probe.Handle
    if (!$probe.WaitForExit(120000)) { $probe.Kill(); $probe.WaitForExit(); throw 'Owned guest streaming recovery timeout' }
    if ((Get-OwnedExitCode $probeHandle) -ne 0) { throw 'Abrupt-exit guest streaming spool recovery failed' }
}
if ((Get-FileHash -LiteralPath $recoveredPath).Hash -ne (Get-FileHash -LiteralPath $reopenPath).Hash) { throw 'Guest journal originals changed on second reopen' }
$historyPaths=@((Join-Path $destination 'process-history.ndjson'),(Join-Path $destination 'process-history-reopened.ndjson'))
foreach ($historyPath in $historyPaths) {
    $historyProbe=Start-Process -FilePath (Join-Path $destination 'officer-host-inventory-tests.exe') -ArgumentList '--read-process-history-lines',$spool -WindowStyle Hidden -PassThru -RedirectStandardOutput $historyPath -RedirectStandardError ($historyPath+'.stderr.txt')
    $historyHandle=$historyProbe.Handle
    if (!$historyProbe.WaitForExit(120000)) { $historyProbe.Kill(); $historyProbe.WaitForExit(); throw 'Owned guest process archive readback timeout' }
    if ((Get-OwnedExitCode $historyHandle) -ne 0) { throw 'Guest process archive readback failed' }
}
if ((Get-FileHash -LiteralPath $historyPaths[0]).Hash -ne (Get-FileHash -LiteralPath $historyPaths[1]).Hash) { throw 'Guest process archive originals changed on reopen' }
$historyCount=0; $archivedFixtureStops=0
foreach ($historyLine in [IO.File]::ReadLines($historyPaths[0])) {
    $historyRecord=$historyLine | ConvertFrom-Json; ++$historyCount
    if ($lifecycleExpected -and $historyRecord.category -eq 'process_stop' -and $historyRecord.provenance.kind -eq 'etw' -and
        $historyRecord.data.process.pid -eq $lifecycleExpected.Pid -and $historyRecord.data.process.start_time_ticks -eq $lifecycleExpected.CreationTicks) { ++$archivedFixtureStops }
}
$selectedRecords = New-Object 'System.Collections.Generic.List[object]'
$recordCount = 0; $logCount = 0
$lifecycleStops = New-Object 'System.Collections.Generic.List[object]'
$usnFixtureRows = New-Object 'System.Collections.Generic.List[object]'
foreach ($line in [IO.File]::ReadLines($recoveredPath)) {
    $record = $line | ConvertFrom-Json; ++$recordCount
    if ($record.category -eq 'windows_event_log') { ++$logCount }
    if ($fileFixtureExpected -and $record.category -eq 'filesystem_usn_batch') {
        foreach($entry in $record.data.entries){
            if($entry.filename -in @($fileFixtureExpected.BeforeName,$fileFixtureExpected.AfterName)){
                $usnFixtureRows.Add([pscustomobject]@{RecordId=$record.record_id;Volume=$record.data.volume;JournalId=$record.data.journal_id;Entry=$entry})
            }
        }
    }
    if ($lifecycleExpected -and $record.category -eq 'process_stop' -and $record.provenance.kind -eq 'etw' -and
        $record.data.process.pid -eq $lifecycleExpected.Pid -and $record.data.process.start_time_ticks -eq $lifecycleExpected.CreationTicks) {
        $lifecycleStops.Add($record)
    }
    if ($record.kind -eq 'health' -or $record.category -match '^(thread_inventory|memory_region_inventory|device_guard_state|scheduled_task_inventory|wmi_subscription_inventory|startup_inventory|account_inventory|local_group_inventory|logon_session_inventory|terminal_session_inventory|msi_product_inventory|uninstall_registry_inventory)') { $selectedRecords.Add($record) }
}
$lifecycleVerified = $false
$retainedGraphVerified = $false
$nativeFieldStates = @{}
$nativeSequenceLifecycleConsistent = $false
if ($ExerciseProcessLifecycle) {
    $lifecycleVerified = $lifecycleExpected.Completed -and $lifecycleStops.Count -eq 1 -and $archivedFixtureStops -eq 1 -and
        $lifecycleStops[0].data.lifecycle.exit_code -eq [string]$lifecycleExpected.ExitCode -and
        [decimal]$lifecycleStops[0].data.lifecycle.termination_time_ticks -ge [decimal]$lifecycleExpected.CreationTicks -and
        $null -ne $lifecycleStops[0].data.process.entity_id -and
        $lifecycleStops[0].data.process.entity_id -eq $lifecycleStops[0].subject.entity_id
    [pscustomobject]@{Expected=$lifecycleExpected;MatchingNativeStops=$lifecycleStops.ToArray();Verified=[bool]$lifecycleVerified;
        Scope='One live owned ETW process stop with exact PID plus native creation FILETIME and exit code; no claim of complete lifecycle continuity or ancestry'} |
        ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $destination 'lifecycle-report.json') -Encoding UTF8
    if ($lifecycleVerified) {
        $native=$lifecycleStops[0].data.source_facts.process.native_fields
        if (!$native -or $native.format -ne 'windows_etw_process_fields_v1' -or $native.event_id -ne 2 -or
            $native.parent_instance_verified -or $native.sequence_alias_promotion_performed -or
            $native.full_native_payload_retained -or @($native.fields.PSObject.Properties).Count -ne 19) {
            throw 'Guest selected native field scope missing or overclaimed'
        }
        foreach ($property in $native.fields.PSObject.Properties) {
            $field=$property.Value
            if ($field.value_interpreted -or $field.state -notin @('healthy','unsupported','unavailable')) { throw 'Guest native scalar state invalid' }
            if ($field.state -eq 'healthy') {
                if ($null -eq $field.value -or $field.native_status -ne '0' -or $field.reported_bytes -notin @(4,8) -or
                    $field.value -notmatch '^(0|[1-9][0-9]{0,19})$') { throw 'Guest native scalar carrier/read evidence invalid' }
            } elseif ($null -ne $field.value) { throw 'Guest refused native scalar has a value' }
            if (!$nativeFieldStates.ContainsKey($field.state)) {$nativeFieldStates[$field.state]=0}
            ++$nativeFieldStates[$field.state]
        }
        $births=@([IO.File]::ReadLines($historyPaths[0]) | ForEach-Object {$_ | ConvertFrom-Json} |
            Where-Object {$_.category -eq 'process' -and $_.subject.entity_id -eq $lifecycleStops[0].subject.entity_id})
        if ($births.Count -eq 1 -and $native.fields.ProcessSequenceNumber.state -eq 'healthy' -and
            $births[0].data.source_facts.process.native_fields.fields.ProcessSequenceNumber.state -eq 'healthy') {
            if ($native.fields.ProcessSequenceNumber.value -ne $births[0].data.source_facts.process.native_fields.fields.ProcessSequenceNumber.value) {
                throw 'Owned native lifecycle sequence values conflict'
            }
            $nativeSequenceLifecycleConsistent=$true
        }
        $graphPath=Join-Path $destination 'process-ancestry.json'
        $rootEntity=$lifecycleStops[0].subject.entity_id
        $graphProbe=Start-Process -FilePath (Join-Path $destination 'officer-process-graph-tests.exe') -ArgumentList '--read-ancestry',$spool,$rootEntity -WindowStyle Hidden -PassThru -RedirectStandardOutput $graphPath -RedirectStandardError ($graphPath+'.stderr.txt')
        $graphHandle=$graphProbe.Handle
        if (!$graphProbe.WaitForExit(120000)) { $graphProbe.Kill(); $graphProbe.WaitForExit(); throw 'Owned guest graph query timeout' }
        if ((Get-OwnedExitCode $graphHandle) -ne 0) { throw 'Guest retained graph query failed' }
        $graph=Get-Content -LiteralPath $graphPath -Raw | ConvertFrom-Json
        $root=@($graph.nodes | Where-Object entity_id -EQ $rootEntity)
        if ($graph.format -ne 'process_ancestry_v1' -or $graph.source_coverage_complete -or
            $graph.creator_relationship_verified -or $graph.alias_promotion_performed -or
            $root.Count -ne 1 -or !$root[0].stop_observed -or $null -ne $root[0].liveness -or
            @($root[0].evidence | Where-Object record_id -EQ $lifecycleStops[0].record_id).Count -ne 1) {
            throw 'Guest retained exact lifecycle graph evidence missing or overclaimed'
        }
        $retainedGraphVerified=$true
    }
}
$records = $selectedRecords.ToArray()
$deviceGuardCaptures = @($records | Where-Object category -EQ 'device_guard_state')
$deviceGuardHealth = @($records | Where-Object { $_.kind -eq 'health' -and $_.data.device_guard_state.last_committed_record_id })
if ($deviceGuardCaptures.Count -ne 1 -or !$deviceGuardHealth.Count) { throw 'Guest durable Device Guard capture/health evidence missing' }
$deviceGuard = $deviceGuardCaptures[0]
if ($deviceGuard.data.format -ne 'device_guard_state_v1' -or $deviceGuard.data.inventory_complete -or
    $deviceGuard.data.protection_verified -or $deviceGuard.data.policy_authority_verified -or
    $deviceGuard.data.collection_deadline_enforced -or $deviceGuard.data.native_allocation_bounded) { throw 'Guest Device Guard source scope overclaim' }
foreach ($binding in $deviceGuardHealth) {
    $bound = $binding.data.device_guard_state
    if ($bound.last_committed_record_id -ne $deviceGuard.record_id -or
        $bound.capture_freshness.record_id -ne $deviceGuard.record_id -or
        $bound.capture_freshness.state -ne 'healthy' -or
        ($bound.last_committed_query_status | ConvertTo-Json -Depth 32 -Compress) -ne ($deviceGuard.data | ConvertTo-Json -Depth 32 -Compress) -or
        [decimal]$bound.last_committed_capture_started_uptime_ms -gt [decimal]$deviceGuard.data.collection_started_uptime_ms -or
        [decimal]$deviceGuard.data.collection_started_uptime_ms -gt [decimal]$deviceGuard.data.collection_completed_uptime_ms -or
        [decimal]$deviceGuard.data.collection_completed_uptime_ms -gt [decimal]$bound.last_committed_uptime_ms) { throw 'Guest Device Guard record/body/clock binding failed' }
}
[pscustomobject]@{Scope='Native guest provider capture, durable abrupt-exit recovery and exact committed health binding';
    Captures=$deviceGuardCaptures.Count;HealthBindings=$deviceGuardHealth.Count;ProviderState=$deviceGuard.data.state;
    ProviderRows=@($deviceGuard.data.entries).Count;EffectiveProtectionVerified=$false;FullQualification=$false} |
    ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $destination 'device-guard-report.json') -Encoding UTF8
$health = @($records | Where-Object { $_.kind -eq 'health' -and $_.data.windows_event_log })
if (!$logCount -or !$health.Count) { throw 'Guest runtime log/coverage evidence missing' }
$captureResults = @()
if ($ExerciseFileFixtures) {
    [uint32]$beforeReasons=0; [uint32]$afterReasons=0
    foreach($row in $usnFixtureRows){
        if($row.Entry.filename -eq $fileFixtureExpected.BeforeName){$beforeReasons=$beforeReasons -bor [uint32]::Parse($row.Entry.reason_mask)}
        else {$afterReasons=$afterReasons -bor [uint32]::Parse($row.Entry.reason_mask)}
    }
    $fileVerified=($beforeReasons -band 0x100) -and ($beforeReasons -band 0x70) -and ($beforeReasons -band 0x1000) -and ($afterReasons -band 0x2000) -and ($afterReasons -band 0x200)
    [pscustomobject]@{Expected=$fileFixtureExpected;MatchingRows=$usnFixtureRows.ToArray();BeforeReasonMask=$beforeReasons;AfterReasonMask=$afterReasons;Verified=[bool]$fileVerified;ActorAttributionVerified=$false;FullFileCoverageVerified=$false} | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $destination 'usn-runtime-fixture-report.json') -Encoding UTF8
    if(!$fileVerified){throw 'Owned runtime USN create/ADS/rename/delete fixture not observed; originals retained'}
}
foreach ($source in @('thread_inventory','memory_region_inventory','scheduled_task_inventory','wmi_subscription_inventory','startup_inventory','account_inventory','local_group_inventory','logon_session_inventory','terminal_session_inventory','msi_product_inventory','uninstall_registry_inventory')) {
    $capture = @($records | Where-Object category -EQ $source)
    if ($capture.Count -ne 1) { throw "Missing or ambiguous guest persistence capture: $source" }
    $pages = @($records | Where-Object { $_.category -eq ($source + '_page') -and $_.data.capture_id -eq $capture[0].data.capture_id })
    $entryCount = 0
    foreach ($pageId in $capture[0].data.page_record_ids) {
        $page = @($pages | Where-Object record_id -EQ $pageId)
        if ($page.Count -ne 1) { throw 'Guest persistence page assembly failure' }
        $entryCount += $page[0].data.entries.Count
    }
    if ([string]$entryCount -ne $capture[0].data.entries_delivered -or $capture[0].data.inventory_complete) { throw 'Guest persistence accounting or scope failure' }
    if ($source -eq 'memory_region_inventory') {
        $memoryRows=@($pages | ForEach-Object { $_.data.entries } | Where-Object { $_.entry_kind -eq 'memory_region' })
        if (!$memoryRows.Count -or @($memoryRows | Where-Object { $_.content_read -or $_.injection_verified -or $null -ne $_.mapping_instance_identity }).Count) { throw 'Guest memory inventory scope/evidence missing or overclaimed' }
    }
    $captureResults += [pscustomobject]@{Source=$source;Entries=$entryCount;State=$capture[0].data.state;EnumerationComplete=$capture[0].data.enumeration_complete;QueryFailures=$capture[0].data.query_failure_count}
}
if ($ExercisePersistenceFixtures) {
    $tasks = @($records | Where-Object category -EQ 'scheduled_task_inventory_page' | ForEach-Object { $_.data.entries } | Where-Object { $_.fields.name.value -eq $taskName })
    $startup = @($records | Where-Object category -EQ 'startup_inventory_page' | ForEach-Object { $_.data.entries } | Where-Object { $_.value_name -eq $taskName })
    if ($tasks.Count -ne 1 -or $tasks[0].fields.enabled.value -ne $false -or $tasks[0].fields.definition_xml.value -notmatch [regex]::Escape($taskName) -or !$startup.Count) { throw 'Owned native persistence fixture evidence missing' }
}
[pscustomobject]@{OS=(Get-CimInstance Win32_OperatingSystem).Caption;Build=[Environment]::OSVersion.Version.ToString();RecordCount=$recordCount;NativeLogRecords=$logCount;
    HealthRecords=$health.Count;PersistenceCaptures=$captureResults;PersistenceFixturesExercised=[bool]$ExercisePersistenceFixtures;
    ProcessSource=$ProcessSource;ProcessLifecycleExercised=[bool]$ExerciseProcessLifecycle;ProcessStopVerified=[bool]$lifecycleVerified;
    ProcessHistoryRecords=$historyCount;ArchivedFixtureStops=$archivedFixtureStops;DeviceGuardCaptures=$deviceGuardCaptures.Count;
    RetainedExactLifecycleGraphVerified=[bool]$retainedGraphVerified;PositiveParentAncestryVerified=$false;
    OwnedStopNativeFieldStates=$nativeFieldStates;NativeSequenceLifecycleConsistent=[bool]$nativeSequenceLifecycleConsistent;
    DeviceGuardHealthBindings=$deviceGuardHealth.Count;
    EvidenceDirectory=$destination;FullQualification=$false} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $destination 'runtime-report.json') -Encoding UTF8
if ($ExerciseProcessLifecycle -and !$lifecycleVerified) { throw 'Live guest ETW stop identity/exit evidence failed; original records and report retained' }
if (@($results | Where-Object ExitCode -NE 0).Count) { throw 'Guest component validation failures; evidence retained' }
Write-Output $destination
