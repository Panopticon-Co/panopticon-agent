param(
    [Parameter(Mandatory=$true)][string]$DecoderPath,
    [Parameter(Mandatory=$true)][string]$EvidenceParent,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Normal Windows elevation required.' }
$decoder = (Resolve-Path -LiteralPath $DecoderPath).Path
$parent = (Resolve-Path -LiteralPath $EvidenceParent).Path
if ($SourceCommit -notmatch '^[0-9a-f]{40}$' -or (Get-FileHash -LiteralPath $decoder -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Source/build binding invalid.' }
$before = Get-WinEvent -ListLog Security
$run = Join-Path $parent ('authentication-native-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
[void][IO.Directory]::CreateDirectory($run)
try {
    $ids = @(4624,4625,4634,4648,4672,4768,4769,4776)
    $nativeRecords = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=$ids} -MaxEvents 128)
    $selected = @($nativeRecords | Group-Object Id | ForEach-Object { $_.Group | Select-Object -First 1 })
    $verified = @(); $hashes = @{}
    foreach ($record in $selected) {
        $id = [int]$record.Id
        $xmlText = $record.ToXml(); [xml]$xml = $xmlText
        $xmlPath = Join-Path $run ("native-$id.xml")
        $canonicalPath = Join-Path $run ("canonical-$id.json")
        [IO.File]::WriteAllText($xmlPath, $xmlText, [Text.UTF8Encoding]::new($false))
        & $decoder $xmlPath $canonicalPath
        if ($LASTEXITCODE -ne 0) { throw "Native authentication decode failed for EID $id" }
        $canonical = Get-Content -LiteralPath $canonicalPath -Raw | ConvertFrom-Json
        $auth = $canonical.data.authentication
        if ([string]$canonical.data.rendered_xml -cne $xmlText -or [int]$auth.event_id -ne $id -or
            $null -ne $canonical.subject -or $null -ne $auth.process_instance -or
            $null -ne $auth.logon_session_entity -or $null -ne $canonical.data.event_boot_id) {
            throw 'Native source, actor or historical boot invariant failed.'
        }
        if ([string]$canonical.provenance.native_record_id -ne [string]$record.RecordId) { throw 'Source record ID mismatch.' }
        $fields = @{}
        foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
        $comparisons = @('rendered_xml','event_id','event_record_id','unknown_actor','unknown_event_boot')
        if ($auth.state -ne 'degraded') {
            foreach ($role in @('Subject','Target')) {
                $raw = [string]$fields[($role + 'LogonId')]
                if ($raw -match '^0[xX][0-9a-fA-F]+$') {
                    $expected = [Convert]::ToUInt64($raw.Substring(2),16).ToString([Globalization.CultureInfo]::InvariantCulture)
                    $typedRole = $role.ToLowerInvariant()
                    if ([string]$auth.$typedRole.logon_id -cne $expected) { throw "LUID mismatch: $role" }
                    $comparisons += ($role + 'LogonId')
                }
            }
            if ($fields.ContainsKey('LogonType') -and [string]$auth.logon_type -ne [string]$fields.LogonType) { throw 'Logon type mismatch.' }
            if ($fields.ContainsKey('IpAddress') -and $fields.IpAddress -ne '-' -and $fields.IpAddress -ne '' -and [string]$auth.source.ip -cne [string]$fields.IpAddress) { throw 'Source address mismatch.' }
        }
        $verified += @{event_id=$id;record_id=[string]$record.RecordId;state=$auth.state;compared=$comparisons}
        $hashes[(Split-Path -Leaf $xmlPath)] = (Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash
        $hashes[(Split-Path -Leaf $canonicalPath)] = (Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash
    }
    $after = Get-WinEvent -ListLog Security
    if ([string]$before.SecurityDescriptor -cne [string]$after.SecurityDescriptor -or $before.IsEnabled -ne $after.IsEnabled) { throw 'Security channel state changed.' }
    $manifest = @{
        status='passed';source_commit=$SourceCommit;decoder_sha256=$ExpectedSha256;synthetic=$false;
        capture_mode='retained_native_security_records_not_realtime_subscription';records=$verified;
        requested_event_ids=$ids;selected_record_limit=128;channel_permissions_unchanged=$true;
        audit_or_service_configuration_changed=$false;full_authentication_qualification=$false;artifacts=$hashes
    }
    [IO.File]::WriteAllText((Join-Path $run 'manifest.json'), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
} catch {
    [IO.File]::WriteAllText((Join-Path $run 'capture-failure.json'), (@{status='failed';error=$_.Exception.Message} | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    throw
}
