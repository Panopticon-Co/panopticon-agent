[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackagePath)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'PANOPTICON-WIN') { throw 'SCM fixture is restricted to the dedicated Windows validation guest' }
$serviceName = 'PanopticonOfficer'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service already exists; never overwrite another installation' }
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$manifest = Get-Content -LiteralPath (Join-Path $package 'SHA256.json') -Raw | ConvertFrom-Json
foreach ($entry in $manifest) {
    if ([IO.Path]::GetFileName($entry.File) -ne $entry.File) { throw 'Invalid manifest path' }
    if ((Get-FileHash -LiteralPath (Join-Path $package $entry.File)).Hash -ne $entry.Hash) { throw 'Package hash mismatch' }
}
$destination = Join-Path $env:ProgramData ('PanopticonValidation\service-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $destination -ErrorAction Stop | Out-Null
Get-ChildItem -LiteralPath $package -File | Copy-Item -Destination $destination
$exe = Join-Path $destination 'officer-agent.exe'
$spool = Join-Path $destination 'spool'
$identity = Join-Path $destination 'identity.txt'
$command = '"' + $exe + '" --service --source sysmon --spool-directory "' + $spool + '" --identity-path "' + $identity + '"'
$created = $false; $evidence = @()
try {
    New-Service -Name $serviceName -DisplayName 'Panopticon owned validation fixture' -BinaryPathName $command -StartupType Manual -ErrorAction Stop | Out-Null
    $created = $true
    foreach ($iteration in @(1,2)) {
        Start-Service -Name $serviceName
        $service = Get-Service -Name $serviceName
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(60))
        $native = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($native.PathName -ne $command -or $native.StartName -ne 'LocalSystem' -or !$native.ProcessId) { throw 'Service executable/account/process binding mismatch' }
        Start-Sleep -Seconds 20
        $service.Stop() # Native controller request returns before shutdown completes.
        $service.Refresh()
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(60))
        $native = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($native.ExitCode -ne 0 -or $native.ServiceSpecificExitCode -ne 0) { throw 'Endpoint service exited with an error' }
        if (!(Test-Path -LiteralPath (Join-Path $spool 'journal.db'))) { throw 'Service did not create the durable journal' }
        $evidence += [pscustomobject]@{Iteration=$iteration;State=$native.State;ExitCode=$native.ExitCode;ServiceSpecificExitCode=$native.ServiceSpecificExitCode;JournalBytes=(Get-Item -LiteralPath (Join-Path $spool 'journal.db')).Length}
    }
} finally {
    [pscustomobject]@{Scope='owned SCM LocalSystem start-stop-restart fixture';Iterations=$evidence;EvidenceDirectory=$destination;ContentRecoveryVerified=$false;FullQualification=$false} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $destination 'service-report.json') -Encoding UTF8
    if ($created) {
        $native = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($native -and $native.PathName -eq $command -and $native.State -eq 'Stopped') {
            & sc.exe delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning 'Owned stopped service deletion failed; evidence retained' }
        } else { Write-Warning 'Owned service is still active or changed; preserved it without reset, kill or deletion' }
    }
}
Write-Output $destination
