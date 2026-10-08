[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Status','Diagnose','PrepareInstall','Start','Stage','Snapshot','Restore')][string]$Action,
    [string]$BuildDirectory,
    [string]$SnapshotName = 'endpoint-clean-baseline',
    [switch]$AllowMemoryPressure
)
$ErrorActionPreference = 'Stop'
$vboxTool = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$validationRoot = 'C:\Users\Acer\Documents\Panopticon-Windows-Validation'
$vmId = '0bebee33-f9a3-462c-afa5-0df1f04e68d0'
$image = Join-Path $validationRoot 'images\Windows11-Enterprise-LTSC-26100.1742-en-us.iso'
$vmDirectory = Join-Path $validationRoot 'vms\panopticon-windows-validation'
function Invoke-VBox([string[]]$Arguments) {
    & $vboxTool @Arguments
    if ($LASTEXITCODE -ne 0) { throw "VirtualBox operation failed: $($Arguments[0]) ($LASTEXITCODE)" }
}
$info = & $vboxTool showvminfo $vmId --machinereadable
if ($LASTEXITCODE -ne 0 -or $info -notcontains 'name="panopticon-windows-validation"') { throw 'Dedicated VM identity mismatch; no other VM may be modified' }
switch ($Action) {
    'Status' {
        $info | Select-String 'VMState=|memory=|cpus=|firmware=|nic1=|ostype=' | ForEach-Object { $_.Line }
        [pscustomobject]@{HostAvailableMiB=[math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024); RequiredAvailableMiB=5120; ImageReady=(Test-Path -LiteralPath $image)}
    }
    'Diagnose' {
        # Readiness evidence only. No credentials, memory/register dumps,
        # debugger clock queries, resets, or changes to another guest.
        $evidence = Join-Path $validationRoot ('diagnostics\run-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
        $samples = @()
        foreach ($sampleIndex in @(0,1)) {
            if ($sampleIndex -ne 0) { Start-Sleep -Seconds 30 }
            $sampleInfo = & $vboxTool showvminfo $vmId --machinereadable
            if ($LASTEXITCODE -ne 0) { throw 'Owned VM state observation failed; no recovery action taken' }
            $selectedInfo = @($sampleInfo | Where-Object { $_ -match '^(name|VMState|VMStateChangeTime|memory|cpus|GuestAdditionsRunLevel|GuestAdditionsVersion|effparavirtprovider|graphicscontroller|accelerate3d)=' })
            $statsText = & $vboxTool debugvm $vmId statistics --pattern '/Public/Storage/*' 2>&1
            $statsExit = $LASTEXITCODE
            $counters = @()
            if ($statsExit -eq 0) {
                [xml]$statsXml = $statsText -join "`n"
                $counters = @($statsXml.Statistics.Counter | Where-Object { $_.name -match '^/Public/Storage/.+/(BytesRead|BytesWritten|ReqsRead|ReqsWrite|ReqsSucceeded)$' } | ForEach-Object {
                    [pscustomobject]@{Name=[string]$_.name;Value=[string]$_.c;Unit=[string]$_.unit}
                })
            }
            $os = Get-CimInstance Win32_OperatingSystem
            $pageFiles = @(Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage)
            $samples += [pscustomobject]@{ObservedUtc=[DateTime]::UtcNow.ToString('o');Machine=$selectedInfo;StorageQueryExit=$statsExit;StorageCounters=$counters;
                HostAvailableMiB=[math]::Floor($os.FreePhysicalMemory/1024);PageFiles=$pageFiles}
        }
        $frame = Join-Path $evidence 'frame.png'
        & $vboxTool controlvm $vmId screenshotpng $frame 2>&1 | Out-Null
        $frameExit = $LASTEXITCODE
        $guestProperties = & $vboxTool guestproperty enumerate $vmId 2>&1
        $propertiesExit = $LASTEXITCODE
        $selectedProperties = @($guestProperties | Where-Object { $_ -match '^/VirtualBox/(GuestAdd/(Version|Revision|RunLevel)|GuestInfo/OS/(Product|Release|Version)|VMInfo/(ResetCounter|ResumeCounter))\s' } | ForEach-Object { [string]$_ })
        # Log snippets deliberately exclude configuration/unattended arguments.
        $log = Join-Path $vmDirectory 'Logs\VBox.log'
        $diagnosticLog = @(Get-Content -LiteralPath $log -Tail 200 | Where-Object { $_ -match 'TM: Giving up catch-up|VERR_VM_THREAD_NOT_EMT|Changing the VM state|Machine state changed|Guest Additions information report' })
        [pscustomobject]@{VM=$vmId;Samples=$samples;ScreenshotExit=$frameExit;GuestPropertiesExit=$propertiesExit;GuestProperties=$selectedProperties;
            DiagnosticLog=$diagnosticLog;GuestInstallationVerified=$false;EndpointValidationVerified=$false;
            Interpretation='Storage counters and VM state are observations, not proof of guest readiness. Clock-debugger assertions may originate from diagnostics and do not prove a Windows failure.'} |
            ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $evidence 'report.json') -Encoding UTF8
        Get-ChildItem -LiteralPath $evidence -File | Get-FileHash -Algorithm SHA256 | Select-Object @{Name='File';Expression={[IO.Path]::GetFileName($_.Path)}},Hash |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'SHA256.json') -Encoding UTF8
        Write-Output $evidence
    }
    'PrepareInstall' {
        if ($info -notcontains 'VMState="poweroff"') { throw 'Installation preparation requires powered-off owned VM' }
        if (!(Test-Path -LiteralPath $image)) { throw 'Official Microsoft image download incomplete' }
        $credentials = Join-Path $validationRoot 'credentials'
        New-Item -ItemType Directory -Path $credentials -Force | Out-Null
        $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($sid in @($userSid,(New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'),(New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $credentials -AclObject $acl
        $passwordFile = Join-Path $credentials 'guest-password.txt'
        if (!(Test-Path -LiteralPath $passwordFile)) {
            $random = New-Object byte[] 24
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($random) } finally { $rng.Dispose() }
            [IO.File]::WriteAllText($passwordFile,([Convert]::ToBase64String($random)+'Aa1!'),(New-Object Text.UTF8Encoding($false)))
        }
        Invoke-VBox -Arguments @('unattended','install',$vmId,"--iso=$image",'--user=panopticonlab',"--user-password-file=$passwordFile", "--admin-password-file=$passwordFile",
            '--full-user-name=Panopticon Validation','--hostname=panopticon-win.lab','--locale=en_US','--country=US','--time-zone=UTC','--install-additions',
            "--auxiliary-base-path=$credentials\Unattended-",'--start-vm=none') | Out-Null
        Write-Output 'Dedicated guest unattended installation prepared; credentials retained in protected local directory.'
    }
    'Start' {
        # Latest user policy permits Linux and Windows concurrently. Never
        # modify another guest; retain the owned four-vCPU/4096 MiB allocation.
        if ($info -contains 'VMState="running"') { Write-Output 'Owned Windows VM already running'; break }
        $available = [math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024)
        if ($available -lt 5120 -and !$AllowMemoryPressure) { throw "Host resource gate: $available MiB available; need 5120 MiB for 4096 MiB guest plus host headroom. Use -AllowMemoryPressure for the user-authorized concurrent configuration. Other VMs are never stopped." }
        Invoke-VBox -Arguments @('startvm',$vmId,'--type','headless')
    }
    'Stage' {
        if (!$BuildDirectory) { throw 'Stage requires fresh Release build directory' }
        $build = (Resolve-Path -LiteralPath $BuildDirectory).Path
        if (!(Select-String -LiteralPath (Join-Path $build 'CMakeCache.txt') -Pattern '^CMAKE_BUILD_TYPE:STRING=Release$' -Quiet)) { throw 'Debug runtime binaries cannot be packaged for guests' }
        $stage = Join-Path $validationRoot ('staging\build-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
        Get-ChildItem -LiteralPath $build -File -Filter 'officer-*.exe' | Copy-Item -Destination $stage
        Copy-Item -LiteralPath (Join-Path $build 'tinyxml2.dll') -Destination $stage
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_guest_validation.ps1') -Destination $stage
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'validate_windows_service.ps1') -Destination $stage
        $runtime = Join-Path $validationRoot 'staging\vc_redist.x64.exe'
        $signature = Get-AuthenticodeSignature -LiteralPath $runtime
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'VC runtime publisher signature must be valid Microsoft' }
        Copy-Item -LiteralPath $runtime -Destination $stage
        Get-ChildItem -LiteralPath $stage -File | Get-FileHash -Algorithm SHA256 | Select-Object @{Name='File';Expression={[IO.Path]::GetFileName($_.Path)}},Hash | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'SHA256.json') -Encoding UTF8
        Write-Output $stage
    }
    'Snapshot' {
        if ($info -notcontains 'VMState="poweroff"') { throw 'Cold baseline snapshot requires powered-off owned VM' }
        Invoke-VBox -Arguments @('snapshot',$vmId,'take',$SnapshotName,'--description','Validated cold baseline; export run evidence before reverting')
    }
    'Restore' {
        if ($info -notcontains 'VMState="poweroff"') { throw 'Restore requires powered-off owned VM; export run evidence first' }
        Invoke-VBox -Arguments @('snapshot',$vmId,'restore',$SnapshotName)
    }
}
