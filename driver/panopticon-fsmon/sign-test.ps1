# Test-sign panopticon-fsmon for loading on the isolated validation VM.
#
# This produces a self-signed test certificate and signs the driver and its
# catalog so Windows will load it WHEN TEST SIGNING IS ENABLED. It is not a
# production signature and must never be used off the validation VM.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $DriverDir,
    [string] $CertName = "Panopticon-FsMon-Test",
    [string] $DriverFile = "panopticon-fsmon.sys",
    [string] $CatalogFile = "panopticon-fsmon.cat"
)

$ErrorActionPreference = "Stop"

$sys = Join-Path $DriverDir $DriverFile
$cat = Join-Path $DriverDir $CatalogFile
if (-not (Test-Path $sys)) { throw "Driver not found: $sys (build with the WDK first)" }

# Locate signtool / makecert from the installed WDK/SDK.
$kitRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
$signtool = Get-ChildItem -Path $kitRoot -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) { throw "signtool.exe not found under $kitRoot" }

# Create a test code-signing cert in the local machine store if absent.
$existing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq "CN=$CertName" } | Select-Object -First 1
if (-not $existing) {
    Write-Host "Creating test certificate CN=$CertName"
    $existing = New-SelfSignedCertificate -Subject "CN=$CertName" -Type CodeSigningCert `
        -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1)
    # Trust it on this VM so the signed driver validates.
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite"); $store.Add($existing); $store.Close()
    $pub = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
    $pub.Open("ReadWrite"); $pub.Add($existing); $pub.Close()
}

$thumb = $existing.Thumbprint
Write-Host "Signing $DriverFile with $thumb"
& $signtool sign /v /fd SHA256 /sha1 $thumb /t http://timestamp.digicert.com $sys
if ($LASTEXITCODE -ne 0) { throw "signtool failed on $DriverFile" }

if (Test-Path $cat) {
    Write-Host "Signing catalog $CatalogFile"
    & $signtool sign /v /fd SHA256 /sha1 $thumb /t http://timestamp.digicert.com $cat
    if ($LASTEXITCODE -ne 0) { throw "signtool failed on $CatalogFile" }
}

Write-Host "Done. Ensure 'bcdedit /set testsigning on' and reboot before 'fltmc load panopticon-fsmon'."
