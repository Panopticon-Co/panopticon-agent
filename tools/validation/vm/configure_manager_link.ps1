param(
    [string]$MacAddress = '00-0C-29-57-96-84',
    [string]$EndpointAddress = '10.77.10.31',
    [string]$ManagerAddress = '10.77.10.10'
)
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter | Where-Object MacAddress -EQ $MacAddress)
if ($adapters.Count -ne 1) { throw 'Expected one VMnet10 adapter with the recorded MAC address' }
$adapter = $adapters[0]
if ($adapter.Status -eq 'Disabled') { $adapter | Enable-NetAdapter -Confirm:$false }
$addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
$configured = @($addresses | Where-Object IPAddress -EQ $EndpointAddress)
if ($configured.Count -eq 0) {
    $otherStatic = @($addresses | Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notlike '169.254.*' })
    if ($otherStatic.Count -gt 0) { throw 'Adapter has another static address; refusing to replace it' }
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $EndpointAddress -PrefixLength 24 | Out-Null
}
$probe = Test-NetConnection -ComputerName $ManagerAddress -Port 443 -InformationLevel Detailed
if (-not $probe.TcpTestSucceeded -or $probe.SourceAddress.IPAddress -ne $EndpointAddress) {
    throw 'Manager HTTPS is not reachable through the assigned VMnet10 source address'
}
[pscustomobject]@{
    InterfaceAlias = $adapter.Name
    MacAddress = $adapter.MacAddress
    SourceAddress = $probe.SourceAddress.IPAddress
    RemoteAddress = $probe.RemoteAddress.ToString()
    Port = $probe.RemotePort
    TcpTestSucceeded = $probe.TcpTestSucceeded
} | ConvertTo-Json -Compress
