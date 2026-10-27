# Inject officer-hook.dll into a target process by PID (VM only).
#
# Uses the classic CreateRemoteThread + LoadLibraryW technique. This is a
# development/validation helper for the isolated VM, where the agent is already
# serving the officer-hook pipe. It requires the target to resolve the hooked
# APIs through its IAT (see README limitations).
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [int] $Pid,
    [Parameter(Mandatory = $true)] [string] $DllPath
)

$ErrorActionPreference = "Stop"
$full = (Resolve-Path $DllPath).Path
if (-not (Test-Path $full)) { throw "DLL not found: $full" }

$src = @"
using System;
using System.Runtime.InteropServices;
public static class Inject {
    [DllImport("kernel32", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
    [DllImport("kernel32", SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr addr, uint size, uint type, uint prot);
    [DllImport("kernel32", SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr p, IntPtr addr, byte[] buf, uint size, out UIntPtr written);
    [DllImport("kernel32", SetLastError=true)] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32", SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32", SetLastError=true)] public static extern IntPtr CreateRemoteThread(IntPtr p, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, out IntPtr tid);
}
"@
Add-Type -TypeDefinition $src

$PROCESS_ALL = 0x1F0FFF
$MEM_COMMIT_RESERVE = 0x3000
$PAGE_RW = 0x4

$h = [Inject]::OpenProcess($PROCESS_ALL, $false, $Pid)
if ($h -eq [IntPtr]::Zero) { throw "OpenProcess failed for PID $Pid" }

$bytes = [System.Text.Encoding]::Unicode.GetBytes($full + [char]0)
$mem = [Inject]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$bytes.Length, $MEM_COMMIT_RESERVE, $PAGE_RW)
if ($mem -eq [IntPtr]::Zero) { throw "VirtualAllocEx failed" }
[UIntPtr]$written = [UIntPtr]::Zero
[void][Inject]::WriteProcessMemory($h, $mem, $bytes, [uint32]$bytes.Length, [ref]$written)

$load = [Inject]::GetProcAddress([Inject]::GetModuleHandle("kernel32.dll"), "LoadLibraryW")
[IntPtr]$tid = [IntPtr]::Zero
$thread = [Inject]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $load, $mem, 0, [ref]$tid)
if ($thread -eq [IntPtr]::Zero) { throw "CreateRemoteThread failed" }
Write-Host "Injected $full into PID $Pid (remote thread $tid)."
