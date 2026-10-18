<#
.SYNOPSIS
    Removes a developer installation of the NetGuard service and, unless -KeepRules is given, the firewall rules it owns.
#>
[CmdletBinding()]
param([switch]$KeepRules)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (administrator) PowerShell prompt.'
}

$service = Get-CimInstance Win32_Service -Filter "Name='NetGuardService'"
if (-not $service) { Write-Host 'NetGuardService is not installed.'; return }

$exe = $service.PathName.Trim('"')
Stop-Service NetGuardService -ErrorAction SilentlyContinue
if (-not $KeepRules) {
    # Removes only rules carrying NetGuard's ownership marker; other rules are never touched.
    & $exe cleanup-rules
}
sc.exe delete NetGuardService | Out-Null
Write-Host 'NetGuardService removed.'
