<#
.SYNOPSIS
    Developer install: registers a locally built NetGuard service (LocalSystem) without the MSI.
.DESCRIPTION
    Run from an elevated PowerShell prompt after scripts/build.ps1. Use scripts/uninstall-dev.ps1 to remove it.
    Production deployments should use the signed MSI.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (administrator) PowerShell prompt.'
}

$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root "src\NetGuard.Service\bin\$Configuration\net9.0-windows\NetGuard.Service.exe"
if (-not (Test-Path $exe)) { throw "Service binary not found: $exe. Run scripts/build.ps1 -Configuration $Configuration first." }

if (Get-Service NetGuardService -ErrorAction SilentlyContinue) {
    throw 'NetGuardService already exists. Run scripts/uninstall-dev.ps1 first.'
}

New-Service -Name NetGuardService -BinaryPathName "`"$exe`"" -DisplayName 'NetGuard Enterprise' `
    -Description 'Enforces per-application network policies with Windows Defender Firewall.' -StartupType Automatic | Out-Null
sc.exe failure NetGuardService reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null
Start-Service NetGuardService
Get-Service NetGuardService
