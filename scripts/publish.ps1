<#
.SYNOPSIS
    Publishes the service and desktop application as self-contained win-x64 builds into artifacts\publish.
.DESCRIPTION
    Self-contained publishing means target machines need no separately installed .NET runtime.
    Output layout (consumed by the installer):
        artifacts\publish\service\   NetGuard.Service.exe and dependencies
        artifacts\publish\desktop\   NetGuard.Desktop.exe and dependencies
        artifacts\publish\docs\      README, security and limitation documents, policy schema
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Output = (Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts\publish')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }

$common = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', "-p:Version=$Version", '-p:DebugType=embedded', '-nologo')

dotnet publish (Join-Path $root 'src\NetGuard.Service\NetGuard.Service.csproj') @common -o (Join-Path $Output 'service')
if ($LASTEXITCODE) { throw 'Publishing the service failed.' }

dotnet publish (Join-Path $root 'src\NetGuard.Desktop\NetGuard.Desktop.csproj') @common -o (Join-Path $Output 'desktop')
if ($LASTEXITCODE) { throw 'Publishing the desktop application failed.' }

$docs = New-Item -ItemType Directory -Force (Join-Path $Output 'docs')
Copy-Item (Join-Path $root 'README.md') $docs
Copy-Item (Join-Path $root 'docs\*.md') $docs
Copy-Item (Join-Path $root 'schemas\netguard-policy.v1.schema.json') $docs

Write-Host "Published NetGuard Enterprise $Version to $Output"
