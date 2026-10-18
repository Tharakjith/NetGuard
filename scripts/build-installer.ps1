<#
.SYNOPSIS
    Produces the release MSI: test → publish → sign binaries → build MSI → sign MSI.
.EXAMPLE
    ./scripts/build-installer.ps1 -Version 1.0.0 -Thumbprint 0123ABCD...
    ./scripts/build-installer.ps1 -Version 1.0.0 -Unsigned      # internal test builds only
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Thumbprint,
    [switch]$Unsigned,
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$publish = Join-Path $root 'artifacts\publish'
$installerOut = Join-Path $root 'artifacts\installer'

if (-not $Unsigned -and -not $Thumbprint) {
    throw 'Provide -Thumbprint for a signed release, or -Unsigned for an internal test build.'
}

& (Join-Path $PSScriptRoot 'build.ps1') -Configuration Release -SkipTests:$SkipTests
& (Join-Path $PSScriptRoot 'publish.ps1') -Version $Version -Output $publish

if (-not $Unsigned) {
    & (Join-Path $PSScriptRoot 'sign.ps1') -Path $publish -Thumbprint $Thumbprint
}

dotnet build (Join-Path $root 'installer\NetGuard.Installer.wixproj') -c Release -nologo `
    "-p:PublishRoot=$publish" "-p:ProductVersion=$Version" -o $installerOut
if ($LASTEXITCODE) { throw 'Building the MSI failed.' }

$msi = Join-Path $installerOut "NetGuardEnterprise-$Version-x64.msi"
if (-not $Unsigned) {
    & (Join-Path $PSScriptRoot 'sign.ps1') -Path $msi -Thumbprint $Thumbprint
} else {
    Write-Warning 'The MSI and binaries are NOT signed. Do not distribute this build.'
}

$hash = (Get-FileHash $msi -Algorithm SHA256).Hash
"$hash  $(Split-Path $msi -Leaf)" | Set-Content "$msi.sha256" -Encoding ascii
Write-Host "Installer: $msi"
Write-Host "SHA-256:   $hash"
