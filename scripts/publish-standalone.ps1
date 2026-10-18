<#
.SYNOPSIS
    Builds a single, portable NetGuardEnterprise.exe that can be copied to another computer and run.
.DESCRIPTION
    The service is published self-contained, zipped and embedded in a self-contained single-file build of the
    desktop application. Target machines need no .NET runtime and no installer. On first run the EXE offers to
    install the background service (one UAC prompt) into "%ProgramFiles%\NetGuard Enterprise Portable\Service".
    Running a newer EXE updates the service. To remove it:  NetGuardEnterprise.exe --uninstall-service
.EXAMPLE
    ./scripts/publish-standalone.ps1 -Version 1.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Output
)
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) -Parent
if (-not $Output) { $Output = Join-Path $root 'artifacts\standalone' }
$staging = Join-Path $root 'artifacts\standalone-staging'

foreach ($dir in $Output, $staging) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
}

$common = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', "-p:Version=$Version", '-p:DebugType=embedded', '-nologo')

# The service runs from a normal folder (ETW and SQLite native libraries are loaded from disk).
$serviceDir = Join-Path $staging 'service'
dotnet publish (Join-Path $root 'src\NetGuard.Service\NetGuard.Service.csproj') @common -o $serviceDir
if ($LASTEXITCODE) { throw 'Publishing the service failed.' }

$package = Join-Path $staging 'NetGuard.ServicePackage.zip'
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($serviceDir, $package, [System.IO.Compression.CompressionLevel]::Optimal, $false)

# Clear the desktop's win-x64 intermediates before and after, so the embedded resource is always compiled in
# and later MSI publishes (scripts/publish.ps1) never reuse an assembly that contains it.
$desktopObj = Join-Path $root 'src\NetGuard.Desktop\obj\Release\net9.0-windows\win-x64'
if (Test-Path $desktopObj) { Remove-Item $desktopObj -Recurse -Force }
dotnet publish (Join-Path $root 'src\NetGuard.Desktop\NetGuard.Desktop.csproj') @common `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    "-p:EmbeddedServicePackage=$package" -o (Join-Path $staging 'desktop')
$publishFailed = $LASTEXITCODE
if (Test-Path $desktopObj) { Remove-Item $desktopObj -Recurse -Force }
if ($publishFailed) { throw 'Publishing the desktop application failed.' }

New-Item -ItemType Directory -Force $Output | Out-Null
$exe = Join-Path $Output 'NetGuardEnterprise.exe'
Copy-Item (Join-Path $staging 'desktop\NetGuard.Desktop.exe') $exe
Remove-Item $staging -Recurse -Force

$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
"$hash  NetGuardEnterprise.exe" | Set-Content "$exe.sha256" -Encoding ascii
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Standalone EXE: $exe ($size MB)"
Write-Host "SHA-256: $hash"
Write-Warning 'The EXE is not signed. Sign it with scripts/sign.ps1 before distributing it outside your organization.'
