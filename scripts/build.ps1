<#
.SYNOPSIS
    Restores, builds and tests the NetGuard Enterprise solution.
.EXAMPLE
    ./scripts/build.ps1                     # Release build + unit and integration tests
    ./scripts/build.ps1 -Configuration Debug -SkipTests
.NOTES
    Firewall-modifying tests run only from an elevated prompt with NETGUARD_FIREWALL_WRITE_TESTS=1.
    End-to-end traffic tests additionally need NETGUARD_E2E_TARGET=host:port (see docs/TESTING.md).
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$solution = Join-Path $root 'NetGuard.sln'

dotnet restore $solution
if ($LASTEXITCODE) { throw 'Restore failed.' }

dotnet build $solution -c $Configuration --no-restore -nologo
if ($LASTEXITCODE) { throw 'Build failed.' }

if (-not $SkipTests) {
    $results = Join-Path $root 'artifacts\test-results'
    dotnet test $solution -c $Configuration --no-build -nologo --logger "trx" --results-directory $results
    if ($LASTEXITCODE) { throw 'Tests failed.' }
    Write-Host "Test results: $results"
}
