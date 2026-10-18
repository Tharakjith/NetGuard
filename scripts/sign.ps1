<#
.SYNOPSIS
    Authenticode-signs NetGuard binaries or the MSI with SHA-256 and an RFC 3161 timestamp, then verifies them.
.DESCRIPTION
    Provide the signing certificate either by thumbprint (certificate in CurrentUser\My or LocalMachine\My,
    including hardware tokens/HSM-backed keys) or as a PFX file. Private keys are never stored in this repository.
    Only NetGuard's own files are signed; third-party runtime files keep their original Microsoft signatures.
.EXAMPLE
    ./scripts/sign.ps1 -Path artifacts\publish -Thumbprint 0123ABCD...
    ./scripts/sign.ps1 -Path artifacts\installer\NetGuardEnterprise-1.0.0-x64.msi -Thumbprint 0123ABCD...
#>
[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Thumbprint')][string]$Thumbprint,
    [Parameter(Mandatory, ParameterSetName = 'Pfx')][string]$PfxPath,
    [Parameter(ParameterSetName = 'Pfx')][securestring]$PfxPassword,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK signing tools.' }

$targets = if (Test-Path $Path -PathType Container) {
    Get-ChildItem $Path -Recurse -Include 'NetGuard.*.exe', 'NetGuard.*.dll'
} else {
    Get-Item $Path
}
if (-not $targets) { throw "No NetGuard files found under $Path." }

$identity = if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
    @('/sha1', $Thumbprint)
} else {
    $plain = if ($PfxPassword) { [System.Net.NetworkCredential]::new('', $PfxPassword).Password } else { '' }
    @('/f', $PfxPath, '/p', $plain)
}

foreach ($file in $targets) {
    & $signtool.FullName sign /fd SHA256 /tr $TimestampUrl /td SHA256 /d 'NetGuard Enterprise' @identity $file.FullName
    if ($LASTEXITCODE) { throw "Signing failed: $($file.FullName)" }
    & $signtool.FullName verify /pa /q $file.FullName
    if ($LASTEXITCODE) { throw "Signature verification failed: $($file.FullName)" }
}
Write-Host "Signed and verified $($targets.Count) file(s)."
