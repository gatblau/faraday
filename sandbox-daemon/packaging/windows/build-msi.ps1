# Build the Windows service installer (.msi) for faradayd (windows-deployment phase 5, ADR-031).
#
# Signing is OPTIONAL and OFF by default — an UNSIGNED .msi is produced unless you opt in
# (no certificate is required to build/test). To Authenticode-sign, set:
#   $env:PYS_SIGN_THUMBPRINT = "<cert SHA1 thumbprint in the local cert store>"
#
# Requires the WiX 'wix' dotnet tool (dotnet tool install --global wix).
# Usage: build-msi.ps1 [-Binary <path-to-faradayd.exe>] [-Version <x.y.z>]
param(
    [string]$Binary = (Join-Path $PSScriptRoot '..\..\target\release\faradayd.exe'),
    [string]$Version = $(if ($env:PYS_VERSION) { $env:PYS_VERSION } else { '0.1.0' })
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Binary)) {
    throw "binary not found at $Binary (run: cargo build --release --bin faradayd)"
}
$binDir = (Resolve-Path (Split-Path $Binary)).Path
$root   = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$outDir = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$msi = Join-Path $outDir "faradayd-$Version.msi"
$wxs = Join-Path $PSScriptRoot 'faradayd.wxs'

Write-Host "building $msi from $wxs (bin=$binDir)"
wix build $wxs -bindpath "bin=$binDir" -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }

if ($env:PYS_SIGN_THUMBPRINT) {
    Write-Host "signing with thumbprint $env:PYS_SIGN_THUMBPRINT"
    signtool sign /sha1 $env:PYS_SIGN_THUMBPRINT /fd SHA256 `
        /tr http://timestamp.digicert.com /td SHA256 $msi
    if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
} else {
    Write-Host 'built UNSIGNED (set PYS_SIGN_THUMBPRINT to sign) — SmartScreen will warn on first run'
}
Write-Host "built $msi"
