# MSI smoke test (windows-deployment phase 5). Proves the per-user .msi installs the binary,
# registers the HKCU autostart, and merges the MCP front door into the user's Claude config
# WITHOUT clobbering an existing server; then proves uninstall removes the binary + autostart.
# The live-daemon round-trip needs PYS_* config the package does not supply (parity with the
# macOS .pkg) and is tracked as a follow-up. Run from the sandbox-daemon working directory.
#requires -Version 5
$ErrorActionPreference = 'Stop'

$msi = (Get-ChildItem dist/faradayd-*.msi -ErrorAction SilentlyContinue | Select-Object -First 1)
if (-not $msi) { throw 'no .msi found in dist/ (build-msi.ps1 did not produce one)' }
$msi = $msi.FullName

# Pre-seed an existing MCP server so we can prove the post-install merge does not clobber it.
$claude = Join-Path $env:USERPROFILE '.claude.json'
'{ "mcpServers": { "other": { "command": "C:\\other.exe" } } }' | Set-Content -Path $claude -Encoding utf8

Write-Host "installing $msi"
$p = Start-Process msiexec -ArgumentList @('/i', $msi, '/quiet', '/norestart', '/l*v', 'msi-install.log') -Wait -PassThru
if ($p.ExitCode -ne 0) {
    if (Test-Path msi-install.log) { Get-Content msi-install.log -Tail 60 }
    throw "msi install failed (exit $($p.ExitCode))"
}

$exe = Join-Path $env:LOCALAPPDATA 'faradayd\faradayd.exe'
if (-not (Test-Path $exe)) { throw "installed binary missing at $exe" }
Write-Host "OK: binary installed at $exe"

$run = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name faradayd -ErrorAction SilentlyContinue).faradayd
if (-not $run) { throw 'autostart Run key not registered' }
Write-Host "OK: autostart registered -> $run"

$cfg = Get-Content $claude -Raw | ConvertFrom-Json
if (-not $cfg.mcpServers.faradayd) { throw 'faradayd MCP entry missing after the post-install merge' }
if (-not $cfg.mcpServers.other)    { throw 'post-install merge CLOBBERED the pre-existing server' }
Write-Host 'OK: MCP front door merged without clobbering the existing server'

Write-Host 'uninstalling'
$u = Start-Process msiexec -ArgumentList @('/x', $msi, '/quiet', '/norestart') -Wait -PassThru
if ($u.ExitCode -ne 0) { throw "msi uninstall failed (exit $($u.ExitCode))" }
if (Test-Path $exe) { throw 'binary still present after uninstall' }
$run2 = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name faradayd -ErrorAction SilentlyContinue).faradayd
if ($run2) { throw 'autostart Run key still present after uninstall' }
Write-Host 'OK: uninstall removed the binary and the autostart key'

Write-Host 'msi smoke passed'
