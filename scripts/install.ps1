# Builds KeyHolder and installs it for the current user with a desktop shortcut.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-NoBuild]
param([switch]$NoBuild)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $env:LOCALAPPDATA "Programs\KeyHolder"

if (-not $NoBuild) {
    Push-Location (Join-Path $root "app")
    try {
        if (-not (Test-Path "node_modules")) { npm install; if (-not $?) { throw "npm install failed" } }
        npx tauri build --no-bundle
        if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
    } finally { Pop-Location }
    Push-Location $root
    try {
        cargo build --release -p kh-cli
        if ($LASTEXITCODE -ne 0) { throw "kh build failed" }
        cargo build --release -p kh-service
        if ($LASTEXITCODE -ne 0) { throw "keyholder-service build failed" }
    } finally { Pop-Location }
}

$running = Get-Process -Name "keyholder" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "KeyHolder is running - quit it from the tray first, then run this script again."
    exit 1
}

New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $root "target\release\keyholder.exe") (Join-Path $dest "keyholder.exe") -Force
Copy-Item (Join-Path $root "target\release\kh.exe") (Join-Path $dest "kh.exe") -Force
Copy-Item (Join-Path $root "target\release\keyholder-service.exe") (Join-Path $dest "keyholder-service.exe") -Force
# A separate .ico for shortcuts: Windows caches icons per path, so an updated exe can keep
# showing the old picture; a dedicated, versioned icon file avoids the stale cache entry.
$iconFile = Join-Path $dest ("keyholder-" + (Get-FileHash (Join-Path $root "app\src-tauri\icons\icon.ico")).Hash.Substring(0, 8) + ".ico")
Get-ChildItem $dest -Filter "keyholder-*.ico" -ErrorAction SilentlyContinue | Remove-Item -Force
Copy-Item (Join-Path $root "app\src-tauri\icons\icon.ico") $iconFile -Force

$shell = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath("Desktop")
foreach ($dir in @($desktop, (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"))) {
    # Shortcuts from before the rename.
    Remove-Item (Join-Path $dir "KeyHolder.lnk") -Force -ErrorAction SilentlyContinue
    $lnk = $shell.CreateShortcut((Join-Path $dir "MCP Keyholder.lnk"))
    $lnk.TargetPath = Join-Path $dest "keyholder.exe"
    $lnk.WorkingDirectory = $dest
    $lnk.IconLocation = $iconFile + ",0"
    $lnk.Description = "MCP Keyholder - secrets for AI agents"
    $lnk.Save()
}

Write-Host "Installed to $dest"
Write-Host "kh for agents: $(Join-Path $dest 'kh.exe')"
