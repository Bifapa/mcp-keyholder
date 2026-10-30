# Builds the signed installer of MCP Keyholder and, with -Publish, releases it.
#
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1            # build only
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -Publish   # build and release
#
# The version comes from app/src-tauri/tauri.conf.json, the release notes from CHANGELOG.md.
# Installers go to the public repository Bifapa/mcp-keyholder-releases (the source stays
# private); the app checks its latest.json for updates and verifies the signature with the
# public key in tauri.conf.json. The private key lives outside the repository:
# %USERPROFILE%\.tauri\mcp-keyholder.key.
param([switch]$Publish)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$releases = "Bifapa/mcp-keyholder-releases"
$keyFile = Join-Path $env:USERPROFILE ".tauri\mcp-keyholder.key"

$version = (Get-Content (Join-Path $root "app\src-tauri\tauri.conf.json") -Raw | ConvertFrom-Json).version
$tag = "v$version"
if (-not (Test-Path $keyFile)) { throw "Signing key not found: $keyFile" }

# Release notes: the CHANGELOG section of this version.
$notes = ""
$inSection = $false
foreach ($line in Get-Content (Join-Path $root "CHANGELOG.md") -Encoding UTF8) {
    if ($line -match '^## \[(.+?)\]') {
        if ($inSection) { break }
        $inSection = ($Matches[1] -eq $version)
        continue
    }
    if ($inSection) { $notes += "$line`n" }
}
$notes = $notes.Trim()
if (-not $notes) { throw "CHANGELOG.md has no section for $version" }

# kh.exe and keyholder-service.exe first: the installer picks them up (windows/hooks.nsh).
Push-Location $root
try {
    cargo build --release -p kh-cli -p kh-service
    if ($LASTEXITCODE -ne 0) { throw "kh / keyholder-service build failed" }
} finally { Pop-Location }

$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content $keyFile -Raw
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ""
Push-Location (Join-Path $root "app")
try {
    if (-not (Test-Path "node_modules")) { npm ci; if ($LASTEXITCODE -ne 0) { throw "npm ci failed" } }
    npx tauri build
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
} finally {
    Pop-Location
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY, Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
}

$nsis = Join-Path $root "target\release\bundle\nsis"
$setup = Get-ChildItem $nsis -Filter "*_${version}_x64-setup.exe" | Select-Object -First 1
if (-not $setup -or -not (Test-Path "$($setup.FullName).sig")) { throw "Installer or its signature is missing in $nsis" }

$out = Join-Path $root "target\release\publish"
New-Item -ItemType Directory -Force $out | Out-Null
Get-ChildItem $out | Remove-Item -Force
$asset = "MCP-Keyholder_${version}_x64-setup.exe"
Copy-Item $setup.FullName (Join-Path $out $asset)
Copy-Item "$($setup.FullName).sig" (Join-Path $out "$asset.sig")

$latest = [ordered]@{
    version   = $version
    notes     = $notes
    pub_date  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    platforms = [ordered]@{
        "windows-x86_64" = [ordered]@{
            signature = (Get-Content "$($setup.FullName).sig" -Raw).Trim()
            url       = "https://github.com/$releases/releases/download/$tag/$asset"
        }
    }
}
# UTF-8 without BOM: the updater's JSON parser rejects a BOM.
[IO.File]::WriteAllText((Join-Path $out "latest.json"), ($latest | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
[IO.File]::WriteAllText((Join-Path $out "notes.md"), $notes, (New-Object Text.UTF8Encoding $false))
Write-Host "Built $version in $out"

if (-not $Publish) {
    Write-Host "Run with -Publish to release it to $releases."
    exit 0
}

$ErrorActionPreference = "Continue"
gh release view $tag --repo $releases *> $null
$exists = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = "Stop"
if ($exists) { throw "Release $tag already exists in $releases" }

gh release create $tag --repo $releases --title "MCP Keyholder $version" --notes-file (Join-Path $out "notes.md") `
    (Join-Path $out $asset) (Join-Path $out "$asset.sig") (Join-Path $out "latest.json")
if ($LASTEXITCODE -ne 0) { throw "gh release create failed" }

# Mark the released source in the private repository.
git -C $root tag -a $tag -m "MCP Keyholder $version"
git -C $root push origin $tag
Write-Host "Released ${tag}: https://github.com/$releases/releases/tag/$tag"
