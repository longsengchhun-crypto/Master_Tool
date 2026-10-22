# Build, sign and publish a SENTRIX release to GitHub so every installed app and the running bot service update themselves.
#
#   powershell -ExecutionPolicy Bypass -File scripts\publish-release.ps1 -Notes "What changed, in plain words"
#
# Needs: the production update key (default %USERPROFILE%\.sentrix-keys\updater-prod.key + .password, or SENTRIX_SIGNING_KEY_PATH /
# SENTRIX_SIGNING_KEY_PASSWORD), `gh` logged in, node, cargo. The version is read from apps/desktop/src-tauri/tauri.conf.json:
# bump it (and the two Cargo.toml versions) before running. A version that is already released is refused.
#
# It publishes:
#   SENTRIX_<v>_x64-setup.exe        the installer (the app's updater downloads this one)
#   SENTRIX-setup.exe                the same file under a fixed name, for the "download" link people are given
#   latest.json                      what installed apps read to learn there is a new version (signed)
#   sentrix-botd.exe + .sig          the bot service
#   botd-latest.json                 what the running bot service reads (signed)
#   SHA256SUMS.txt
param(
  [string]$Notes = 'Improvements and fixes.',
  [switch]$Draft,
  [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Utf8NoBom($path, $text) { [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false))) }

$conf = Get-Content 'apps\desktop\src-tauri\tauri.conf.json' -Raw | ConvertFrom-Json
$version = $conf.version
$tag = "v$version"
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'The GitHub CLI (gh) is required.' }
$repo = (gh repo view --json nameWithOwner -q .nameWithOwner).Trim()
if (gh release view $tag 2>$null) { throw "Release $tag already exists. Bump the version first: updates are only offered for higher versions." }

if (-not $env:SENTRIX_SIGNING_KEY_PATH) { $env:SENTRIX_SIGNING_KEY_PATH = Join-Path $env:USERPROFILE '.sentrix-keys\updater-prod.key' }
if (-not $env:SENTRIX_SIGNING_KEY_PASSWORD) { $env:SENTRIX_SIGNING_KEY_PASSWORD = [System.IO.File]::ReadAllText((Join-Path $env:USERPROFILE '.sentrix-keys\updater-prod.password')) }
if (-not (Test-Path $env:SENTRIX_SIGNING_KEY_PATH)) { throw "Signing key not found: $env:SENTRIX_SIGNING_KEY_PATH" }

$dist = Join-Path $root 'dist-release'
if (-not $SkipBuild) {
  Step "Build the signed installer for $version"
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'build-release.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'The installer build failed.' }
  Step 'Build the bot service'
  cargo build --release -p sentrix-core --bin sentrix-botd
  if ($LASTEXITCODE -ne 0) { throw 'The bot service build failed.' }
}

$installer = Join-Path $dist "SENTRIX_${version}_x64-setup.exe"
if (-not (Test-Path $installer)) { throw "Installer not found: $installer" }
$stage = Join-Path $dist "release-$version"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item $installer $stage
Copy-Item "$installer.sig" $stage
Copy-Item $installer (Join-Path $stage 'SENTRIX-setup.exe')
Copy-Item (Join-Path $root 'target\release\sentrix-botd.exe') (Join-Path $stage 'sentrix-botd.exe')

Step 'Sign the bot service'
$env:TAURI_SIGNING_PRIVATE_KEY = [System.IO.File]::ReadAllText($env:SENTRIX_SIGNING_KEY_PATH)
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $env:SENTRIX_SIGNING_KEY_PASSWORD
Push-Location (Join-Path $root 'apps\desktop')
npx tauri signer sign (Join-Path $stage 'sentrix-botd.exe') | Out-Null
Pop-Location
if (-not (Test-Path (Join-Path $stage 'sentrix-botd.exe.sig'))) { throw 'Signing the bot service failed.' }

Step 'Write the update feeds'
$base = "https://github.com/$repo/releases/download/$tag"
$date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$appSig = [System.IO.File]::ReadAllText("$installer.sig").Trim()
$latest = [ordered]@{
  version = $version; notes = $Notes; pub_date = $date
  platforms = [ordered]@{ 'windows-x86_64' = [ordered]@{ signature = $appSig; url = "$base/SENTRIX_${version}_x64-setup.exe" } }
}
Utf8NoBom (Join-Path $stage 'latest.json') ($latest | ConvertTo-Json -Depth 6)
$botSha = (Get-FileHash (Join-Path $stage 'sentrix-botd.exe') -Algorithm SHA256).Hash.ToLower()
$bot = [ordered]@{
  version = $version; notes = $Notes; pub_date = $date
  url = "$base/sentrix-botd.exe"; sha256 = $botSha
  signature = [System.IO.File]::ReadAllText((Join-Path $stage 'sentrix-botd.exe.sig')).Trim()
}
Utf8NoBom (Join-Path $stage 'botd-latest.json') ($bot | ConvertTo-Json -Depth 4)
$sums = Get-ChildItem $stage -File | Where-Object { $_.Name -notlike '*.json' -and $_.Name -notlike '*.sig' } | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)" }
Utf8NoBom (Join-Path $stage 'SHA256SUMS.txt') (($sums -join "`n") + "`n")

Step 'Check the feeds before publishing anything'
$check = (Get-Content (Join-Path $stage 'latest.json') -Raw | ConvertFrom-Json)
if ($check.version -ne $version -or -not $check.platforms.'windows-x86_64'.signature) { throw 'latest.json is wrong.' }
if ((Get-Content (Join-Path $stage 'botd-latest.json') -Raw | ConvertFrom-Json).sha256 -ne $botSha) { throw 'botd-latest.json is wrong.' }

Step "Publish $tag to $repo"
$assets = @('SENTRIX_${version}_x64-setup.exe', 'SENTRIX_${version}_x64-setup.exe.sig', 'SENTRIX-setup.exe', 'sentrix-botd.exe', 'sentrix-botd.exe.sig', 'SHA256SUMS.txt', 'botd-latest.json', 'latest.json') | ForEach-Object { Join-Path $stage ($_.Replace('${version}', $version)) }
$flags = @(); if ($Draft) { $flags += '--draft' }
gh release create $tag @assets --title "SENTRIX $version" --notes "$Notes`n`nInstalled apps and the running bot service update themselves from this release. Verify downloads with SHA256SUMS.txt." @flags
if ($LASTEXITCODE -ne 0) { throw 'gh release create failed.' }
Write-Host ''
Write-Host "Published: https://github.com/$repo/releases/tag/$tag" -ForegroundColor Green
Write-Host "People download:  https://github.com/$repo/releases/latest/download/SENTRIX-setup.exe"
