# Reproducible Windows release build. Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 [-DevKey]
#
# Signing keys:
#   production : set SENTRIX_SIGNING_KEY_PATH (and SENTRIX_SIGNING_KEY_PASSWORD) to your updater private key
#   development: -DevKey uses ~/.sentrix-keys/updater-dev.key. NEVER ship a build signed with the dev key.
#
# Authenticode (publisher) signing is separate from update signing. It needs a code-signing certificate that this
# repository does not have, so the output is reported as UNSIGNED unless you sign it afterwards (docs/BUILD.md).
param([switch]$DevKey)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Need($cmd) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "Missing prerequisite: $cmd (see docs/BUILD.md)" } }
Need node; Need npm; Need cargo

# --- signing key -------------------------------------------------------------------------------------------------
if ($DevKey) {
  $keyPath = Join-Path $env:USERPROFILE '.sentrix-keys\updater-dev.key'
  $pwPath  = Join-Path $env:USERPROFILE '.sentrix-keys\updater-dev.password'
  if (-not (Test-Path $keyPath)) { throw "Dev key not found at $keyPath" }
  $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = [System.IO.File]::ReadAllText($pwPath)
  Write-Warning 'Using the DEVELOPMENT updater key. This build must not be distributed.'
} else {
  if (-not $env:SENTRIX_SIGNING_KEY_PATH) { throw 'Set SENTRIX_SIGNING_KEY_PATH to the production updater private key (or pass -DevKey for a local build).' }
  $keyPath = $env:SENTRIX_SIGNING_KEY_PATH
  $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $env:SENTRIX_SIGNING_KEY_PASSWORD
}
$env:TAURI_SIGNING_PRIVATE_KEY = [System.IO.File]::ReadAllText($keyPath)

# --- build -------------------------------------------------------------------------------------------------------
Step 'Install JavaScript dependencies from the lockfile'
npm ci
if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }

Step 'Stage the detection engine runtime'
Push-Location apps\desktop
node scripts\stage-engine.mjs
if ($LASTEXITCODE -ne 0) { throw 'stage-engine failed' }

Step 'Build the desktop app and NSIS installer (release)'
npx tauri build
if ($LASTEXITCODE -ne 0) { throw 'tauri build failed' }
Pop-Location

# --- verify ------------------------------------------------------------------------------------------------------
$conf = Get-Content apps\desktop\src-tauri\tauri.conf.json -Raw | ConvertFrom-Json
$version = $conf.version
$installer = Join-Path $root "target\release\bundle\nsis\SENTRIX_${version}_x64-setup.exe"
if (-not (Test-Path $installer)) { throw "Installer not found: $installer" }
if (-not (Test-Path "$installer.sig")) { throw 'Update signature (.sig) was not produced' }

Step 'Verify the update signature against the public key compiled into the app'
$env:SENTRIX_ARTIFACT = $installer
cargo test -p sentrix-desktop --test update_signature -- --ignored --exact built_installer_verifies_against_the_key_in_tauri_conf
if ($LASTEXITCODE -ne 0) { throw 'Update signature verification FAILED. Do not release.' }

# --- record ------------------------------------------------------------------------------------------------------
$out = Join-Path $root 'dist-release'
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item $installer, "$installer.sig" $out -Force
$hash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item $installer).Length
$auth = Get-AuthenticodeSignature $installer
$manifest = [ordered]@{
  product        = 'SENTRIX'
  version        = $version
  platform       = 'windows-x64'
  file           = (Split-Path $installer -Leaf)
  sha256         = $hash
  sizeBytes      = $size
  updateSigned   = $true
  updateKey      = $(if ($DevKey) { 'DEVELOPMENT (do not distribute)' } else { 'production' })
  authenticode   = $auth.Status.ToString()
  builtAt        = (Get-Date).ToUniversalTime().ToString('o')
  gitCommit      = $(try { (git rev-parse HEAD 2>$null) } catch { $null })
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $out 'release-manifest.json') -Encoding ASCII
"$hash  $(Split-Path $installer -Leaf)" | Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ASCII

Write-Host ''
Write-Host "Release artifacts in $out" -ForegroundColor Green
Write-Host "  SHA-256 : $hash"
Write-Host "  Size    : $([math]::Round($size/1MB,1)) MB"
Write-Host "  Authenticode: $($auth.Status)  $(if ($auth.Status -ne 'Valid') { '<- NOT publisher-signed: Windows SmartScreen will warn users' })"
