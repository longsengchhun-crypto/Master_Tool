# Run the SENTRIX bot service in the background, start it when you sign in, and keep it running.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install-bot-autostart.ps1            # install and start
#   powershell -ExecutionPolicy Bypass -File scripts\install-bot-autostart.ps1 -Remove    # stop and remove
#
# What it sets up:
#   * a copy of the service in %LOCALAPPDATA%\SENTRIX-Bot (the service updates this copy by itself, signed updates only)
#   * a small wrapper that restarts the service if it stops or has just updated itself
#   * a scheduled task "SENTRIX Bot" that starts the wrapper at sign-in, hidden
# The bot token is NOT copied anywhere: the wrapper points at the env file you already have.
param(
  [string]$EnvFile,
  [string]$ClamAvDir,
  [string]$DataDir,
  [string]$Exe,
  [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$install = Join-Path $env:LOCALAPPDATA 'SENTRIX-Bot'
$task = 'SENTRIX Bot'

function Stop-Bot {
  Get-Process -Name 'sentrix-botd*' -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill(); $_.WaitForExit(8000) | Out-Null } catch {} }
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*SENTRIX-Bot*run-bot.ps1*' } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force } catch {} }
}

if ($Remove) {
  Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  Stop-Bot
  Write-Host "Removed the scheduled task. Files stay in $install (delete the folder if you want them gone)." -ForegroundColor Green
  return
}

if (-not $EnvFile)   { $EnvFile   = Join-Path $root '.sentrix-dev\bot.env' }
if (-not $ClamAvDir) { $ClamAvDir = Join-Path $root 'third_party\clamav' }
if (-not $DataDir)   { $DataDir   = Join-Path $root '.sentrix-dev' }
if (-not $Exe) {
  $Exe = @((Join-Path $root 'dist-release\botd\sentrix-botd.exe'), (Join-Path $root 'target\release\sentrix-botd.exe')) | Where-Object { Test-Path $_ } | Sort-Object { (Get-Item $_).LastWriteTime } -Descending | Select-Object -First 1
}
if (-not $Exe -or -not (Test-Path $Exe)) { throw 'No sentrix-botd.exe found. Build it first: cargo build --release -p sentrix-core --bin sentrix-botd' }
if (-not (Test-Path $EnvFile)) { throw "The bot env file was not found: $EnvFile (it holds SENTRIX_BOT_TOKEN)" }

Write-Host '==> Stopping any copy of the bot that is running (only one program may listen to a bot at a time)' -ForegroundColor Cyan
Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Stop-Bot
New-Item -ItemType Directory -Force $install | Out-Null
Copy-Item $Exe (Join-Path $install 'sentrix-botd.exe') -Force

$wrapper = @"
`$ErrorActionPreference = 'Continue'
`$env:SENTRIX_SUPERVISED = '1'
`$env:SENTRIX_DATA_DIR   = '$DataDir'
`$env:SENTRIX_CLAMAV_DIR = '$ClamAvDir'
Set-Location '$install'
while (`$true) {
  & '$install\sentrix-botd.exe' --env-file '$EnvFile' *>> '$install\bot.log'
  Start-Sleep -Seconds 5
  if ((Get-Item '$install\bot.log' -ErrorAction SilentlyContinue).Length -gt 5MB) { Move-Item '$install\bot.log' '$install\bot.old.log' -Force }
}
"@
[System.IO.File]::WriteAllText((Join-Path $install 'run-bot.ps1'), $wrapper, (New-Object System.Text.UTF8Encoding($true)))

Write-Host '==> Registering the scheduled task' -ForegroundColor Cyan
$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$install\run-bot.ps1`""
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -Description 'SENTRIX Telegram bot service. Updates itself.' -Force | Out-Null
Start-ScheduledTask -TaskName $task
Start-Sleep -Seconds 8
$log = Join-Path $install 'bot.log'
Write-Host ''
if (Test-Path $log) { Get-Content $log -Tail 8 }
Write-Host ''
Write-Host "Bot service installed in $install and running in the background." -ForegroundColor Green
Write-Host "Log: $log   |   Stop and remove: scripts\install-bot-autostart.ps1 -Remove"
Write-Host 'It starts when you sign in to Windows. The computer must be on and online for the bot to answer.'
