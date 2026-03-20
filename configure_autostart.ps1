param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("host", "client")]
    [string]$Role = "host",

    [switch]$Disable
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$startupDir = [Environment]::GetFolderPath("Startup")
$shortcutName = "KBShare-$Role.lnk"
$shortcutPath = Join-Path $startupDir $shortcutName
$launcherPath = Join-Path $scriptDir "start_tray.ps1"

if (-not (Test-Path $launcherPath)) {
    throw "Launcher not found: $launcherPath"
}

if ($Disable) {
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Host "Removed autostart: $shortcutPath"
    }
    else {
        Write-Host "Autostart entry not found: $shortcutPath"
    }
    exit 0
}

$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcherPath`" -Role $Role -AutoStart"
$shortcut.WorkingDirectory = $scriptDir
$shortcut.WindowStyle = 7
$shortcut.IconLocation = "$env:WINDIR\System32\shell32.dll,44"
$shortcut.Description = "KB Share $Role autostart"
$shortcut.Save()

Write-Host "Created autostart: $shortcutPath"
Write-Host "Role: $Role"
Write-Host "Launcher: $launcherPath"
