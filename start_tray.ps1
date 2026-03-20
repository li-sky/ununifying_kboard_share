param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("host", "client")]
    [string]$Role,

    [switch]$AutoStart
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonwPath = Join-Path $scriptDir ".venv\Scripts\pythonw.exe"
$pythonPath = Join-Path $scriptDir ".venv\Scripts\python.exe"
$trayRunnerPath = Join-Path $scriptDir "tray_runner.py"

if (-not (Test-Path $trayRunnerPath)) {
    throw "Tray runner not found: $trayRunnerPath"
}

if (Test-Path $pythonwPath) {
    $pythonExe = $pythonwPath
}
elseif (Test-Path $pythonPath) {
    $pythonExe = $pythonPath
}
elseif (Get-Command pyw -ErrorAction SilentlyContinue) {
    $pythonExe = "pyw"
}
elseif (Get-Command pythonw -ErrorAction SilentlyContinue) {
    $pythonExe = "pythonw"
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
}
else {
    throw "No usable Python or Pythonw interpreter found"
}

$arguments = @($trayRunnerPath, "--role", $Role)
if ($AutoStart) {
    $arguments += "--auto-start"
}

& $pythonExe @arguments
