$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

$backendScript = Join-Path $Root "run_backend.ps1"
$frontendScript = Join-Path $Root "run_frontend.ps1"

Write-Host "Backend ve frontend ayri PowerShell pencerelerinde baslatiliyor..."
Write-Host "API:       http://127.0.0.1:8000"
Write-Host "Dashboard: http://127.0.0.1:5173"

Start-Process powershell.exe -ArgumentList @(
  "-NoExit",
  "-ExecutionPolicy", "Bypass",
  "-File", "`"$backendScript`""
)

Start-Sleep -Seconds 2

Start-Process powershell.exe -ArgumentList @(
  "-NoExit",
  "-ExecutionPolicy", "Bypass",
  "-File", "`"$frontendScript`""
)
