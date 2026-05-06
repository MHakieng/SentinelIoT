$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$FrontendDir = Join-Path $Root "sentinel_iot\dashboard\react_app"

if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
  Write-Host "node_modules bulunamadi. Frontend paketleri yukleniyor..."
  Set-Location $FrontendDir
  npm install
}

Set-Location $FrontendDir
$env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
Write-Host "SentinelIoT Dashboard: http://127.0.0.1:5173"
npm run dev -- --host 127.0.0.1
