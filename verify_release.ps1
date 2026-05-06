param(
  [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$BackendDir = Join-Path $Root "sentinel_iot"
$FrontendDir = Join-Path $BackendDir "dashboard\react_app"
$Python = Join-Path $BackendDir ".venv\Scripts\python.exe"

function Invoke-Checked {
  param(
    [scriptblock]$Command,
    [string]$Name
  )

  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "$Name basarisiz oldu. Exit code: $LASTEXITCODE"
  }
}

if (-not (Test-Path $Python)) {
  throw "Sanal ortam bulunamadi. Once .\setup.ps1 calistirin."
}

Set-Location $Root
Write-Host "[1/2] Backend testleri calisiyor..."
Invoke-Checked { & $Python -m pytest -q -p no:cacheprovider --basetemp .pytest-tmp } "Backend testleri"

if (-not $SkipFrontend) {
  Write-Host "[2/2] Frontend lint ve build kontrolu calisiyor..."
  Set-Location $FrontendDir
  Invoke-Checked { npm run check } "Frontend kontrolu"
}

Set-Location $Root
Write-Host "Release dogrulamasi tamamlandi."
