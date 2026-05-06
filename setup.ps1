param(
  [switch]$SkipNpm
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$BackendDir = Join-Path $Root "sentinel_iot"
$FrontendDir = Join-Path $BackendDir "dashboard\react_app"
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"

function Resolve-Python {
  $candidates = @(
    "py -3.12",
    "py -3",
    "python"
  )

  foreach ($candidate in $candidates) {
    try {
      $null = Invoke-Expression "$candidate --version"
      return $candidate
    } catch {
      continue
    }
  }

  throw "Python bulunamadi. Python 3.12 kurun veya PATH'e ekleyin."
}

Set-Location $Root

if (-not (Test-Path $VenvPython)) {
  $Python = Resolve-Python
  Write-Host "Python sanal ortam olusturuluyor: sentinel_iot\.venv"
  Invoke-Expression "$Python -m venv `"$BackendDir\.venv`""
}

Write-Host "Backend paketleri yukleniyor..."
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $BackendDir "requirements.txt")

if (-not $SkipNpm) {
  Write-Host "Frontend paketleri yukleniyor..."
  Set-Location $FrontendDir
  npm install
}

Set-Location $Root
Write-Host ""
Write-Host "Kurulum tamamlandi."
Write-Host "Not: Ag taramasi icin Nmap kurulu olmali ve PATH'te 'nmap' olarak bulunmali."
