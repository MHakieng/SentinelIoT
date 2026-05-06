$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$BackendDir = Join-Path $Root "sentinel_iot"
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
$EnvFile = Join-Path $Root ".env"

function Import-DotEnv {
  param([string]$Path)

  if (-not (Test-Path $Path)) {
    Write-Host ".env bulunamadi. LLM kullanmak icin .env.example dosyasini .env olarak kopyalayip doldurun."
    return
  }

  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
      return
    }

    $name, $value = $line.Split("=", 2)
    $name = $name.Trim()
    $value = $value.Trim().Trim('"').Trim("'")
    if ($name) {
      [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
  }
}

if (-not (Test-Path $VenvPython)) {
  Write-Host "Sanal ortam bulunamadi. Once setup.ps1 calistiriliyor..."
  & (Join-Path $Root "setup.ps1") -SkipNpm
}

Set-Location $Root
Import-DotEnv $EnvFile
Write-Host "SentinelIoT API: http://127.0.0.1:8000"
& $VenvPython -m uvicorn sentinel_iot.api.main:app --host 127.0.0.1 --port 8000 --reload
