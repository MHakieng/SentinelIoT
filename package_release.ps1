param(
  [string]$OutputDir = "release"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$ReleaseDir = Join-Path $Root $OutputDir
$PackageName = "SentinelIoT-release.zip"
$PackagePath = Join-Path $ReleaseDir $PackageName
$TempDir = Join-Path $ReleaseDir "SentinelIoT"

Set-Location $Root

if (Test-Path $TempDir) {
  Remove-Item -LiteralPath $TempDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

$excludeDirs = @(
  ".git",
  ".pytest_cache",
  ".pytest-tmp",
  "release",
  "evaluation\datasets\raw",
  "evaluation\datasets\processed",
  "evaluation\models",
  "evaluation\live",
  "evaluation\results",
  "sentinel_iot\.pytest_cache",
  "sentinel_iot\.pytest-tmp",
  "sentinel_iot\.venv",
  "sentinel_iot\evaluation\results",
  "sentinel_iot\dashboard\react_app\node_modules",
  "sentinel_iot\dashboard\react_app\dist"
)

$excludeFiles = @(
  ".env",
  "sentinel_iot\sentinel_iot.db"
)

function Get-RelativePath {
  param([string]$Path)
  return $Path.Substring($Root.Length).TrimStart("\", "/")
}

function Test-Excluded {
  param(
    [string]$RelativePath,
    [bool]$IsDirectory
  )

  if ($IsDirectory) {
    $leaf = Split-Path $RelativePath -Leaf
    if ($leaf -in @(".git", ".pytest_cache", ".pytest-tmp", ".venv", "node_modules", "dist", "release")) {
      return $true
    }
  }

  foreach ($dir in $excludeDirs) {
    if ($RelativePath -eq $dir -or $RelativePath.StartsWith("$dir\")) {
      return $true
    }
  }

  if (-not $IsDirectory) {
    $extension = [System.IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
    if ($extension -in @(".db", ".sqlite", ".sqlite3", ".pcap", ".pcapng", ".pkl", ".joblib", ".log")) {
      return $true
    }
    if ($extension -eq ".csv" -and -not $RelativePath.StartsWith("docs\evaluation_results\")) {
      return $true
    }

    foreach ($file in $excludeFiles) {
      if ($RelativePath -eq $file) {
        return $true
      }
    }
  }

  return $false
}

function Copy-ReleaseTree {
  param(
    [string]$SourceDir
  )

  foreach ($item in Get-ChildItem -LiteralPath $SourceDir -Force) {
    $relative = Get-RelativePath $item.FullName
    if (Test-Excluded $relative $item.PSIsContainer) {
      continue
    }

    $destination = Join-Path $TempDir $relative
    if ($item.PSIsContainer) {
      New-Item -ItemType Directory -Force -Path $destination | Out-Null
      Copy-ReleaseTree $item.FullName
    } else {
      $destinationDir = Split-Path $destination -Parent
      if (-not (Test-Path $destinationDir)) {
        New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
      }
      Copy-Item -LiteralPath $item.FullName -Destination $destination -Force
    }
  }
}

Copy-ReleaseTree $Root

if (Test-Path $PackagePath) {
  Remove-Item -LiteralPath $PackagePath -Force
}

Compress-Archive -Path (Join-Path $TempDir "*") -DestinationPath $PackagePath -Force
Remove-Item -LiteralPath $TempDir -Recurse -Force
Write-Host "Paket hazir: $PackagePath"
