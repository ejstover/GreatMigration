<#
.SYNOPSIS
  One-shot setup & run:
  - Clone (or update) repo
  - Create virtualenv
  - Install requirements
  - Ensure backend/.env (MIST_* vars)
  - Start the FastAPI app with uvicorn
#>

param(
  [string]$RepoUrl,                # e.g. https://github.com/ejstover/GreatMigration.git
  [string]$TargetDir = "$PWD",     # where to clone/use the project
  [string]$Branch = "main",
  [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

function Require-Tool($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "$name is not installed or not on PATH."
  }
}

function Ensure-GitRepo($url, $dir, $branch) {
  if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
  }

  if (-not (Test-Path (Join-Path $dir ".git"))) {
    if (-not $url) { throw "RepoUrl is required for first-time clone." }
    Write-Host "Cloning $url into $dir ..." -ForegroundColor Cyan
    git clone --branch $branch $url $dir
  } else {
    Push-Location $dir
    Write-Host "Updating existing repo in $dir ..." -ForegroundColor Cyan
    git fetch origin
    git checkout $branch
    git pull --rebase origin $branch
    Pop-Location
  }
}

function Ensure-Venv($dir) {
  $venvPath = Join-Path $dir ".venv"
  if (-not (Test-Path $venvPath)) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) {
      py -m venv $venvPath
    } else {
      python -m venv $venvPath
    }
  }
  return $venvPath
}

function Pip($venvPython, $args) {
  & $venvPython -m pip $args
  if ($LASTEXITCODE -ne 0) { throw "pip failed: $args" }
}

function Ensure-Requirements($projectDir, $venvPython) {
  $reqPath = Join-Path $projectDir "backend\requirements.txt"
  Write-Host "Upgrading pip..." -ForegroundColor Cyan
  Pip $venvPython "install --upgrade pip"

  if (Test-Path $reqPath) {
    Write-Host "Installing dependencies from backend\requirements.txt ..." -ForegroundColor Cyan
    Pip $venvPython "install -r `"$reqPath`""
  } else {
    Write-Host "requirements.txt not found; installing core deps..." -ForegroundColor Yellow
    Pip $venvPython "install fastapi==0.115.0 uvicorn==0.30.6 python-multipart==0.0.9 jinja2==3.1.4 requests ciscoconfparse>=1.6.52 python-dotenv"
  }
}

function Ensure-Env($projectDir) {
  $envPath = Join-Path $projectDir "backend\.env"
  if (-not (Test-Path $envPath)) {
    Write-Host "Creating backend\.env ..." -ForegroundColor Cyan
    $token = Read-Host "Enter MIST_TOKEN"
    $base  = Read-Host "Enter MIST_BASE_URL (or press Enter for default https://api.ac2.mist.com)"
    if (-not $base) { $base = "https://api.ac2.mist.com" }
    $org   = Read-Host "Enter MIST_ORG_ID (optional; press Enter to skip)"

    @"
MIST_TOKEN=$token
MIST_BASE_URL=$base
MIST_ORG_ID=$org
"@ | Out-File -Encoding UTF8 $envPath -Force
  }
}

function Start-App($projectDir, $venvPath, $port) {
  $venvPython = Join-Path $venvPath "Scripts\python.exe"
  $backendDir = Join-Path $projectDir "backend"

  # Export env for this process in case .env loader isn't present
  $dotenv = Join-Path $backendDir ".env"
  if (Test-Path $dotenv) {
    (Get-Content $dotenv) | ForEach-Object {
      if ($_ -match "^\s*([^=#]+)\s*=\s*(.*)\s*$") {
        $name = $Matches[1].Trim()
        $val  = $Matches[2]
        if ($val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Trim('"') }
        if ($val.StartsWith("'") -and $val.EndsWith("'")) { $val = $val.Trim("'") }
        if ($name) { $env:$name = $val }
      }
    }
  }

  Write-Host "Starting API on http://0.0.0.0:$port ..." -ForegroundColor Green
  # Use --app-dir so we can run from project root
  & $venvPython -m uvicorn app:app --host 0.0.0.0 --port $port --app-dir "$backendDir"
}

# ---------- Main ----------
Require-Tool git
Require-Tool python  -ErrorAction SilentlyContinue
# "py" is optional; we try it first during venv creation if present

$projectDir = Resolve-Path $TargetDir | Select-Object -ExpandProperty Path

Ensure-GitRepo -url $RepoUrl -dir $projectDir -branch $Branch

$venvPath = Ensure-Venv -dir $projectDir
$venvPython = Join-Path $venvPath "Scripts\python.exe"

Ensure-Requirements -projectDir $projectDir -venvPython $venvPython
Ensure-Env -projectDir $projectDir

Start-App -projectDir $projectDir -venvPath $venvPath -port $Port
