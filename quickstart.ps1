<#
.SYNOPSIS
  One-shot setup & run:
  - Clone (or update) repo
  - Create virtualenv
  - Install deps
    - Ensure backend/.env (prompts for Mist token, auth settings, and API port)
  - Start the FastAPI app with uvicorn
#>

param(
  [string]$RepoUrl,                # e.g. https://github.com/ejstover/GreatMigration.git
  [string]$TargetDir = "$PWD",     # where to clone/use the project
  [string]$Branch = "main",
  [int]$Port = 0,
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"

function Require-Tool {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "$Name is not installed or not on PATH."
  }
}

function Ensure-GitRepo {
  param([string]$url, [string]$dir, [string]$branch)
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

function Ensure-Venv {
  param([string]$dir)
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

function Pip {
  param(
    [string]$venvPython,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
  )
  & $venvPython -m pip @Args
  if ($LASTEXITCODE -ne 0) { throw "pip failed: $Args" }
}

function Ensure-Requirements {
  param([string]$projectDir, [string]$venvPython)
  & $venvPython -m pip --version *> $null
  if ($LASTEXITCODE -ne 0) {
    Write-Host "pip not found; bootstrapping with ensurepip ..." -ForegroundColor Yellow
    & $venvPython -m ensurepip --upgrade
    if ($LASTEXITCODE -ne 0) { throw "Failed to bootstrap pip with ensurepip." }
  }
  $reqPath = Join-Path $projectDir "backend\requirements.txt"

  Write-Host "Upgrading pip..." -ForegroundColor Cyan
  Pip $venvPython install --upgrade pip wheel setuptools

  if (Test-Path $reqPath) {
    Write-Host "Installing dependencies from backend\requirements.txt ..." -ForegroundColor Cyan
    Pip $venvPython install -r $reqPath
  } else {
    Write-Host "requirements.txt not found; installing core deps..." -ForegroundColor Yellow
    Pip $venvPython install fastapi==0.115.0 uvicorn==0.30.6 python-multipart==0.0.9 jinja2==3.1.4 requests 'ciscoconfparse>=1.6.52' python-dotenv
  }
}

function Ensure-Env {
  param([string]$projectDir)
  $envPath = Join-Path $projectDir "backend\.env"
  if (Test-Path $envPath) {
    Write-Host "Found $envPath"
    $port = $null
    Get-Content $envPath | ForEach-Object {
      if ($_ -match "^API_PORT=(.*)$") { $port = $Matches[1] }
    }
    return [int]$port
  }

  $envSample = Join-Path $projectDir ".env.sample"
  Write-Host "`nCreating backend\.env (first run). Values are stored locally in this file." -ForegroundColor Cyan

  $tokenSecure = Read-Host "MIST_TOKEN (input hidden)" -AsSecureString
  $token = [System.Net.NetworkCredential]::new("", $tokenSecure).Password
  $base  = Read-Host "MIST_BASE_URL [default https://api.ac2.mist.com]"
  if (-not $base) { $base = "https://api.ac2.mist.com" }
  $org   = Read-Host "MIST_ORG_ID (optional)"
  $tmpl  = Read-Host "SWITCH_TEMPLATE_ID (optional)"
  $port  = Read-Host "API_PORT [default 8000]"
  if (-not $port) { $port = "8000" }
  $auth  = Read-Host "AUTH_METHOD [default local]"
  if (-not $auth) { $auth = "local" } else { $auth = $auth.ToLower() }
  $syslogHost = Read-Host "SYSLOG_HOST (optional)"
  $syslogPort = Read-Host "SYSLOG_PORT [default 514]"
  if (-not $syslogPort) { $syslogPort = "514" }

  $lines = @(
    "AUTH_METHOD=$auth",
    "SESSION_SECRET=change_me",
    "MIST_TOKEN=$token",
    "MIST_BASE_URL=$base",
    "MIST_ORG_ID=$org",
    "SWITCH_TEMPLATE_ID=$tmpl",
    "HELP_URL=https://github.com/ejstover/GreatMigration/blob/main/README.md"
  )

  if ($auth -eq "ldap") {
    Write-Host "LDAP selected. Update backend\.env with correct LDAP settings." -ForegroundColor Yellow
    if (Test-Path $envSample) {
      foreach ($ln in Get-Content $envSample) {
        if ($ln -like '# LDAP_*' -or $ln -like '# PUSH_GROUP_DN*') {
          $lines += $ln.TrimStart('# ').Trim()
        }
      }
    } else {
      $lines += "LDAP_SERVER_URL="
      $lines += "LDAP_SEARCH_BASE="
      $lines += "LDAP_BIND_TEMPLATE="
      $lines += "PUSH_GROUP_DN="
      $lines += "LDAP_SERVICE_DN="
      $lines += "LDAP_SERVICE_PASSWORD="
    }
  } else {
    $user = Read-Host "Local username"
    $pwdSecure = Read-Host "Local password (input hidden)" -AsSecureString
    $pwd = [System.Net.NetworkCredential]::new("", $pwdSecure).Password
    $lines += "LOCAL_USERS=${user}:${pwd}"
    $lines += "LOCAL_PUSH_USERS=$user"
  }

  $lines += "API_PORT=$port"
  if ($syslogHost) {
    $lines += "SYSLOG_HOST=$syslogHost"
    if ($syslogPort) { $lines += "SYSLOG_PORT=$syslogPort" }
  }

  $content = ($lines -join "`n") + "`n"
  Set-Content -Path $envPath -Value $content -Encoding UTF8
  Write-Host "Wrote $envPath" -ForegroundColor Green
  return [int]$port
}

function Ensure-PortRules {
  param([string]$projectDir)
  $sample = Join-Path $projectDir "backend/port_rules.sample.json"
  $dest = Join-Path $projectDir "backend/port_rules.json"
  if (Test-Path $dest) {
    Write-Host "Found $dest"
  } elseif (Test-Path $sample) {
    Copy-Item -Path $sample -Destination $dest
    Write-Host "Copied $sample to $dest" -ForegroundColor Cyan
  } else {
    Write-Host "Sample port rules not found at $sample" -ForegroundColor Yellow
  }
}

function Start-App {
  param([string]$projectDir, [string]$venvPath, [int]$port)
  $venvPython = Join-Path $venvPath "Scripts\python.exe"
  $backendDir = Join-Path $projectDir "backend"

  # Export env VARS for this process in case the app doesn't load .env itself
  $dotenv = Join-Path $backendDir ".env"
  if (Test-Path $dotenv) {
    Get-Content $dotenv | ForEach-Object {
      if ($_ -match "^\s*([^=#]+)\s*=\s*(.*)\s*$") {
        $name = $Matches[1].Trim()
        $val  = $Matches[2].Trim()
        if ($val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Trim('"') }
        if ($val.StartsWith("'") -and $val.EndsWith("'")) { $val = $val.Trim("'") }
        if ($name) {
          # Correct dynamic env var assignment (current process):
          Set-Item -Path ("Env:{0}" -f $name) -Value $val
          # Alternatively: [System.Environment]::SetEnvironmentVariable($name, $val, 'Process')
        }
      }
    }
  }

  Write-Host "Starting API on http://0.0.0.0:$port ..." -ForegroundColor Green
  & $venvPython -m uvicorn app:app --host 0.0.0.0 --port $port --app-dir "$backendDir"
}

# ---------- Main ----------
Require-Tool git
Require-Tool python

$projectDir = (Resolve-Path $TargetDir).Path

Ensure-GitRepo -url $RepoUrl -dir $projectDir -branch $Branch

$venvPath = Ensure-Venv -dir $projectDir
$venvPython = Join-Path $venvPath "Scripts\python.exe"

Ensure-Requirements -projectDir $projectDir -venvPython $venvPython
$envPort = Ensure-Env -projectDir $projectDir
Ensure-PortRules -projectDir $projectDir

if (-not $PSBoundParameters.ContainsKey('Port') -and $envPort -ne 0) { $Port = $envPort }
if (-not $Port) { $Port = 8000 }

if ($NoStart) {
  Write-Host "`nSetup complete. To start later run:" -ForegroundColor Cyan
  $backendDir = Join-Path $projectDir "backend"
  $venvPython = Join-Path $venvPath "Scripts\python.exe"
  Write-Host "  `"$venvPython`" -m uvicorn app:app --host 0.0.0.0 --port $Port --app-dir `"$backendDir`"" -ForegroundColor White
} else {
  Start-App -projectDir $projectDir -venvPath $venvPath -port $Port
}
