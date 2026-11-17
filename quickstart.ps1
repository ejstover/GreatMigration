<#
.SYNOPSIS
  Launch GreatMigration. Use setup, upgrade, or autostart for explicit maintenance.
.EXAMPLE
  .\quickstart.ps1
.EXAMPLE
  .\quickstart.ps1 setup -NoStart
.EXAMPLE
  .\quickstart.ps1 upgrade -RepoUrl https://github.com/you/GreatMigration.git
.EXAMPLE
  .\quickstart.ps1 autostart enable
#>
[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [ValidateSet('start','setup','upgrade','stop','restart','status','autostart')]
  [string]$Command,
  [Parameter(Position=1)]
  [ValidateSet('enable','disable','status')]
  [string]$Action,
  [string]$RepoUrl,
  [string]$TargetDir = "$PWD",
  [string]$Branch,
  [int]$Port,
  [switch]$NoStart,
  [switch]$Autostart,
  [switch]$NoAutostart,
  [Alias('h')]
  [switch]$Help
)
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 'quickstart.py'
if (-not (Test-Path -LiteralPath $launcher)) {
  throw 'Keep quickstart.py beside quickstart.ps1; Python owns the shared launcher.'
}
# Prefer the existing interpreter. Plain startup needs neither global Python nor Git.
$venvPython = Join-Path $TargetDir '.venv/Scripts/python.exe'
$pythonArgs = @()
if (Test-Path -LiteralPath $venvPython) {
  $python = $venvPython
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
  $python = 'py'
  $pythonArgs = @('-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
  $python = 'python'
} else {
  throw 'Python 3.11 or newer is required. Install Python, then run quickstart setup.'
}
$forward = @($launcher)
if ($Command) { $forward += $Command }
if ($Action) { $forward += $Action }
$forward += @('--dir', $TargetDir)
if ($PSBoundParameters.ContainsKey('RepoUrl')) { $forward += @('--repo', $RepoUrl) }
if ($PSBoundParameters.ContainsKey('Branch')) { $forward += @('--branch', $Branch) }
if ($PSBoundParameters.ContainsKey('Port')) { $forward += @('--port', [string]$Port) }
if ($NoStart) { $forward += '--no-start' }
if ($Autostart) { $forward += '--autostart' }
if ($NoAutostart) { $forward += '--no-autostart' }
if ($Help) { $forward += '--help' }
& $python @pythonArgs @forward
exit $LASTEXITCODE
