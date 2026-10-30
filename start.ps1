$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    Write-Error 'Run: py -m venv .venv; then .venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-advanced.txt'
}
& $pythonPath app.py
