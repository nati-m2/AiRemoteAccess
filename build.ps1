# Build Warp for Windows (GUI + CLI). Run on a Windows machine.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$py = "python"
if (Test-Path ".venv\Scripts\python.exe") { $py = ".venv\Scripts\python.exe" }

& $py -m PyInstaller --version *> $null
if ($LASTEXITCODE -ne 0) { & $py -m pip install pyinstaller }

& $py build.py @args
exit $LASTEXITCODE
