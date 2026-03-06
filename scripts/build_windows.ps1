$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Python venv not found at $python"
}

Write-Host "[1/4] Installing build dependencies..."
& $python -m pip install -r (Join-Path $root "memguard\requirements.txt") pyinstaller

Write-Host "[2/4] Building GUI executable..."
& $python -m PyInstaller --noconfirm --clean --onefile --windowed --name "MemGuardLite" --add-data "$root\data;data" (Join-Path $root "launch_gui.py")

Write-Host "[3/4] Building CLI executable..."
& $python -m PyInstaller --noconfirm --clean --onefile --console --name "MemGuardLite-CLI" --add-data "$root\data;data" (Join-Path $root "memguard\__main__.py")

$releaseDir = Join-Path $root "release"
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

Write-Host "[4/4] Preparing release folder..."
Copy-Item (Join-Path $root "dist\MemGuardLite.exe") $releaseDir -Force
Copy-Item (Join-Path $root "dist\MemGuardLite-CLI.exe") $releaseDir -Force
Copy-Item (Join-Path $root "README.md") $releaseDir -Force

Write-Host "Build complete. Files are in: $releaseDir"
