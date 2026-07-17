$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

python -m pip install -r requirements-build.txt
# A permanent application directory avoids PyInstaller's temporary _MEI folder
# lifecycle when the UI launches the background helper process.
python -m PyInstaller --noconfirm --clean --onedir --windowed --name AutomateVitWifi wifi_login.py

$compiler = (Get-Command iscc -ErrorAction SilentlyContinue).Source
if (-not $compiler) {
    $knownPath = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
    if (Test-Path $knownPath) { $compiler = $knownPath }
}
if (-not $compiler) {
    $knownPath = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    if (Test-Path $knownPath) { $compiler = $knownPath }
}
if (-not $compiler) {
    Write-Warning 'The app executable was built at dist\AutomateVitWifi.exe, but Inno Setup 6 is not installed. Install it, then run: iscc AutomateVitWifi.iss'
    exit 0
}
& $compiler AutomateVitWifi.iss
