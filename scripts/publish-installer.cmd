@echo off
setlocal
cd /d "%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\publish-installer.ps1" -PauseOnError
exit /b %ERRORLEVEL%
