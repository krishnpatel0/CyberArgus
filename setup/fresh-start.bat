@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fresh-start.ps1" %*
exit /b %ERRORLEVEL%
