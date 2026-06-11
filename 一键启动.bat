@echo off
title Firefly Auto Registration Task Manager
setlocal

echo Starting server...
echo.
echo If you want to close the program, just close this black console window.
echo.

REM Stop previous server that is still listening on port 8000
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo Stopping previous server process %%p ...
    taskkill /PID %%p /F >nul 2>nul
)

REM Wait 1 second
timeout /t 1 >nul

REM Open browser
start http://localhost:8000

REM Run python server
python server.py

pause
