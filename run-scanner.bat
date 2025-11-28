@echo off
TITLE Shai-Hulud 2.0 Scanner

:: 1. Check if Node is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [X] Error: Node.js is not installed or not in your PATH.
    echo     Please install Node.js to run this scanner.
    pause
    exit /b
)

:: 2. Run the scanner
:: %* passes all arguments (like --upload) to the node script
echo [*] Launching Scanner...
node "%~dp0scan-shai.js" %*

echo.
echo ========================================================
echo  Scan Complete. Check shai-hulud-report.csv for details.
echo ========================================================
echo.

:: 3. Pause so the user can read the output
pause
