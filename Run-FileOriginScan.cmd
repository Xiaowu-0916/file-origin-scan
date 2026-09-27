@echo off
chcp 65001 >nul
title File Origin Scan
setlocal

set "TOOL=%~dp0FileOriginScan.ps1"
if not exist "%TOOL%" (
    echo [ERROR] FileOriginScan.ps1 not found next to this launcher.
    echo.
    pause
    exit /b 1
)

set "TARGET=%~1"
if "%TARGET%"=="" (
    echo.
    echo   File Origin Scan - find out which software the loose files belong to
    echo   Tip: you can also drag a folder onto this .cmd file.
    echo.
    echo   Examples:  D:\      or      %%USERPROFILE%%\Downloads
    echo.
    set /p "TARGET=  Folder to scan: "
)

if "%TARGET%"=="" (
    echo.
    echo   Nothing to scan. Bye.
    echo.
    pause
    exit /b 1
)

set "RECURSE="
set /p "ANS=  Include subfolders? [y/N]: "
if /i "%ANS%"=="y" set "RECURSE=-Recurse"

echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%TOOL%" -Path "%TARGET%" %RECURSE%

echo.
echo   Done. The HTML report is in the "reports" folder next to this launcher.
echo.
pause
endlocal
