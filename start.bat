@echo off
chcp 65001 >nul
cls
echo.
echo   ========================================
echo   PySecScanner - Security Scanner v2.0
echo   ========================================
echo.
echo   Select interface:
echo.
echo      [1] Modern GUI  [recommended]
echo      [2] Classic GUI
echo.
set /p choice="   Enter 1 or 2: "

if "%choice%"=="2" goto classic
goto modern

:modern
echo.
echo   Launching Modern GUI...
echo.
set GUI_SCRIPT=gui\modern_gui.py
goto launch

:classic
echo.
echo   Launching Classic GUI...
echo.
set GUI_SCRIPT=gui\app.py
goto launch

:launch
where python >nul 2>&1
if %errorlevel% equ 0 (
    python %GUI_SCRIPT%
    goto end
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    python3 %GUI_SCRIPT%
    goto end
)

echo.
echo   [Error] Python not found!
echo   Please install Python and add it to PATH.
echo   https://www.python.org/downloads/
echo.
pause
exit /b 1

:end
if %errorlevel% neq 0 (
    echo.
    echo   [Error] Launch failed.
    echo.
    pause
)
