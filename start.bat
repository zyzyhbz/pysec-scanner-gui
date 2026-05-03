@echo off
chcp 65001 >nul
cls
echo.
echo   ========================================
echo   PySecScanner - 安全扫描工具 v2.0
echo   ========================================
echo.
echo   正在启动现代化 GUI 界面...
echo.

set GUI_SCRIPT=gui\modern_gui.py

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
echo   [错误] 未找到 Python！
echo   请安装 Python 并将其添加到 PATH 环境变量中。
echo   https://www.python.org/downloads/
echo.
pause
exit /b 1

:end
if %errorlevel% neq 0 (
    echo.
    echo   [错误] 启动失败。
    echo.
    pause
)
