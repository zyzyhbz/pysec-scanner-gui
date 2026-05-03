@echo off
chcp 65001 >nul
echo.
echo   ========================================
echo     PySecScanner - Web界面启动器
echo   ========================================
echo.

:: 设置Python路径，确保能找到项目模块
set SCRIPT_DIR=%~dp0
set PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%

:: 检测Python环境
where python >nul 2>&1
if %errorlevel% equ 0 (
    cd /d "%SCRIPT_DIR%"
    python web/app.py
    goto :end
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    cd /d "%SCRIPT_DIR%"
    python3 web/app.py
    goto :end
)

echo   [错误] 未找到 Python！
echo.
echo   请确保已安装 Python 并将其添加到 PATH 环境变量。
echo   你可以从 https://www.python.org/downloads/ 下载安装。
echo.
pause
exit /b 1

:end
pause
