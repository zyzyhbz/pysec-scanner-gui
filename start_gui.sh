#!/bin/bash
echo ""
echo "  ========================================"
echo "    PySecScanner - 安全扫描工具 v2.0"
echo "  ======================================="
echo ""
echo "  正在启动现代化 GUI 界面..."
echo ""

GUI_SCRIPT="gui/modern_gui.py"

# 检查Python
if command -v python3 &> /dev/null; then
    python3 "$GUI_SCRIPT"
elif command -v python &> /dev/null; then
    python "$GUI_SCRIPT"
else
    echo "  [错误] 未找到 Python！"
    echo ""
    exit 1
fi
