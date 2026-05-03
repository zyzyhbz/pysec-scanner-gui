#!/bin/bash
echo ""
echo "  ========================================"
echo "    PySecScanner - 安全扫描工具 v2.0"
echo "  ======================================="
echo ""
echo "  请选择要启动的界面："
echo ""
echo "    [1] 新版界面（现代化改造 - 推荐）"
echo "    [2] 原版界面（经典样式）"
echo ""
read -p "  请输入数字 (1/2): " choice

if [ "$choice" = "2" ]; then
    GUI_SCRIPT="gui/app.py"
    echo ""
    echo "  正在启动原版界面..."
else
    GUI_SCRIPT="gui/modern_gui.py"
    echo ""
    echo "  正在启动新版现代化界面..."
fi
echo ""

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
