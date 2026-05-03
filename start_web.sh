#!/bin/bash
# PySecScanner Web界面启动脚本

echo ""
echo "========================================"
echo "  PySecScanner - Web界面启动器"
echo "========================================"
echo ""

# 设置Python路径，确保能找到项目模块
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH}"
cd "${SCRIPT_DIR}"

# 检测Python环境
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo "[错误] 未找到 Python！"
    echo ""
    echo "请确保已安装 Python 并将其添加到 PATH 环境变量。"
    echo "你可以从 https://www.python.org/downloads/ 下载安装。"
    exit 1
fi

echo "使用Python: $PYTHON_CMD"
echo ""

# 启动Web服务
$PYTHON_CMD web/app.py
