#!/usr/bin/env python3
"""
创建PySecScanner的窗口图标
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_icon():
    """创建一个简单的安全扫描器图标"""
    # 创建64x64的图标
    size = 64
    img = Image.new('RGBA', (size, size), (0, 42, 255, 0))  # 透明背景
    draw = ImageDraw.Draw(img)
    
    # 绘制盾牌形状
    # 中心点
    cx, cy = size // 2, size // 2
    
    # 盾牌轮廓
    shield_points = [
        (cx - 20, cy - 25),  # 左上
        (cx + 20, cy - 25),  # 右上
        (cx + 20, cy),       # 右中
        (cx, cy + 25),       # 底部中心
        (cx - 20, cy),       # 左中
    ]
    
    # 绘制盾牌背景（深蓝色）
    draw.polygon(shield_points, fill=(10, 26, 35, 255), outline=(0, 212, 255, 255), width=2)
    
    # 绘制扫描线效果
    for i in range(3):
        y = cy - 15 + i * 12
        draw.line([(cx - 15, y), (cx + 15, y)], fill=(0, 212, 255, 200), width=2)
    
    # 绘制"扫描"文字
    try:
        # 尝试使用系统字体，如果失败则使用默认字体
        font = ImageFont.truetype("arial.ttf", 10)
    except:
        font = ImageFont.load_default()
    
    # 添加"盾牌"符号
    draw.text((cx - 5, cy - 5), "🛡️", fill=(0, 212, 255, 255), font=font)
    
    # 保存为ICO文件
    icon_path = os.path.join(os.path.dirname(__file__), '..', 'gui', 'icon.ico')
    img.save(icon_path, format='ICO', sizes=[(32, 32), (48, 48), (64, 64)])
    print(f"图标已创建: {icon_path}")
    return icon_path

if __name__ == '__main__':
    create_icon()
