"""
GUI主题引擎 - 使用ttkbootstrap实现现代化主题管理
支持深色/浅色主题切换和配置持久化
扩展了Material Design风格颜色令牌和组件样式配置
"""

import tkinter as tk
from tkinter import ttk
import os
import sys

# 添加项目父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import ttkbootstrap as ttkb
    TTKBOOTSTRAP_AVAILABLE = True
except ImportError:
    TTKBOOTSTRAP_AVAILABLE = False
    print("警告: ttkbootstrap未安装，请运行: pip install ttkbootstrap")


class ThemeEngine:
    """主题引擎单例 - 管理GUI主题应用和切换"""

    _instance = None

    # ========== 暗色模式颜色令牌 (Material Dark) ==========
    DARK_COLORS = {
        'bg_primary': '#121212',
        'bg_secondary': '#1E1E1E',
        'bg_card': '#2A2A2A',
        'bg_elevated': '#323232',
        'primary': '#00FFAA',
        'primary_light': '#4DFFB8',
        'primary_dark': '#00CC88',
        'accent': '#00A3FF',
        'accent_light': '#4DB8FF',
        'success': '#00D166',
        'danger': '#FF4D4D',
        'warning': '#FFA500',
        'fg': '#E0E0E0',
        'fg_secondary': '#A0A0A0',
        'fg_disabled': '#666666',
        'border': '#3A3A3A',
        'border_focus': '#00FFAA',
        'sidebar': '#161616',
        'sidebar_hover': '#1E1E1E',
        'sidebar_active': '#252525',
    }

    # ========== 亮色模式颜色令牌 (Material Light) ==========
    LIGHT_COLORS = {
        'bg_primary': '#F8F9FA',
        'bg_secondary': '#E9ECEF',
        'bg_card': '#FFFFFF',
        'bg_elevated': '#F1F3F5',
        'primary': '#00B894',
        'primary_light': '#00FFAA',
        'primary_dark': '#009970',
        'accent': '#00A3FF',
        'accent_light': '#4DB8FF',
        'success': '#00B894',
        'danger': '#E74C3C',
        'warning': '#F39C12',
        'fg': '#212529',
        'fg_secondary': '#6C757D',
        'fg_disabled': '#ADB5BD',
        'border': '#DEE2E6',
        'border_focus': '#00B894',
        'sidebar': '#FFFFFF',
        'sidebar_hover': '#F1F3F5',
        'sidebar_active': '#E9ECEF',
    }

    # 严重级别颜色映射（主题无关）
    SEVERITY_COLORS = {
        'critical': '#FF4D4D',
        'high': '#FF6B6B',
        'medium': '#FFA500',
        'low': '#00D166',
        'info': '#00A3FF',
    }

    # ttkbootstrap主题映射
    TTkB_THEMES = {
        'dark': 'darkly',      # 最接近 #121212 的暗色主题
        'light': 'litera',      # 最接近 #F8F9FA 的亮色主题
    }

    def __new__(cls, root=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, root=None):
        """初始化主题引擎"""
        if self._initialized:
            return
        self._initialized = True
        self.root = root
        self.current_mode = 'dark'
        self.colors = self.DARK_COLORS.copy()
        self.style = None
        self._setup_fonts()

    def _setup_fonts(self):
        """配置字体"""
        self.fonts = {
            'ui': ('Segoe UI', 10),
            'ui_bold': ('Segoe UI', 10, 'bold'),
            'ui_small': ('Segoe UI', 9),
            'ui_large': ('Segoe UI', 12),
            'ui_title': ('Segoe UI', 14, 'bold'),
            'code': ('Cascadia Code', 9) if self._font_exists('Cascadia Code') else ('Consolas', 9),
            'code_small': ('Cascadia Code', 8) if self._font_exists('Cascadia Code') else ('Consolas', 8),
            'icon': ('Segoe UI Emoji', 12),
        }

    def _font_exists(self, family):
        """检查字体是否存在于系统中"""
        try:
            from tkinter import font
            return family in font.families()
        except:
            return False

    def apply_theme(self, root, mode='dark'):
        """应用主题到根窗口"""
        self.current_mode = mode
        self.colors = self.DARK_COLORS.copy() if mode == 'dark' else self.LIGHT_COLORS.copy()

        if TTKBOOTSTRAP_AVAILABLE:
            theme_name = self.TTkB_THEMES.get(mode, 'darkly')
            try:
                self.style = ttkb.Style(theme=theme_name)
            except:
                self.style = ttkb.Style()
        else:
            self.style = ttk.Style()

        self._configure_global_style()
        self._configure_components()
        return self.style

    def _configure_global_style(self):
        """全局样式配置"""
        c = self.colors
        s = self.style
        fonts = self.fonts

        # 全局字体
        s.configure('.', font=fonts['ui'])

        # Toplevel/窗口背景
        s.configure('TFrame', background=c['bg_primary'])
        s.configure('TLabel', background=c['bg_primary'], foreground=c['fg'])

    def _configure_components(self):
        """配置各组件样式"""
        c = self.colors
        s = self.style
        fonts = self.fonts

        # ===== 侧边导航栏 =====
        s.configure('Sidebar.TFrame', background=c['sidebar'])
        s.configure('SidebarItem.TButton',
                    background=c['sidebar'],
                    foreground=c['fg_secondary'],
                    font=fonts['ui'],
                    borderwidth=0,
                    padding=(16, 10),
                    anchor='w')
        s.map('SidebarItem.TButton',
              background=[('active', c['sidebar_hover']), ('pressed', c['sidebar_active'])],
              foreground=[('active', c['primary']), ('pressed', c['primary'])])

        s.configure('SidebarItemActive.TButton',
                    background=c['sidebar_active'],
                    foreground=c['primary'],
                    font=fonts['ui_bold'],
                    borderwidth=0,
                    padding=(16, 10),
                    anchor='w')

        # 导航图标
        s.configure('SidebarIcon.TLabel',
                    background=c['sidebar'],
                    foreground=c['fg_secondary'],
                    font=fonts['icon'])

        # ===== 卡片面板 =====
        s.configure('Card.TFrame', background=c['bg_card'])
        s.configure('Card.TLabelframe', background=c['bg_card'], borderwidth=1)
        # 注意：ttkbootstrap 不支持自定义 TLabel 样式后缀，
        # 卡片内文字请直接使用 tk.Label 并传入 bg/fg 参数

        # ===== 按钮样式 =====
        s.configure('Action.TButton',
                    font=fonts['ui_bold'],
                    padding=(20, 8))

        # 自定义强调按钮（圆角通过ttkb原生主题实现）
        if TTKBOOTSTRAP_AVAILABLE:
            # ttkbootstrap自带圆角和hover效果，只需指定颜色类型
            pass
        else:
            s.configure('Accent.TButton',
                        background=c['primary'],
                        foreground=c['bg_primary'],
                        font=fonts['ui_bold'],
                        padding=(20, 8))

        # ===== 输入框 =====
        s.configure('Custom.TEntry',
                    fieldbackground=c['bg_secondary'],
                    foreground=c['fg'],
                    insertcolor=c['fg'],
                    padding=(8, 4))

        # ===== 表格 Treeview =====
        s.configure('Custom.Treeview',
                    background=c['bg_card'],
                    foreground=c['fg'],
                    fieldbackground=c['bg_card'],
                    rowheight=28,
                    font=fonts['ui'])
        s.configure('Custom.Treeview.Heading',
                    background=c['bg_secondary'],
                    foreground=c['fg'],
                    font=fonts['ui_bold'],
                    padding=(8, 6))
        s.map('Custom.Treeview',
              background=[('selected', c['primary_dark'] if self.current_mode == 'dark' else c['primary_light'])],
              foreground=[('selected', '#000000' if self.current_mode == 'light' else '#FFFFFF')])

        # ===== 进度条 =====
        s.configure('Pulse.Horizontal.TProgressbar',
                    background=c['primary'],
                    troughcolor=c['bg_secondary'])

        # ===== 标签页 Notebook =====
        s.configure('Custom.TNotebook', background=c['bg_primary'])
        s.configure('Custom.TNotebook.Tab',
                    font=fonts['ui'],
                    padding=(16, 8),
                    background=c['bg_secondary'],
                    foreground=c['fg_secondary'])
        s.map('Custom.TNotebook.Tab',
              background=[('selected', c['bg_card'])],
              foreground=[('selected', c['primary'])],
              expand=[('selected', [2, 2, 2, 0])])

        # ===== 滚动条 =====
        s.configure('Custom.Vertical.TScrollbar',
                    background=c['bg_elevated'],
                    troughcolor=c['bg_secondary'],
                    bordercolor=c['border'],
                    arrowcolor=c['fg_secondary'])

        # ===== 分隔线 =====
        s.configure('Divider.TFrame', background=c['border'])

    def get_color(self, key):
        """获取当前主题颜色"""
        return self.colors.get(key, '#000000')

    def get_font(self, key):
        """获取字体配置"""
        return self.fonts.get(key, ('Segoe UI', 10))

    def toggle_mode(self):
        """切换明暗主题"""
        new_mode = 'light' if self.current_mode == 'dark' else 'dark'
        return self.apply_theme(self.root, new_mode)


class StyleConfigManager:
    """样式配置管理器 - 封装常用组件创建方法"""

    def __init__(self, theme_engine: ThemeEngine = None):
        self.te = theme_engine or ThemeEngine()
        self.colors = self.te.colors
        self.fonts = self.te.fonts

    def create_card(self, parent, title=None, padding=16):
        """创建卡片容器"""
        card = ttk.Frame(parent, style='Card.TFrame', padding=padding)
        if title:
            ttk.Label(card, text=title, style='CardTitle.TLabel').pack(anchor='w', pady=(0, 12))
        return card

    def create_sidebar_button(self, parent, text, icon, command, is_active=False):
        """创建侧边导航按钮"""
        style = 'SidebarItemActive.TButton' if is_active else 'SidebarItem.TButton'
        btn = ttk.Button(parent, text=f"{icon}  {text}", style=style, command=command)
        return btn

    def create_action_button(self, parent, text, command, btn_type='primary'):
        """创建操作按钮"""
        if TTKBOOTSTRAP_AVAILABLE:
            style_map = {
                'primary': 'success.TButton',
                'danger': 'danger.TButton',
                'accent': 'info.TButton',
            }
            style = style_map.get(btn_type, 'success.TButton')
        else:
            style = 'Action.TButton'
        return ttk.Button(parent, text=text, style=style, command=command)

    def create_entry(self, parent, placeholder="", width=40):
        """创建输入框"""
        entry = ttk.Entry(parent, style='Custom.TEntry', width=width)
        if placeholder:
            entry.insert(0, placeholder)
            entry.config(foreground=self.colors['fg_disabled'])
            entry.bind('<FocusIn>', lambda e: self._on_entry_focus_in(e, placeholder))
            entry.bind('<FocusOut>', lambda e: self._on_entry_focus_out(e, placeholder))
        return entry

    def _on_entry_focus_in(self, event, placeholder):
        entry = event.widget
        if entry.get() == placeholder:
            entry.delete(0, 'end')
            entry.config(foreground=self.colors['fg'])

    def _on_entry_focus_out(self, event, placeholder):
        entry = event.widget
        if not entry.get():
            entry.insert(0, placeholder)
            entry.config(foreground=self.colors['fg_disabled'])

    def create_treeview(self, parent, columns, heights=10):
        """创建美化表格"""
        tree = ttk.Treeview(parent, style='Custom.Treeview', columns=columns, show='headings', height=heights)
        return tree

    def create_progress(self, parent, mode='determinate'):
        """创建进度条"""
        if TTKBOOTSTRAP_AVAILABLE:
            style = 'success.Striped.Horizontal.TProgressbar' if mode == 'indeterminate' else 'Pulse.Horizontal.TProgressbar'
        else:
            style = 'Pulse.Horizontal.TProgressbar'
        return ttk.Progressbar(parent, style=style, mode=mode, length=200)


# 便捷获取单例
def get_theme_engine(root=None):
    return ThemeEngine(root)
