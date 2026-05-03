"""
PySecScanner GUI - 独立可视化界面
与核心代码解耦，通过导入使用功能
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
import queue
import json
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional, Any

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# 导入AI分析模块
from modules.ai.analyzer import AIAnalyzer
from modules.ai.batch_analyzer import BatchAnalyzer
from modules.ai.deepseek_client import DeepSeekClient
from modules.fix.fix_generator import FixGenerator
from core.scanner import ScanReport
from modules.report.generator import ReportGenerator

# 导入主题引擎
from gui.theme_engine import ThemeEngine, StyleConfigManager

 

class ScanResultAdapter:
    """扫描结果适配器 - 解耦GUI与核心数据结构"""
    
    def __init__(self, data: Dict):
        self.result_type = data.get('result_type', 'info')
        self.title = data.get('title', '')
        self.description = data.get('description', '')
        self.severity = data.get('severity', 'info')
        self.target = data.get('target', '')
        self.evidence = data.get('evidence', '')
        self.raw_data = data.get('raw_data', {})
        self.timestamp = data.get('timestamp', 0)
    
    def to_dict(self) -> Dict:
        return {
            'result_type': self.result_type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'target': self.target,
            'evidence': self.evidence,
            'raw_data': self.raw_data,
            'timestamp': self.timestamp
        }


class ScannerBridge:
    """扫描器桥接类 - 连接GUI与核心扫描器"""
    
    def __init__(self):
        self.scanner = None
        self._initialized = False
    
    def initialize(self):
        """初始化扫描器"""
        if self._initialized:
            return True
        
        try:
            from core.scanner import Scanner
            self.scanner = Scanner()
            self._initialized = True
            return True
        except Exception as e:
            print(f"初始化扫描器失败: {e}")
            return False
    
    def get_modules(self) -> List[Dict]:
        """获取可用模块列表"""
        if not self._initialized:
            self.initialize()
        
        if self.scanner:
            modules = []
            for name in self.scanner.get_available_modules():
                info = self.scanner.get_module_info(name)
                if info:
                    modules.append({
                        'id': name,
                        'name': info.get('name', name),
                        'description': info.get('description', ''),
                        'version': info.get('version', '1.0.0')
                    })
            return modules
        return []
    
    async def scan(self, target: str, modules: List[str] = None, 
                   timeout: int = 10, concurrency: int = 50) -> Dict:
        """执行扫描"""
        if not self._initialized:
            self.initialize()
        
        if not self.scanner:
            raise Exception("扫描器未初始化")
        
        # 更新配置
        self.scanner.config.scan.timeout = timeout
        self.scanner.config.scan.concurrency = concurrency
        
        # 执行扫描
        report = await self.scanner.scan(target, modules)
        
        # 转换结果为字典格式
        return {
            'target': report.target,
            'start_time': report.start_time,
            'end_time': report.end_time,
            'duration': report.duration,
            'results': [r.to_dict() for r in report.results],
            'module_stats': report.module_stats
        }


# 全局扫描器桥接实例
scanner_bridge = ScannerBridge()


class PySecScannerGUI:
    """PySecScanner 图形界面"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PySec Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # 设置窗口图标
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
            try:
                from PIL import Image, ImageTk
                icon_img = Image.open(icon_path)
                photo = ImageTk.PhotoImage(icon_img)
                self.root.iconphoto(True, photo)
                self._icon_photo = photo
            except Exception:
                pass
        
        # Windows: 使用API创建无边框但保留任务栏图标的窗口
        # 先 overrideredirect(False) 确保任务栏图标显示，再通过API移除标题栏
        self.root.overrideredirect(False)
        self.root.config(bg='#0a1a14')  # 发光边框底色
        
        # 使用Windows API移除标题栏但保留任务栏图标
        try:
            import ctypes
            from ctypes import wintypes
            
            GWL_STYLE = -16
            GWL_EXSTYLE = -20
            
            WS_BORDER = 0x00800000
            WS_DLGFRAME = 0x00400000
            WS_CAPTION = WS_BORDER | WS_DLGFRAME
            WS_THICKFRAME = 0x00040000
            WS_MAXIMIZEBOX = 0x00010000
            WS_MINIMIZEBOX = 0x00020000
            WS_SYSMENU = 0x00080000
            WS_POPUP = 0x80000000
            WS_VISIBLE = 0x10000000
            
            # 获取窗口句柄
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            if hwnd == 0:
                hwnd = self.root.winfo_id()
            
            # 获取当前样式
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)
            
            # 移除标题栏相关样式，保留任务栏显示所需的样式
            style &= ~WS_CAPTION
            style &= ~WS_THICKFRAME
            style &= ~WS_MAXIMIZEBOX
            style &= ~WS_MINIMIZEBOX
            style &= ~WS_SYSMENU
            
            # 设置新样式
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, style)
            
            # 强制刷新窗口
            SWP_FRAMECHANGED = 0x0020
            SWP_NOMOVE = 0x0002
            SWP_NOSIZE = 0x0001
            SWP_NOZORDER = 0x0004
            SWP_NOOWNERZORDER = 0x0200
            SWP_SHOWWINDOW = 0x0040
            
            ctypes.windll.user32.SetWindowPos(
                hwnd, 0, 0, 0, 0, 0,
                SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE |
                SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_SHOWWINDOW
            )
            
        except Exception:
            # 如果API调用失败，回退到传统的overrideredirect
            self.root.overrideredirect(True)
        
        # 初始化主题引擎
        self.theme_engine = ThemeEngine(root=self.root)
        self.config_manager = StyleConfigManager()
        
        # 加载保存的主题配置
        theme_config = self.config_manager.get_theme_config()
        self.theme_engine.current_theme = theme_config['theme']
        self.theme_engine.theme_mode = theme_config['mode']
        self.theme_engine.initialize(self.root)
        self.theme_engine.configure_custom_styles()
        
        # 获取严重级别颜色配置
        self.severity_colors = self.config_manager.get_severity_colors()
        
        # 使用现代化色彩令牌体系构建颜色字典（用于tk控件，ttkbootstrap不支持tk.Label等）
        cs = ThemeEngine.COLOR_SYSTEM
        sev = self.severity_colors or ThemeEngine.SEVERITY_COLORS
        base_colors = {
            'bg': cs['bg_darker'],
            'fg': cs['fg'],
            'accent': cs['accent_cyan'],
            'input_bg': cs['bg_dark'],
        }
        # 从配置中引入严重级别颜色（带现代化默认值）
        base_colors.update({
            'critical': sev.get('critical', '#FF4D4D'),
            'high': sev.get('high', '#FF4D4D'),
            'medium': sev.get('medium', '#FFA500'),
            'low': sev.get('low', '#00D166'),
            'info': sev.get('info', '#00FFFF'),
        })
        self.colors = base_colors
        
        # 无边框窗口相关状态
        self._is_maximized = False
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._window_x = 0
        self._window_y = 0
        self._restore_geometry = None
        self._resize_edge = None
        
        # 居中显示窗口
        self.root.update_idletasks()
        _screen_w = self.root.winfo_screenwidth()
        _screen_h = self.root.winfo_screenheight()
        _x = (_screen_w - 1200) // 2
        _y = (_screen_h - 800) // 2
        self.root.geometry(f"1200x800+{_x}+{_y}")
        
        # 状态变量
        self.is_scanning = False
        self.scan_results: List[ScanResultAdapter] = []
        self.ai_analysis_results = []
        self.fix_suggestions = []
        self.message_queue = queue.Queue()
        # AI对话历史
        self.chat_history: List[Dict[str, Any]] = []
        
        # AI分析器
        self.ai_analyzer = None
        self.batch_analyzer = None
        self.fix_generator = None
        # 标记本次修复建议是否由用户显式请求
        self._fix_requested_by_user = False
        
        # 创建窗口发光边框效果（必须在其他组件之前创建）
        self._create_glow_border()
        
        # 创建自定义标题栏
        self._create_title_bar()
        
        # 创建界面
        self._create_widgets()
        
        # 设置窗口边缘调整大小手柄
        self._setup_resize_handles()
        
        # 确保glow canvas在所有组件创建完成后在最底层
        self.root.update_idletasks()
        if hasattr(self, '_glow_canvas'):
            self.root.lower(self._glow_canvas)
        
        # 启动消息处理
        self.root.after(100, self._process_messages)
        
        # 初始化扫描器
        self._init_scanner()
        
        # 初始化AI分析器
        self._init_ai_analyzer()
        
        # 默认激活扫描配置（延迟执行以确保所有UI元素都已渲染）
        self.root.after(200, lambda: self._nav_to_section('scan'))
    
    def _create_widgets(self):
        """创建界面组件（侧边栏布局）"""
        cs = ThemeEngine.COLOR_SYSTEM
        
        # ===== 底部状态栏（先pack确保空间分配） =====
        status_frame = tk.Frame(self.root, bg=cs['bg_darker'], height=28)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=1, pady=(0, 1))
        status_frame.pack_propagate(False)
        
        self.bottom_status = tk.Label(
            status_frame,
            text="状态: 就绪",
            font=("Arial", 9),
            bg=cs['bg_darker'],
            fg='#888888'
        )
        self.bottom_status.pack(side=tk.LEFT, padx=(14, 0))
        
        self.result_count = tk.Label(
            status_frame,
            text="发现: 0 个结果",
            font=("Arial", 9),
            bg=cs['bg_darker'],
            fg=self.colors['accent']
        )
        self.result_count.pack(side=tk.RIGHT, padx=(0, 14))
        
        # ===== 主框架（padx=1 为发光边框留出间隙） =====
        main_frame = tk.Frame(self.root, bg=cs['bg_darker'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=1)
        
        # ===== 左侧侧边栏（200px固定宽度，背景 #0F0F1A） =====
        sidebar = tk.Frame(main_frame, bg=cs['bg_darker'], width=200)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # --- 导航按钮区域（Outline 风格，选中填充 primary 色） ---
        nav_frame = tk.Frame(sidebar, bg=cs['bg_darker'])
        nav_frame.pack(fill=tk.X, padx=5, pady=(8, 5))
        
        self._nav_buttons = {}
        self._active_nav_btn = None
        nav_items = [
            ('scan', '🎯 扫描配置'),
            ('ai', '🤖 AI工具'),
        ]
        for nav_id, nav_text in nav_items:
            btn = tk.Button(
                nav_frame,
                text=nav_text,
                font=("Arial", 9),
                bg=cs['bg_darker'],
                fg=cs['fg_secondary'],
                activebackground=cs['secondary'],
                activeforeground=cs['fg'],
                relief=tk.FLAT,
                anchor='w',
                padx=12,
                pady=5,
                cursor='hand2',
                bd=0,
                highlightthickness=1,
                highlightbackground=cs['border_color'],
                highlightcolor=cs['primary'],
            )
            btn.pack(fill=tk.X, pady=1)
            btn.bind('<Button-1>', lambda e, nid=nav_id: self._nav_to_section(nid))
            self._nav_buttons[nav_id] = btn
        
        # --- 分隔线 ---
        tk.Frame(sidebar, bg=cs['border_color'], height=1).pack(fill=tk.X, padx=10, pady=(0, 5))
        
        # --- 可滚动内容区域（Canvas+Scrollbar） ---
        self._sidebar_canvas = tk.Canvas(sidebar, bg=cs['bg_darker'], highlightthickness=0, width=175)
        sidebar_scrollbar = ttk.Scrollbar(sidebar, orient="vertical", command=self._sidebar_canvas.yview)
        sidebar_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._sidebar_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._sidebar_canvas.configure(yscrollcommand=sidebar_scrollbar.set)
        
        # 滚动内容框架
        scroll_content = tk.Frame(self._sidebar_canvas, bg=cs['bg_darker'])
        sidebar_canvas_window = self._sidebar_canvas.create_window((0, 0), window=scroll_content, anchor="nw")
        
        # 配置滚动区域 + 自适应宽度和高度
        def configure_sidebar_scroll(event=None):
            self._sidebar_canvas.configure(scrollregion=self._sidebar_canvas.bbox("all"))
            if self._sidebar_canvas.winfo_width() > 1:
                self._sidebar_canvas.itemconfig(sidebar_canvas_window, width=self._sidebar_canvas.winfo_width())
        
        # 绑定多个事件以确保滚动区域正确配置
        scroll_content.bind("<Configure>", configure_sidebar_scroll)
        self._sidebar_canvas.bind("<Configure>", configure_sidebar_scroll)
        
        # 鼠标滚轮支持（仅在侧边栏区域内生效）
        def _on_sidebar_mousewheel(event):
            self._sidebar_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        self._sidebar_canvas.bind('<Enter>', lambda e: self._sidebar_canvas.bind_all("<MouseWheel>", _on_sidebar_mousewheel))
        self._sidebar_canvas.bind('<Leave>', lambda e: self._sidebar_canvas.unbind_all("<MouseWheel>"))
        
        # ====== 扫描配置区域（scan section） ======
        self._scan_section = tk.Frame(scroll_content, bg=cs['bg_darker'])
        self._scan_section.pack(fill=tk.X, padx=3, pady=0)
        
        # 目标输入
        target_lf = tk.LabelFrame(
            self._scan_section, text=" 🎯 扫描目标 ",
            bg=cs['bg_darker'], fg=cs['primary'],
            font=('Arial', 9, 'bold'),
            bd=1, relief='groove',
            highlightbackground=cs['border_color']
        )
        target_lf.pack(fill=tk.X, pady=(0, 5), padx=2)
        
        self.target_entry = tk.Entry(
            target_lf,
            font=("Arial", 10),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightcolor=cs['primary'],
            highlightbackground=cs['border_color']
        )
        self.target_entry.pack(fill=tk.X, padx=5, pady=(5, 5), ipady=4)
        self.target_entry.insert(0, "http://testphp.vulnweb.com")
        
        # 模块选择
        modules_lf = tk.LabelFrame(
            self._scan_section, text=" 📋 扫描模块 ",
            bg=cs['bg_darker'], fg=cs['primary'],
            font=('Arial', 9, 'bold'),
            bd=1, relief='groove'
        )
        modules_lf.pack(fill=tk.X, pady=(0, 5), padx=2)
        
        self.module_vars = {}
        default_modules = [
            ("port_scan", "端口扫描", True),
            ("subdomain", "子域名枚举", False),
            ("dir_scan", "目录扫描", True),
            ("sqli", "SQL注入", True),
            ("xss", "XSS检测", True),
            ("ssrf", "SSRF检测", False),
            ("sensitive", "敏感信息", True),
            ("fingerprint", "指纹识别", False),
        ]
        
        for mod_id, mod_name, default in default_modules:
            var = tk.BooleanVar(value=default)
            self.module_vars[mod_id] = var
            cb = tk.Checkbutton(
                modules_lf,
                text=mod_name,
                variable=var,
                bg=cs['bg_darker'],
                fg=cs['fg_secondary'],
                selectcolor=cs['bg_dark'],
                activebackground=cs['bg_darker'],
                activeforeground=cs['fg'],
                font=('Arial', 8),
                anchor='w',
                bd=0,
                highlightthickness=0
            )
            cb.pack(fill=tk.X, padx=5, pady=0)
        
        # 扫描选项
        options_lf = tk.LabelFrame(
            self._scan_section, text=" ⚙ 扫描选项 ",
            bg=cs['bg_darker'], fg=cs['primary'],
            font=('Arial', 9, 'bold'),
            bd=1, relief='groove'
        )
        options_lf.pack(fill=tk.X, pady=(0, 5), padx=2)
        
        # 超时
        tk.Label(
            options_lf,
            text="超时(秒):",
            bg=cs['bg_darker'],
            fg='#aaaaaa',
            font=('Arial', 8)
        ).pack(anchor=tk.W, padx=5)
        
        self.timeout_var = tk.StringVar(value="10")
        tk.Entry(
            options_lf,
            textvariable=self.timeout_var,
            width=8,
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightcolor=cs['primary'],
            highlightbackground=cs['border_color'],
            font=('Arial', 9)
        ).pack(anchor=tk.W, padx=5, pady=(2, 5), ipady=2)
        
        # 并发数
        tk.Label(
            options_lf,
            text="并发数:",
            bg=cs['bg_darker'],
            fg='#aaaaaa',
            font=('Arial', 8)
        ).pack(anchor=tk.W, padx=5)
        
        self.concurrency_var = tk.StringVar(value="50")
        tk.Entry(
            options_lf,
            textvariable=self.concurrency_var,
            width=8,
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightcolor=cs['primary'],
            highlightbackground=cs['border_color'],
            font=('Arial', 9)
        ).pack(anchor=tk.W, padx=5, pady=(2, 5), ipady=2)
        
        # ====== 操作按钮区域 ======
        actions_frame = tk.Frame(scroll_content, bg=cs['bg_darker'])
        actions_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        # Helper: 创建带hover发光效果的操作按钮
        def _make_action_btn(parent, text, command, fg_color=cs['primary'], hover_bg=None):
            """创建操作按钮（高度36px，hover发光效果）"""
            _btn = tk.Button(
                parent,
                text=text,
                font=("Arial", 9),
                bg=cs['bg_darker'],
                fg=fg_color,
                activebackground=hover_bg or cs['secondary'],
                activeforeground=cs['fg'],
                relief=tk.FLAT,
                bd=0,
                cursor='hand2',
                command=command,
                highlightthickness=1,
                highlightbackground=cs['border_color'],
                highlightcolor=cs['primary'],
            )
            _btn.pack(fill=tk.X, pady=2, ipady=5)
            # hover 发光效果
            _btn.bind('<Enter>', lambda e, b=_btn, hc=hover_bg: b.config(
                bg=hc or cs['secondary'],
                highlightbackground=cs['primary']
            ))
            _btn.bind('<Leave>', lambda e, b=_btn: b.config(
                bg=cs['bg_darker'],
                highlightbackground=cs['border_color']
            ))
            return _btn
        
        self.scan_btn = _make_action_btn(
            actions_frame, "▶ 开始扫描", self._start_scan,
            fg_color=cs['primary'], hover_bg=cs['primary']
        )
        # 开始扫描按钮hover时文字变深色
        self.scan_btn.bind('<Enter>', lambda e: self.scan_btn.config(
            bg=cs['primary'], fg=cs['bg_darker'], highlightbackground=cs['primary']))
        self.scan_btn.bind('<Leave>', lambda e: self.scan_btn.config(
            bg=cs['bg_darker'], fg=cs['primary'], highlightbackground=cs['border_color']))
        
        self.stop_btn = _make_action_btn(
            actions_frame, "⏹ 停止扫描", self._stop_scan,
            fg_color=cs['danger'], hover_bg=cs['danger']
        )
        self.stop_btn.config(state=tk.DISABLED)
        
        self.export_btn = _make_action_btn(
            actions_frame, "📊 导出报告", self._export_report,
            fg_color=cs['success'], hover_bg='#1a3a2a'
        )
        
        self.clear_btn = _make_action_btn(
            actions_frame, "🗑 清空结果", self._clear_results,
            fg_color=cs['fg_secondary'], hover_bg=cs['secondary']
        )
        
        # 分隔线
        tk.Frame(actions_frame, bg=cs['border_color'], height=1).pack(fill=tk.X, pady=5)
        
        self.ai_analyze_btn = _make_action_btn(
            actions_frame, "🤖 AI分析", self._start_ai_analysis,
            fg_color=cs['accent_cyan'], hover_bg='#1a2a3a'
        )
        
        self.fix_generate_btn = _make_action_btn(
            actions_frame, "🔧 修复建议", self._generate_fix_suggestions,
            fg_color=cs['warning'], hover_bg='#3a2a1a'
        )
        
        # ====== AI设置区域（ai section） ======
        self._ai_section = tk.Frame(scroll_content, bg=cs['bg_darker'])
        self._ai_section.pack(fill=tk.X, padx=3, pady=(5, 5))
        
        ai_lf = tk.LabelFrame(
            self._ai_section, text=" 🧠 AI设置 ",
            bg=cs['bg_darker'], fg=cs['primary'],
            font=('Arial', 9, 'bold'),
            bd=1, relief='groove'
        )
        ai_lf.pack(fill=tk.X, padx=2)
        
        tk.Label(
            ai_lf,
            text="DeepSeek模型:",
            bg=cs['bg_darker'],
            fg='#aaaaaa',
            font=('Arial', 8)
        ).pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        self.ai_model_var = tk.StringVar(value=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"))
        self.ai_model_combo = ttk.Combobox(
            ai_lf,
            textvariable=self.ai_model_var,
            values=["deepseek-chat", "deepseek-reasoner"],
            state="readonly",
            width=16,
            style='Custom.TCombobox'
        )
        self.ai_model_combo.pack(anchor=tk.W, padx=5, pady=(3, 5))
        self.ai_model_combo.bind("<<ComboboxSelected>>", lambda _e: self._init_ai_analyzer(force=True))
        
        tk.Label(
            ai_lf,
            text="温度 (0-1):",
            bg=cs['bg_darker'],
            fg='#aaaaaa',
            font=('Arial', 8)
        ).pack(anchor=tk.W, padx=5, pady=(3, 0))
        
        self.ai_temp_var = tk.DoubleVar(value=float(os.getenv("DEEPSEEK_TEMPERATURE", "0.7")))
        temp_scale = ttk.Scale(
            ai_lf,
            from_=0.0,
            to=1.0,
            orient=tk.HORIZONTAL,
            variable=self.ai_temp_var,
            length=140,
            style='Custom.Horizontal.TScale'
        )
        temp_scale.pack(anchor=tk.W, padx=5, pady=(3, 5))
        
        self.auto_fix_var = tk.BooleanVar(value=True)
        auto_fix_cb = tk.Checkbutton(
            ai_lf,
            text="自动生成修复建议",
            variable=self.auto_fix_var,
            bg=cs['bg_darker'],
            fg=cs['fg_secondary'],
            selectcolor=cs['bg_dark'],
            activebackground=cs['bg_darker'],
            activeforeground=cs['fg'],
            font=('Arial', 8),
            anchor='w',
            bd=0,
            highlightthickness=0
        )
        auto_fix_cb.pack(anchor=tk.W, padx=5, pady=(3, 5))
        
        # ===== 右侧内容区（自适应） =====
        right_panel = tk.Frame(main_frame, bg=cs['bg_darker'])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(0, 0))
        
        # 进度条区域
        progress_frame = tk.Frame(right_panel, bg=cs['bg_darker'])
        progress_frame.pack(fill=tk.X, pady=(8, 8), padx=10)
        
        self.status_label = tk.Label(
            progress_frame,
            text="就绪",
            font=("Arial", 9),
            bg=cs['bg_darker'],
            fg='#888888'
        )
        self.status_label.pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            length=250,
            mode='determinate',
            style='striped.Horizontal.TProgressbar'
        )
        self.progress_bar.pack(side=tk.RIGHT)
        
        # 启动进度条条纹脉冲动画
        self._stripe_offset = 0
        self._animate_progressbar()
        
        # 结果标签页（Custom.TNotebook 样式：未选中灰色，选中青色指示）
        self.notebook = ttk.Notebook(right_panel, style='Custom.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 5))
        
        # --- 结果列表页 ---
        results_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(results_frame, text="扫描结果")
        
        # 结果表格（Custom.Treeview 样式：无边框、28px行高）
        columns = ("severity", "type", "title", "target")
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            height=18,
            style='Custom.Treeview'
        )
        
        self.results_tree.heading("severity", text="严重程度")
        self.results_tree.heading("type", text="类型")
        self.results_tree.heading("title", text="标题")
        self.results_tree.heading("target", text="目标")
        
        self.results_tree.column("severity", width=90)
        self.results_tree.column("type", width=80)
        self.results_tree.column("title", width=280)
        self.results_tree.column("target", width=200)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_select)
        
        # --- 详情页 ---
        detail_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(detail_frame, text="详细信息")
        
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=cs['border_color']
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- 日志页 ---
        log_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(log_frame, text="扫描日志")
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=cs['bg_dark'],
            fg='#00ff00',
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=cs['border_color']
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- 统计页 ---
        stats_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(stats_frame, text="统计信息")
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame,
            wrap=tk.WORD,
            font=("Arial", 11),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=cs['border_color']
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- AI分析结果页 ---
        ai_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(ai_frame, text="AI分析")
        
        self.ai_text = scrolledtext.ScrolledText(
            ai_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=cs['border_color']
        )
        self.ai_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- 修复建议页 ---
        fix_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(fix_frame, text="修复建议")
        
        self.fix_text = scrolledtext.ScrolledText(
            fix_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=cs['border_color']
        )
        self.fix_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- AI对话页 ---
        chat_frame = tk.Frame(self.notebook, bg=cs['bg_darker'])
        self.notebook.add(chat_frame, text="AI对话")

        # 聊天消息区域
        self.chat_text_frame = tk.Frame(chat_frame, bg=cs['bg_darker'])
        self.chat_text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.chat_text = scrolledtext.ScrolledText(
            self.chat_text_frame,
            wrap=tk.WORD,
            font=("Microsoft YaHei UI", 9),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            padx=10,
            pady=10,
            spacing1=0,
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=cs['border_color']
        )
        self.chat_text.pack(fill=tk.BOTH, expand=True)
        self.chat_text.pack_propagate(False)
        
        self.separator_canvases = []
        self.chat_text.bind("<Configure>", self._update_all_separators)
        self.chat_text.tag_config("user", justify="right", lmargin1=0)
        self.chat_text.tag_config("ai", justify="left", lmargin1=0)
        self.chat_text.tag_config("separator", justify="left", foreground="gray", lmargin1=0, lmargin2=0, rmargin=0)
        
        self.ai_message_start = None

        # 聊天输入区域
        chat_input_frame = tk.Frame(chat_frame, bg=cs['bg_darker'])
        chat_input_frame.pack(fill=tk.X, padx=5, pady=(5, 10))

        self.chat_entry = tk.Entry(
            chat_input_frame,
            font=("Arial", 10),
            bg=cs['bg_dark'],
            fg=cs['fg'],
            insertbackground=cs['fg'],
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightcolor=cs['primary'],
            highlightbackground=cs['border_color']
        )
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        self.chat_entry.bind("<Return>", lambda _e: self._send_chat_message())

        chat_send_btn = tk.Button(
            chat_input_frame,
            text="发送",
            font=("Arial", 9),
            bg=cs['bg_dark'],
            fg=cs['primary'],
            activebackground=cs['primary'],
            activeforeground=cs['bg_darker'],
            relief=tk.FLAT,
            bd=0,
            cursor='hand2',
            command=self._send_chat_message,
            highlightthickness=1,
            highlightbackground=cs['border_color'],
            padx=15,
            pady=4
        )
        chat_send_btn.pack(side=tk.RIGHT)
    
    def _init_scanner(self):
        """初始化扫描器"""
        try:
            if scanner_bridge.initialize():
                self._log("扫描器初始化成功")
                modules = scanner_bridge.get_modules()
                self._log(f"已加载 {len(modules)} 个扫描模块")
            else:
                self._log("扫描器初始化失败", "ERROR")
        except Exception as e:
            self._log(f"初始化错误: {e}", "ERROR")
    
    def _init_ai_analyzer(self, force: bool = False):
        """初始化AI分析器"""
        try:
            if self.ai_analyzer and not force:
                return True
            
            # 统一使用 DeepSeek，允许通过界面选择模型和温度
            model = self.ai_model_var.get() if hasattr(self, "ai_model_var") else os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
            try:
                temperature = float(self.ai_temp_var.get() if hasattr(self, "ai_temp_var") else os.getenv("DEEPSEEK_TEMPERATURE", "0.7"))
            except Exception:
                temperature = 0.7

            ai_service = DeepSeekClient(model=model, temperature=temperature)
            self._log(f"AI服务: DeepSeek (model={model}, temp={temperature})", "INFO")
            
            # 创建AI分析器
            self.ai_analyzer = AIAnalyzer(ai_service=ai_service)
            
            # 创建批量分析器
            self.batch_analyzer = BatchAnalyzer(
                max_concurrent=5,
                ai_analyzer=self.ai_analyzer
            )
            
            # 创建修复生成器
            self.fix_generator = FixGenerator(ai_service_adapter=ai_service)
            
            self._log("AI分析器初始化成功")
            
            return True
        except Exception as e:
            import traceback
            error_msg = f"AI分析器初始化失败: {e}"
            self._log(error_msg, "ERROR")
            traceback.print_exc()
            return False
    
    def _log(self, message: str, level: str = "INFO"):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.message_queue.put(("log", f"[{timestamp}] [{level}] {message}\n"))
    
    def _update_status(self, text: str):
        """更新状态"""
        self.message_queue.put(("status", text))
    
    def _update_progress(self, value: int, text: str):
        """更新进度"""
        self.message_queue.put(("progress", (value, text)))
    
    def _add_result(self, result_data: Dict):
        """添加结果"""
        self.message_queue.put(("result", result_data))
    
    def _process_messages(self):
        """处理消息队列"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == "log":
                    self.log_text.insert(tk.END, data)
                    self.log_text.see(tk.END)
                elif msg_type == "status":
                    self.status_label.config(text=data)
                    self.bottom_status.config(text=f"状态: {data}")
                elif msg_type == "progress":
                    value, text = data
                    self.progress_bar['value'] = value
                    self.status_label.config(text=text)
                elif msg_type == "result":
                    self._display_result(data)
                elif msg_type == "count":
                    self.result_count.config(text=f"发现: {data} 个结果")
                elif msg_type == "scan_complete":
                    self._on_scan_complete(data)
                elif msg_type == "scan_error":
                    self._on_scan_error(data)
                elif msg_type == "ai_complete":
                    self._log(f"AI分析完成，分析了 {data} 个漏洞")
                    self._update_status("AI分析完成")
                elif msg_type == "ai_error":
                    self._log(f"AI分析错误: {data}", "ERROR")
                    self._update_status("AI分析失败")
                elif msg_type == "fix_complete":
                    self._log(f"修复建议生成完成，共 {data} 条建议")
                    self._update_status("修复建议完成")
                elif msg_type == "fix_error":
                    self._log(f"修复建议错误: {data}", "ERROR")
                    self._update_status("修复建议失败")
                elif msg_type == "chat_message":
                    # AI对话消息展示（非流式，保留用于向后兼容）
                    if hasattr(self, "chat_text"):
                        self.chat_text.insert(tk.END, f"AI: {data}\n", "ai")
                        self.chat_text.see(tk.END)
                elif msg_type == "chat_start_ai":
                    # 开始AI回复，插入AI前缀
                    if hasattr(self, "chat_text"):
                        self.chat_text.insert(tk.END, "AI: ", "ai")
                        self.chat_text.see(tk.END)
                elif msg_type == "chat_stream_chunk":
                    # 流式输出的文本块，使用ai标签插入
                    if hasattr(self, "chat_text"):
                        self.chat_text.insert(tk.END, data, "ai")
                        self._scroll_to_bottom()
                elif msg_type == "chat_stream_end":
                    # 流式输出结束，插入换行和分隔线
                    if hasattr(self, "chat_text"):
                        self.chat_text.insert(tk.END, "\n", "ai")
                        
                        # 创建第一条分隔线 Canvas
                        line1_canvas = tk.Canvas(self.chat_text_frame, height=2, bg=self.colors['input_bg'], highlightthickness=0)
                        def draw_line1(width):
                            line1_canvas.delete("all")
                            line1_canvas.create_line(0, 1, width, 1, fill="black", width=2)
                        line1_canvas.draw_line = draw_line1
                        
                        self.chat_text.window_create(tk.END, window=line1_canvas, stretch=tk.YES, padx=0)
                        
                        # 创建第二条分隔线 Canvas
                        line2_canvas = tk.Canvas(self.chat_text_frame, height=2, bg=self.colors['input_bg'], highlightthickness=0)
                        def draw_line2(width):
                            line2_canvas.delete("all")
                            line2_canvas.create_line(0, 1, width, 1, fill="black", width=2)
                        line2_canvas.draw_line = draw_line2
                        
                        self.chat_text.window_create(tk.END, window=line2_canvas, stretch=tk.YES, padx=0)
                        
                        # 存储 Canvas 引用
                        self.separator_canvases.extend([line1_canvas, line2_canvas])
                        
                        # 初始绘制
                        self.root.after(10, lambda: self._update_all_separators())
                        
                        # 添加一个换行符
                        self.chat_text.insert(tk.END, "\n")
                        self._scroll_to_bottom()
                    
        except queue.Empty:
            pass
        
        self.root.after(100, self._process_messages)
    
    def _display_result(self, result_data: Dict):
        """显示单个结果"""
        result = ScanResultAdapter(result_data)
        self.scan_results.append(result)
        
        severity = result.severity.upper()
        
        item_id = self.results_tree.insert(
            "",
            tk.END,
            values=(
                severity,
                result.result_type,
                result.title[:50],
                result.target[:35]
            )
        )
        
        # 设置颜色标签
        color_map = {
            'CRITICAL': self.colors['critical'],
            'HIGH': self.colors['high'],
            'MEDIUM': self.colors['medium'],
            'LOW': self.colors['low'],
            'INFO': self.colors['info']
        }
        
        self.results_tree.tag_configure(severity, foreground=color_map.get(severity, self.colors['fg']))
        self.results_tree.item(item_id, tags=(severity,))
        
        self.result_count.config(text=f"发现: {len(self.scan_results)} 个结果")
    
    def _on_result_select(self, event):
        """选择结果时显示详情"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        index = self.results_tree.index(item)
        
        if index < len(self.scan_results):
            result = self.scan_results[index]
            
            detail = f"""{'='*60}
标题: {result.title}
{'='*60}

类型: {result.result_type}
严重程度: {result.severity.upper()}
目标: {result.target}

描述:
{result.description}

证据:
{result.evidence}

原始数据:
{json.dumps(result.raw_data, indent=2, ensure_ascii=False) if result.raw_data else 'N/A'}

时间: {datetime.fromtimestamp(result.timestamp).strftime('%Y-%m-%d %H:%M:%S') if result.timestamp else 'N/A'}
"""
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, detail)
            
            # 切换到详情页
            self.notebook.select(1)
    
    def _start_scan(self):
        """开始扫描"""
        target = self.target_entry.get().strip()
        
        if not target:
            messagebox.showwarning("警告", "请输入扫描目标！")
            return
        
        # 获取选中的模块
        selected_modules = [k for k, v in self.module_vars.items() if v.get()]
        
        if not selected_modules:
            messagebox.showwarning("警告", "请至少选择一个扫描模块！")
            return
        
        # 清空之前的结果
        self._clear_results()
        
        # 更新UI状态
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self._log(f"开始扫描目标: {target}")
        self._log(f"选中模块: {', '.join(selected_modules)}")
        self._update_status("扫描中...")
        self._update_progress(0, "正在初始化...")
        
        # 获取配置
        try:
            timeout = int(self.timeout_var.get())
            concurrency = int(self.concurrency_var.get())
        except ValueError:
            timeout, concurrency = 10, 50
        
        # 在后台线程执行扫描
        scan_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(target, selected_modules, timeout, concurrency),
            daemon=True
        )
        scan_thread.start()
    
    def _run_scan_thread(self, target: str, modules: List[str], timeout: int, concurrency: int):
        """扫描线程"""
        try:
            # 创建事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self._update_progress(10, "正在连接目标...")
            
            # 执行扫描
            async def do_scan():
                return await scanner_bridge.scan(target, modules, timeout, concurrency)
            
            result = loop.run_until_complete(do_scan())
            loop.close()
            
            self._update_progress(50, "正在处理结果...")
            
            # 处理结果
            total = len(result.get('results', []))
            for i, res in enumerate(result.get('results', [])):
                self._add_result(res)
                progress = 50 + int((i + 1) / max(total, 1) * 50)
                self._update_progress(progress, f"处理结果 {i+1}/{total}")
            
            self._update_progress(100, "扫描完成")
            self.message_queue.put(("scan_complete", result))
            
        except Exception as e:
            self.message_queue.put(("scan_error", str(e)))
    
    def _on_scan_complete(self, result: Dict):
        """扫描完成处理"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log(f"扫描完成，发现 {len(self.scan_results)} 个结果")
        self._update_status("扫描完成")
        
        # 记录本次扫描概要信息，供报告导出使用
        self._last_scan_summary = result

        # 更新统计信息
        severity_count = {}
        for res in self.scan_results:
            sev = res.severity
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        stats = f"""{'='*50}
扫描统计报告
{'='*50}

目标: {result.get('target', 'N/A')}
开始时间: {datetime.fromtimestamp(result.get('start_time', 0)).strftime('%Y-%m-%d %H:%M:%S')}
持续时间: {result.get('duration', 0):.2f} 秒

{'='*50}
结果统计
{'='*50}

总发现数: {len(self.scan_results)}

严重程度分布:
"""
        for sev, count in sorted(severity_count.items()):
            stats += f"  {sev.upper()}: {count} 个\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)
        
        # 切换到统计页
        self.notebook.select(3)
        
        # 显示完成提示
        messagebox.showinfo(
            "扫描完成",
            f"扫描已完成！\n\n目标: {result.get('target', 'N/A')}\n发现: {len(self.scan_results)} 个结果\n耗时: {result.get('duration', 0):.2f} 秒"
        )
    
    def _on_scan_error(self, error_msg: str):
        """扫描错误处理"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log(f"扫描错误: {error_msg}", "ERROR")
        self._update_status(f"错误: {error_msg}")
        
        messagebox.showerror("扫描错误", f"扫描过程中发生错误:\n{error_msg}")
    
    def _stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log("用户停止扫描")
        self._update_status("已停止")
    
    def _toggle_theme(self):
        """切换主题"""
        success = self.theme_engine.toggle_theme()
        if success:
            theme_info = self.theme_engine.get_current_theme()
            mode_name = "深色模式" if theme_info['mode'] == "dark" else "浅色模式"
            self._log(f"主题已切换至: {theme_info['name']} ({mode_name})")
            self.config_manager.save_theme_config(theme_info['name'], theme_info['mode'])
            # 保持发光边框底色
            self.root.config(bg='#0a1a14')
        else:
            self._log("主题切换失败")
    
    def _export_report(self):
        """导出报告"""
        if not self.scan_results:
            messagebox.showwarning("警告", "没有扫描结果可导出！")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[
                ("HTML报告", "*.html"),
                ("JSON报告", "*.json"),
                ("文本报告", "*.txt")
            ],
            title="导出报告"
        )
        
        if not file_path:
            return
        
        try:
            # 使用核心 ReportGenerator 生成 HTML/JSON 报告（带 AI 摘要）
            if file_path.endswith(('.html', '.json')):
                # 将 GUI 结果转换为核心 ScanResult 列表
                from core.base import ScanResult, ResultType, Severity

                core_results = []
                for adapter in self.scan_results:
                    try:
                        result_type = ResultType(adapter.result_type)
                    except Exception:
                        result_type = ResultType.INFO
                    try:
                        severity = Severity(adapter.severity)
                    except Exception:
                        severity = Severity.INFO

                    core_results.append(ScanResult(
                        result_type=result_type,
                        title=adapter.title,
                        description=adapter.description,
                        severity=severity,
                        target=adapter.target,
                        evidence=adapter.evidence,
                        raw_data=adapter.raw_data
                    ))

                # 构造 ScanReport
                summary = getattr(self, "_last_scan_summary", {}) or {}
                start_time = summary.get("start_time", datetime.now().timestamp())
                end_time = summary.get("end_time", datetime.now().timestamp())
                module_stats = summary.get("module_stats", [])

                scan_report = ScanReport(
                    target=summary.get("target", self.target_entry.get()),
                    start_time=start_time,
                    end_time=end_time,
                    results=core_results,
                    module_stats=module_stats,
                )

                fmt = 'json' if file_path.endswith('.json') else 'html'
                generator = ReportGenerator()
                generator.generate(scan_report, file_path, format=fmt)
            else:
                # 纯文本报告仍然使用本地简易生成器
                text = self._generate_text_report()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(text)
            
            messagebox.showinfo("成功", f"报告已导出到:\n{file_path}")
            self._log(f"报告已导出: {file_path}")
            
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
    
    def _generate_html_report(self) -> str:
        """生成HTML报告"""
        target = self.target_entry.get()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PySecScanner 扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        .result {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #00d4ff; }}
        .critical {{ border-left-color: #ff4757; }}
        .high {{ border-left-color: #ff6b6b; }}
        .medium {{ border-left-color: #ffa502; }}
        .low {{ border-left-color: #2ed573; }}
        .info {{ border-left-color: #70a1ff; }}
        .severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 10px; }}
        pre {{ background: #0f0f1a; padding: 10px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>PySecScanner 扫描报告</h1>
    <p><strong>目标:</strong> {target}</p>
    <p><strong>扫描时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>发现数量:</strong> {len(self.scan_results)} 个</p>
    <hr>
    <h2>扫描结果</h2>
"""
        
        for result in self.scan_results:
            html += f"""
    <div class="result {result.severity}">
        <p><span class="severity">{result.severity.upper()}</span><strong>{result.title}</strong></p>
        <p><strong>类型:</strong> {result.result_type} | <strong>目标:</strong> {result.target}</p>
        <p>{result.description}</p>
        <pre>{result.evidence}</pre>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def _generate_text_report(self) -> str:
        """生成文本报告"""
        target = self.target_entry.get()
        
        text = f"""
{'='*60}
PySecScanner 扫描报告
{'='*60}

目标: {target}
扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
发现数量: {len(self.scan_results)} 个

{'='*60}
扫描结果
{'='*60}
"""
        
        for i, result in enumerate(self.scan_results, 1):
            text += f"""
[{i}] {result.title}
    严重程度: {result.severity.upper()}
    类型: {result.result_type}
    目标: {result.target}
    描述: {result.description}
    证据: {result.evidence[:200]}
"""
        
        return text
    
    def _clear_results(self):
        """清空结果"""
        self.scan_results.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.log_text.delete(1.0, tk.END)
        self.detail_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.ai_text.delete(1.0, tk.END)
        self.fix_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.result_count.config(text="发现: 0 个结果")
        self._update_status("就绪")
    
    def _start_ai_analysis(self):
        """启动AI分析"""
        if not self.scan_results:
            messagebox.showwarning("警告", "请先进行扫描获取结果！")
            return
        
        if not self.ai_analyzer or not self.batch_analyzer:
            # 重新初始化AI分析器
            if not self._init_ai_analyzer():
                messagebox.showerror("错误", "AI分析器初始化失败！")
                return
        
        self._log("开始AI分析...")
        self._update_status("AI分析中...")
        
        # 启动AI分析线程
        ai_thread = threading.Thread(target=self._run_ai_analysis_thread, daemon=True)
        ai_thread.start()
    
    def _run_ai_analysis_thread(self):
        """AI分析线程"""
        try:
            from core.base import ScanResult, ResultType, Severity
            
            # 将扫描结果适配器转换为ScanResult对象
            scan_results = []
            for result_adapter in self.scan_results:
                # GUI里的result_type/severity通常是字符串，这里转换为枚举以匹配核心数据结构
                try:
                    result_type = ResultType(result_adapter.result_type)
                except Exception:
                    result_type = ResultType.INFO
                
                try:
                    severity = Severity(result_adapter.severity)
                except Exception:
                    severity = Severity.INFO
                
                scan_result = ScanResult(
                    result_type=result_type,
                    title=result_adapter.title,
                    description=result_adapter.description,
                    severity=severity,
                    target=result_adapter.target,
                    evidence=result_adapter.evidence,
                    raw_data=result_adapter.raw_data
                )
                scan_results.append(scan_result)
            
            # 使用批量分析器进行分析
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def do_analysis():
                # 创建进度回调
                def progress_callback(progress_dict):
                    current = progress_dict.get('completed', 0)
                    total = progress_dict.get('total', 1)
                    progress = int(current / total * 100)
                    self.message_queue.put(("progress", (progress, f"AI分析: {current}/{total}")))
                
                # 执行批量分析，返回分析结果列表
                analysis_results = await self.batch_analyzer.analyze_batch(
                    results=scan_results,
                    on_progress=progress_callback
                )
                
                return analysis_results
            
            analysis_results = loop.run_until_complete(do_analysis())
            loop.close()
            
            # 输出调试信息
            print(f"=== AI分析完成，返回 {len(analysis_results)} 个分析结果 ===")
            for i, result in enumerate(analysis_results):
                print(f"分析结果 {i+1}:")
                print(f"  类型: {type(result)}")
                print(f"  结果对象: {result}")
                if hasattr(result, 'to_dict'):
                    result_dict = result.to_dict()
                    print(f"  字典形式: {result_dict}")
            
            # 处理分析结果
            self._display_ai_results(analysis_results)
            
            self.message_queue.put(("ai_complete", len(analysis_results)))

            # 如用户勾选“自动生成修复建议”，在AI分析完成后直接生成
            try:
                if hasattr(self, "auto_fix_var") and self.auto_fix_var.get():
                    self._log("AI分析完成，自动开始生成修复建议...")
                    # 自动生成修复建议时，不标记为用户请求，这样不会自动切换到修复建议标签页
                    self._fix_requested_by_user = False
                    fix_thread = threading.Thread(target=self._run_fix_generation_thread, daemon=True)
                    fix_thread.start()
            except Exception:
                # 自动流程失败不影响AI分析结果展示
                pass
            
        except Exception as e:
            import traceback
            print(f"=== AI分析线程异常: {e} ===")
            traceback.print_exc()
            self.message_queue.put(("ai_error", str(e)))
    
    def _display_ai_results(self, analysis_results):
        """显示AI分析结果"""
        self.ai_analysis_results = []
        
        formatted = "=" * 70 + "\n"
        formatted += "AI智能分析报告\n"
        formatted += "=" * 70 + "\n\n"
        
        for i, analysis in enumerate(analysis_results, 1):
            formatted += f"[{i}] 分析结果\n"
            formatted += "-" * 50 + "\n"
            
            # 获取原始扫描结果
            if i <= len(self.scan_results):
                result_adapter = self.scan_results[i-1]
                formatted += f"漏洞: {result_adapter.title}\n"
                formatted += f"目标: {result_adapter.target}\n"
            
            # 检查分析结果类型
            if analysis is None:
                formatted += "分析结果: (无)\n"
            elif hasattr(analysis, 'to_dict'):
                # AIAnalysisResult对象
                analysis_dict = analysis.to_dict()
                formatted += f"根因: {analysis_dict.get('root_cause', '未知')}\n"
                formatted += f"影响范围: {analysis_dict.get('impact_scope', '未知')}\n"
                formatted += f"攻击路径: {analysis_dict.get('attack_path', '未知')}\n"
                
                cvss_score = analysis_dict.get('cvss_score', 0)
                formatted += f"CVSS评分: {cvss_score}\n"
                
                cvss_justification = analysis_dict.get('cvss_justification', '')
                if cvss_justification:
                    formatted += f"CVSS依据: {cvss_justification}\n"
                
                additional = analysis_dict.get('additional_insights', {})
                if additional:
                    formatted += self._format_additional_insights(additional)
                
                self.ai_analysis_results.append(analysis_dict)
            elif isinstance(analysis, dict):
                # 字典类型
                formatted += f"根因: {analysis.get('root_cause', '未知')}\n"
                formatted += f"影响范围: {analysis.get('impact_scope', '未知')}\n"
                formatted += f"CVSS评分: {analysis.get('cvss_score', 0)}\n"
                self.ai_analysis_results.append(analysis)
            else:
                formatted += f"分析结果类型: {type(analysis).__name__}\n"
                formatted += f"分析结果: {str(analysis)}\n"
                if hasattr(analysis, '__dict__'):
                    # 尝试获取属性
                    attrs = {k: v for k, v in analysis.__dict__.items() if not k.startswith('_')}
                    if attrs:
                        formatted += f"属性: {attrs}\n"
            
            formatted += "\n"
        
        self.ai_text.delete(1.0, tk.END)
        self.ai_text.insert(1.0, formatted)
        
        # 切换到AI分析页
        self.notebook.select(4)
        
        self._log(f"AI分析完成，共 {len(analysis_results)} 个结果")

    def _format_additional_insights(self, additional: Dict[str, Any]) -> str:
        """将additional_insights格式化为更易读的中文说明"""
        lines = []

        # 简单字段的中文映射
        simple_map = {
            "model": "使用模型",
            "vulnerability_type": "漏洞类型",
            "ai_analysis": "AI分析原文",
            "risk_assessment": "风险评估",
            "url": "URL",
            "sensitive_type": "敏感信息类型",
        }

        # 先处理简单键
        for key, label in simple_map.items():
            if key in additional and additional.get(key) not in (None, "", []):
                value = additional[key]
                if isinstance(value, list):
                    value_str = "；".join(str(v) for v in value)
                else:
                    value_str = str(value)
                lines.append(f"{label}: {value_str}")

        # recommended_actions 专门处理为清单
        if "recommended_actions" in additional and additional["recommended_actions"]:
            actions = additional["recommended_actions"]
            if isinstance(actions, list):
                lines.append("推荐处置步骤：")
                for a in actions:
                    lines.append(f"  - {a}")
            else:
                lines.append(f"推荐处置步骤: {actions}")

        # 漏洞链分析单独美化
        vchain = additional.get("vulnerability_chain_analysis")
        if isinstance(vchain, dict):
            desc = vchain.get("description", "")
            combos = vchain.get("potential_combinations", [])
            related = vchain.get("related_vulnerabilities", {})
            reco = vchain.get("recommendation", "")

            lines.append("漏洞链分析：")
            if desc:
                lines.append(f"  说明: {desc}")
            if combos:
                lines.append("  可能的组合利用：")
                for c in combos:
                    lines.append(f"    - {c}")
            if related:
                lines.append("  相关漏洞关联：")
                for k, vs in related.items():
                    vs_str = "，".join(vs) if isinstance(vs, list) else str(vs)
                    lines.append(f"    - {k} → {vs_str}")
            if reco:
                lines.append(f"  建议: {reco}")

        if not lines:
            return ""

        return "额外洞察：\n" + "\n".join(lines) + "\n"

    def _update_all_separators(self, event=None):
        """更新所有分隔线的宽度"""
        if not hasattr(self, 'separator_canvases'):
            return
            
        if event:
            text_width = self.chat_text.winfo_width()
            # 减去内边距
            content_width = text_width - 20  # padx=10 on both sides
        else:
            content_width = 800
            
        for canvas in self.separator_canvases:
            if hasattr(canvas, 'draw_line'):
                content_width = content_width if content_width > 1 else 800
                canvas.configure(width=content_width)
                canvas.delete("all")
                canvas.draw_line(content_width)
    
    def _scroll_to_bottom(self):
        """滚动到对话底部"""
        if hasattr(self, "chat_text"):
            self.chat_text.see(tk.END)
    
    def _send_chat_message(self):
        """发送AI对话消息"""
        if not hasattr(self, "chat_entry"):
            return
        content = self.chat_entry.get().strip()
        if not content:
            return

        # 插入用户消息到文本框，使用user标签靠右对齐
        if hasattr(self, "chat_text"):
            self.chat_text.insert(tk.END, content + "\n", "user")
            
            # 创建第一条分隔线 Canvas
            line1_canvas = tk.Canvas(self.chat_text_frame, height=2, bg=self.colors['input_bg'], highlightthickness=0)
            # 为 Canvas 添加绘制方法
            def draw_line1(width):
                line1_canvas.delete("all")
                line1_canvas.create_line(0, 1, width, 1, fill="black", width=2)
            line1_canvas.draw_line = draw_line1
            
            # 将 Canvas 直接插入 ScrolledText, stretch=YES 使其占满整个宽度
            self.chat_text.window_create(tk.END, window=line1_canvas, stretch=tk.YES, padx=0)
            
            # 创建第二条分隔线 Canvas
            line2_canvas = tk.Canvas(self.chat_text_frame, height=2, bg=self.colors['input_bg'], highlightthickness=0)
            def draw_line2(width):
                line2_canvas.delete("all")
                line2_canvas.create_line(0, 1, width, 1, fill="black", width=2)
            line2_canvas.draw_line = draw_line2
            
            self.chat_text.window_create(tk.END, window=line2_canvas, stretch=tk.YES, padx=0)
            
            # 存储 Canvas 引用
            self.separator_canvases.extend([line1_canvas, line2_canvas])
            
            # 初始绘制
            self.root.after(10, lambda: self._update_all_separators())
            
            # 添加一个换行符
            self.chat_text.insert(tk.END, "\n")
            self.chat_text.see(tk.END)
        
        self.chat_entry.delete(0, tk.END)

        # 启动后台线程调用AI（使用流式输出）
        t = threading.Thread(target=self._run_chat_thread, args=(content,), daemon=True)
        t.start()

    def _run_chat_thread(self, user_msg: str):
        """AI对话线程：基于当前扫描结果与DeepSeek对话（支持流式输出）"""
        try:
            # 构造当前扫描摘要（最多10条）
            summary_parts = []
            for i, r in enumerate(self.scan_results[:10], 1):
                summary_parts.append(
                    f"[{i}] {r.severity.upper()} {r.title} @ {r.target}\n"
                    f"  描述: {r.description}\n"
                )
            summary_text = "".join(summary_parts) if summary_parts else "当前没有扫描结果。"

            system_prompt = (
                "你是一名资深渗透测试工程师，正在根据扫描结果回答用户的问题。"
                "请使用简体中文回答，可以结合扫描结果中的具体漏洞标题、严重程度和目标。"
            )

            messages = [{"role": "system", "content": system_prompt}]
            # 附带最近几轮对话历史
            for m in self.chat_history[-6:]:
                messages.append(m)
            messages.append({
                "role": "user",
                "content": f"当前扫描摘要：\n{summary_text}\n\n用户问题：{user_msg}"
            })

            # 使用当前模型和温度参数
            model = self.ai_model_var.get() if hasattr(self, "ai_model_var") else "deepseek-chat"
            try:
                temperature = float(self.ai_temp_var.get() if hasattr(self, "ai_temp_var") else 0.7)
            except Exception:
                temperature = 0.7

            client = DeepSeekClient(model=model, temperature=temperature)
            
            # 用于收集完整的响应文本
            full_answer = []
            
            # 在开始AI回复前,先创建一个空的AI消息气泡
            self.message_queue.put(("chat_start_ai", ""))
            
            # 定义流式输出回调函数
            def stream_callback(chunk: str):
                """每次收到流式数据块时的回调函数"""
                full_answer.append(chunk)
                
                # 将流式数据块发送到消息队列,实时更新UI
                self.message_queue.put(("chat_stream_chunk", chunk))
            
            async def _call_stream():
                """使用流式API调用"""
                return await client._call_api_streaming(messages, callback=stream_callback)
            
            import asyncio
            full_answer_text = asyncio.run(_call_stream())
            
            # 将完整的响应文本用于记录历史
            full_answer_str = full_answer_text if full_answer_text else "".join(full_answer)

            # 记录对话历史
            self.chat_history.append({"role": "user", "content": user_msg})
            self.chat_history.append({"role": "assistant", "content": full_answer_str})

            # 发送完成消息
            self.message_queue.put(("chat_stream_end", ""))
        except Exception as e:
            self.message_queue.put(("chat_stream_chunk", f"\n[AI错误] {e}"))
    
    def _generate_fix_suggestions(self):
        """生成修复建议"""
        if not self.ai_analysis_results:
            messagebox.showwarning("警告", "请先进行AI分析！")
            return
        
        if not self.fix_generator:
            messagebox.showerror("错误", "修复生成器未初始化！")
            return
        
        self._log("开始生成修复建议...")
        self._update_status("生成修复建议中...")
        # 标记为用户主动请求，用于决定是否自动切换到“修复建议”标签页
        self._fix_requested_by_user = True
        
        # 启动修复生成线程
        fix_thread = threading.Thread(target=self._run_fix_generation_thread, daemon=True)
        fix_thread.start()
    
    def _run_fix_generation_thread(self):
        """修复建议生成线程"""
        try:
            from core.base import ScanResult, ResultType, Severity
            from modules.ai.ai_service_adapter import AIAnalysisResult
            
            # 将扫描结果适配器转换为ScanResult对象
            scan_results = []
            for result_adapter in self.scan_results:
                # GUI里的result_type/severity通常是字符串，这里转换为枚举以匹配核心数据结构
                try:
                    result_type = ResultType(result_adapter.result_type)
                except Exception:
                    result_type = ResultType.INFO
                
                try:
                    severity = Severity(result_adapter.severity)
                except Exception:
                    severity = Severity.INFO
                
                scan_result = ScanResult(
                    result_type=result_type,
                    title=result_adapter.title,
                    description=result_adapter.description,
                    severity=severity,
                    target=result_adapter.target,
                    evidence=result_adapter.evidence,
                    raw_data=result_adapter.raw_data
                )
                scan_results.append(scan_result)
            
            # 创建事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def generate_fixes():
                fix_suggestions = []
                total = len(scan_results)
                
                for i, result in enumerate(scan_results):
                    try:
                        progress = int((i + 1) / total * 100)
                        self.message_queue.put(("progress", (progress, f"生成修复建议: {result.title}")))
                        
                        # 如果存在 AI 分析结果，则一并传入，驱动 AI 修复逻辑
                        analysis = None
                        if self.ai_analysis_results and i < len(self.ai_analysis_results):
                            ar = self.ai_analysis_results[i]
                            if isinstance(ar, dict):
                                analysis = AIAnalysisResult(
                                    root_cause=ar.get("root_cause", ""),
                                    impact_scope=ar.get("impact_scope", ""),
                                    attack_path=ar.get("attack_path", ""),
                                    cvss_score=ar.get("cvss_score", 0.0),
                                    cvss_justification=ar.get("cvss_justification", ""),
                                    additional_insights=ar.get("additional_insights", {}),
                                )

                        fix = await self.fix_generator.generate_fix(result, analysis)
                        fix_suggestions.append(fix)
                        
                        print(f"  - 修复建议 {i+1}/{total}: {fix.get('vulnerability_type', '未知')}")
                    except Exception as e:
                        print(f"  - 结果 {i+1}: 失败 - {e}")
                        import traceback
                        traceback.print_exc()
                
                return fix_suggestions
            
            fix_suggestions = loop.run_until_complete(generate_fixes())
            loop.close()
            
            # 处理修复建议
            self._display_fix_suggestions(fix_suggestions)
            
            self.message_queue.put(("fix_complete", len(fix_suggestions)))
            
        except Exception as e:
            import traceback
            print(f"=== 修复建议线程异常: {e} ===")
            traceback.print_exc()
            self.message_queue.put(("fix_error", str(e)))
    
    def _display_fix_suggestions(self, fix_suggestions):
        """显示修复建议"""
        self.fix_suggestions = []
        
        formatted = "=" * 70 + "\n"
        formatted += "修复建议报告\n"
        formatted += "=" * 70 + "\n\n"
        
        for i, fix in enumerate(fix_suggestions, 1):
            # 获取修复建议字典
            if hasattr(fix, 'to_dict'):
                fix_dict = fix.to_dict()
            elif isinstance(fix, dict):
                fix_dict = fix
            else:
                fix_dict = {}
            
            self.fix_suggestions.append(fix_dict)
            
            formatted += f"[{i}] 修复建议\n"
            formatted += "-" * 50 + "\n"
            
            # 标题
            title = fix_dict.get('title', '未知')
            if title:
                formatted += f"标题: {title}\n"
            else:
                formatted += f"标题: (无)\n"
            
            # 漏洞类型
            vuln_type = fix_dict.get('vulnerability_type', '未知')
            if vuln_type:
                formatted += f"漏洞类型: {vuln_type}\n"
            else:
                formatted += f"漏洞类型: (无)\n"
            
            # 修复类型
            fix_type = fix_dict.get('fix_type', '未知')
            if fix_type:
                formatted += f"修复类型: {fix_type}\n"
            else:
                formatted += f"修复类型: (无)\n"
            
            # 优先级
            priority = fix_dict.get('priority', '未知')
            formatted += f"优先级: {priority.upper() if isinstance(priority, str) else str(priority)}\n"
            
            # 描述
            description = fix_dict.get('description', '')
            if description:
                formatted += f"描述:\n{description}\n"
            
            # 步骤
            if 'steps' in fix_dict:
                steps = fix_dict.get('steps')
                if steps:
                    formatted += f"修复步骤:\n"
                    if isinstance(steps, list):
                        for j, step in enumerate(steps, 1):
                            formatted += f"  {j}. {step}\n"
                    elif isinstance(steps, str):
                        formatted += f"  {steps}\n"
                    else:
                        formatted += f"  {str(steps)}\n"
                else:
                    formatted += "修复步骤: (无)\n"
            
            # 代码示例
            if 'code_example' in fix_dict:
                code_example = fix_dict['code_example']
                if isinstance(code_example, dict):
                    formatted += "代码示例:\n"
                    for lang, code in code_example.items():
                        formatted += f"  {lang}:\n"
                        if isinstance(code, str):
                            formatted += f"    {code}\n"
                        elif isinstance(code, list):
                            for line in code:
                                formatted += f"    {line}\n"
                    formatted += "\n"
                else:
                    formatted += "代码示例: (无)\n"
            
            formatted += "\n"
        
        self.fix_text.delete(1.0, tk.END)
        self.fix_text.insert(1.0, formatted)
        
        # 只有当用户主动点击“生成修复建议”按钮时才自动切换到修复建议页
        if getattr(self, "_fix_requested_by_user", False):
            self.notebook.select(5)
        
        self._log(f"修复建议生成完成，共 {len(fix_suggestions)} 条建议")
    
    # ========== 侧边栏导航与动画 ==========
    
    def _nav_to_section(self, section_id):
        """导航到侧边栏指定区域，激活对应按钮"""
        cs = ThemeEngine.COLOR_SYSTEM
        
        # 重置所有导航按钮为Outline风格（未选中）
        for nid, btn in self._nav_buttons.items():
            btn.config(bg=cs['bg_darker'], fg=cs['fg_secondary'])
        
        # 激活选中按钮（填充 primary 色）
        active_btn = self._nav_buttons.get(section_id)
        if active_btn:
            active_btn.config(bg=cs['primary'], fg=cs['bg_darker'])
        self._active_nav_btn = active_btn
        
        # 滚动到对应区域
        section_map = {
            'scan': getattr(self, '_scan_section', None),
            'ai': getattr(self, '_ai_section', None),
        }
        target = section_map.get(section_id)
        if target and hasattr(self, '_sidebar_canvas'):
            try:
                # 计算目标区域在scroll_content中的y坐标
                y = target.winfo_y()
                bbox = self._sidebar_canvas.bbox("all")
                if bbox and bbox[3] > 0:
                    self._sidebar_canvas.yview_moveto(y / bbox[3])
            except Exception:
                pass
    
    def _animate_progressbar(self):
        """进度条条纹脉冲动画（模拟数据流动感）"""
        if not hasattr(self, 'progress_bar') or not self.progress_bar.winfo_exists():
            return
        
        if self.is_scanning:
            cs = ThemeEngine.COLOR_SYSTEM
            self._stripe_offset = getattr(self, '_stripe_offset', 0) + 1
            # 在两种色调之间交替，模拟条纹流动效果
            if self._stripe_offset % 2 == 0:
                self.theme_engine.style.configure('striped.Horizontal.TProgressbar',
                    background=cs['primary'])
            else:
                self.theme_engine.style.configure('striped.Horizontal.TProgressbar',
                    background='#00DD99')
        
        self.root.after(300, self._animate_progressbar)
    
    # ========== 无边框窗口：自定义标题栏 ==========
    
    def _create_title_bar(self):
        """创建自定义标题栏"""
        cs = ThemeEngine.COLOR_SYSTEM
        
        # 标题栏容器（高度36px，背景色使用 COLOR_SYSTEM['secondary']）
        title_bar = tk.Frame(self.root, bg=cs['secondary'], height=36)
        title_bar.pack(fill=tk.X, side=tk.TOP, padx=1, pady=(1, 0))
        title_bar.pack_propagate(False)
        self._title_bar = title_bar
        
        # 左侧：可拖拽区域 + 标题文字
        drag_area = tk.Frame(title_bar, bg=cs['secondary'])
        drag_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 应用标题
        title_label = tk.Label(
            drag_area,
            text="PySec Scanner",
            font=("Arial", 12, "bold"),
            bg=cs['secondary'],
            fg=cs['primary']
        )
        title_label.pack(side=tk.LEFT, padx=(10, 5))
        
        # 副标题
        subtitle_label = tk.Label(
            drag_area,
            text="安全扫描工具",
            font=("Arial", 9),
            bg=cs['secondary'],
            fg=cs['fg_secondary']
        )
        subtitle_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # 绑定拖拽移动事件到标题区域
        for widget in [title_bar, drag_area, title_label, subtitle_label]:
            widget.bind('<ButtonPress-1>', self._on_title_bar_press)
            widget.bind('<B1-Motion>', self._on_title_bar_drag)
        
        # 双击标题栏切换最大化
        for widget in [title_bar, drag_area, title_label, subtitle_label]:
            widget.bind('<Double-Button-1>', lambda e: self._on_maximize())
        
        # 右侧：控制按钮区域
        btn_area = tk.Frame(title_bar, bg=cs['secondary'])
        btn_area.pack(side=tk.RIGHT)
        
        # 主题切换按钮 🌓
        theme_btn = tk.Label(
            btn_area, text="🌓", font=("Arial", 10),
            bg=cs['secondary'], fg=cs['fg_secondary'],
            cursor='hand2', padx=10
        )
        theme_btn.pack(side=tk.LEFT, fill=tk.Y, pady=6)
        theme_btn.bind('<Button-1>', lambda e: self._toggle_theme())
        theme_btn.bind('<Enter>', lambda e: theme_btn.config(fg=cs['fg']))
        theme_btn.bind('<Leave>', lambda e: theme_btn.config(fg=cs['fg_secondary']))
        
        # 最小化按钮 ─
        min_btn = tk.Label(
            btn_area, text="─", font=("Arial", 10, "bold"),
            bg=cs['secondary'], fg=cs['fg_secondary'],
            cursor='hand2', padx=10
        )
        min_btn.pack(side=tk.LEFT, fill=tk.Y, pady=6)
        min_btn.bind('<Button-1>', lambda e: self._on_minimize())
        min_btn.bind('<Enter>', lambda e: min_btn.config(fg=cs['fg']))
        min_btn.bind('<Leave>', lambda e: min_btn.config(fg=cs['fg_secondary']))
        
        # 最大化/还原按钮 □
        self.max_btn = tk.Label(
            btn_area, text="□", font=("Arial", 10),
            bg=cs['secondary'], fg=cs['fg_secondary'],
            cursor='hand2', padx=10
        )
        self.max_btn.pack(side=tk.LEFT, fill=tk.Y, pady=6)
        self.max_btn.bind('<Button-1>', lambda e: self._on_maximize())
        self.max_btn.bind('<Enter>', lambda e: self.max_btn.config(fg=cs['fg']))
        self.max_btn.bind('<Leave>', lambda e: self.max_btn.config(fg=cs['fg_secondary']))
        
        # 关闭按钮 ✕
        close_btn = tk.Label(
            btn_area, text="✕", font=("Arial", 10),
            bg=cs['secondary'], fg=cs['fg_secondary'],
            cursor='hand2', padx=10
        )
        close_btn.pack(side=tk.LEFT, fill=tk.Y, pady=6)
        close_btn.bind('<Button-1>', lambda e: self._on_close())
        close_btn.bind('<Enter>', lambda e: close_btn.config(bg=cs['danger'], fg='#FFFFFF'))
        close_btn.bind('<Leave>', lambda e: close_btn.config(bg=cs['secondary'], fg=cs['fg_secondary']))
    
    def _on_title_bar_press(self, event):
        """标题栏按下 - 记录拖拽起始位置"""
        if self._is_maximized:
            return
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root
        self._window_x = self.root.winfo_x()
        self._window_y = self.root.winfo_y()
    
    def _on_title_bar_drag(self, event):
        """标题栏拖拽 - 移动窗口"""
        if self._is_maximized:
            # 最大化状态下拖拽，先还原窗口
            self.root.state('normal')
            self._is_maximized = False
            self.max_btn.config(text="□")
            if self._restore_geometry:
                self.root.geometry(self._restore_geometry)
            # 重新记录起始位置
            self._drag_start_x = event.x_root
            self._drag_start_y = event.y_root
            self._window_x = self.root.winfo_x()
            self._window_y = self.root.winfo_y()
            return
        
        dx = event.x_root - self._drag_start_x
        dy = event.y_root - self._drag_start_y
        new_x = self._window_x + dx
        new_y = self._window_y + dy
        self.root.geometry(f"+{new_x}+{new_y}")
    
    def _on_minimize(self):
        """最小化窗口"""
        self.root.iconify()
    
    def _on_maximize(self):
        """最大化/还原窗口切换"""
        if self._is_maximized:
            # 还原窗口
            if self._restore_geometry:
                self.root.geometry(self._restore_geometry)
            self._is_maximized = False
            self.max_btn.config(text="□")
        else:
            # 保存当前窗口位置和大小
            self._restore_geometry = (
                f"{self.root.winfo_width()}x{self.root.winfo_height()}"
                f"+{self.root.winfo_x()}+{self.root.winfo_y()}"
            )
            # 最大化到屏幕工作区
            screen_w = self.root.winfo_screenwidth()
            screen_h = self.root.winfo_screenheight()
            self.root.geometry(f"{screen_w}x{screen_h}+0+0")
            self._is_maximized = True
            self.max_btn.config(text="❐")
    
    def _on_close(self):
        """关闭窗口"""
        self.root.destroy()
    
    # ========== 无边框窗口：边缘调整大小 ==========
    
    def _setup_resize_handles(self):
        """设置窗口边缘调整大小手柄"""
        RESIZE_SIZE = 4
        bg_color = '#0a1a14'  # 与窗口背景一致
        
        # 右边缘
        right_handle = tk.Frame(self.root, width=RESIZE_SIZE, cursor='sb_h_double_arrow', bg=bg_color)
        right_handle.place(relx=1.0, x=-RESIZE_SIZE, rely=0.0, relheight=1.0)
        right_handle.bind('<ButtonPress-1>', lambda e, edge='e': self._on_resize_press(e, edge))
        right_handle.bind('<B1-Motion>', self._on_resize_drag)
        
        # 底部边缘
        bottom_handle = tk.Frame(self.root, height=RESIZE_SIZE, cursor='sb_v_double_arrow', bg=bg_color)
        bottom_handle.place(relx=0.0, rely=1.0, y=-RESIZE_SIZE, relwidth=1.0)
        bottom_handle.bind('<ButtonPress-1>', lambda e, edge='s': self._on_resize_press(e, edge))
        bottom_handle.bind('<B1-Motion>', self._on_resize_drag)
        
        # 右下角
        corner_handle = tk.Frame(self.root, width=RESIZE_SIZE * 2, height=RESIZE_SIZE * 2,
                                  cursor='size', bg=bg_color)
        corner_handle.place(relx=1.0, x=-RESIZE_SIZE * 2, rely=1.0, y=-RESIZE_SIZE * 2)
        corner_handle.bind('<ButtonPress-1>', lambda e, edge='se': self._on_resize_press(e, edge))
        corner_handle.bind('<B1-Motion>', self._on_resize_drag)
        
        # 左边缘
        left_handle = tk.Frame(self.root, width=RESIZE_SIZE, cursor='sb_h_double_arrow', bg=bg_color)
        left_handle.place(relx=0.0, rely=0.0, relheight=1.0)
        left_handle.bind('<ButtonPress-1>', lambda e, edge='w': self._on_resize_press(e, edge))
        left_handle.bind('<B1-Motion>', self._on_resize_drag)
    
    def _on_resize_press(self, event, edge):
        """边缘调整大小 - 按下记录起始状态"""
        self._resize_edge = edge
        self._resize_start_x = event.x_root
        self._resize_start_y = event.y_root
        self._resize_start_width = self.root.winfo_width()
        self._resize_start_height = self.root.winfo_height()
        self._resize_start_pos_x = self.root.winfo_x()
        self._resize_start_pos_y = self.root.winfo_y()
    
    def _on_resize_drag(self, event):
        """边缘调整大小 - 拖拽中"""
        if not self._resize_edge:
            return
        
        dx = event.x_root - self._resize_start_x
        dy = event.y_root - self._resize_start_y
        
        min_w = 1000
        min_h = 700
        edge = self._resize_edge
        
        new_w = self._resize_start_width
        new_h = self._resize_start_height
        new_x = self._resize_start_pos_x
        new_y = self._resize_start_pos_y
        
        if 'e' in edge:
            new_w = max(min_w, self._resize_start_width + dx)
        
        if 's' in edge:
            new_h = max(min_h, self._resize_start_height + dy)
        
        if 'w' in edge:
            potential_w = self._resize_start_width - dx
            if potential_w >= min_w:
                new_w = potential_w
                new_x = self._resize_start_pos_x + dx
        
        self.root.geometry(f"{new_w}x{new_h}+{new_x}+{new_y}")
    
    # ========== 无边框窗口：发光边框效果 ==========
    
    def _create_glow_border(self):
        """创建窗口外边框发光效果（使用Canvas绘制）"""
        cs = ThemeEngine.COLOR_SYSTEM
        
        # 创建底层Canvas用于绘制发光边框
        self._glow_canvas = tk.Canvas(
            self.root,
            highlightthickness=0,
            bg='#0a1a14'
        )
        # 使用place定位，但要确保不影响其他组件的布局
        self._glow_canvas.place(x=0, y=0, relwidth=1.0, relheight=1.0)
        
        def draw_glow(event=None):
            self._glow_canvas.delete('glow')
            w = self._glow_canvas.winfo_width()
            h = self._glow_canvas.winfo_height()
            if w > 2 and h > 2:
                # 绘制外边框发光线（使用primary色 #00FFAA）
                self._glow_canvas.create_rectangle(
                    0, 0, w - 1, h - 1,
                    outline=cs['primary'],
                    width=1,
                    tags='glow'
                )
        
        self._glow_canvas.bind('<Configure>', draw_glow)
    
    def run(self):
        """运行应用"""
        self.root.mainloop()


def main():
    """主入口"""
    app = PySecScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
