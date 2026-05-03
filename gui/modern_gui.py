"""
PySecScanner - 现代化GUI桌面客户端
====================================
基于 tkinter 8.6.15 + ttkbootstrap 1.20.2 的现代化界面改造示例
包含：侧边导航、卡片布局、交互动画、Toast通知、脉冲效果等

使用方法:
    cd pysec-scanner
    python gui/modern_gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import json
import asyncio
import os

# 导入主题引擎
try:
    from gui.theme_engine import ThemeEngine, StyleConfigManager, TTKBOOTSTRAP_AVAILABLE
    from core.database import Database
    from modules.ai.deepseek_client import DeepSeekClient
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from gui.theme_engine import ThemeEngine, StyleConfigManager, TTKBOOTSTRAP_AVAILABLE
    from core.database import Database
    from modules.ai.deepseek_client import DeepSeekClient


class ModernScannerGUI:
    """PySecScanner 现代化主界面"""

    # ===== 可替换为你原有模块的导入位置 =====
    # 示例：from core.scanner import Scanner
    # 示例：from core.database import db

    def __init__(self):
        """初始化主窗口"""
        # 使用ttkbootstrap的Window获取原生主题支持
        if TTKBOOTSTRAP_AVAILABLE:
            import ttkbootstrap as ttkb
            self.root = ttkb.Window(title="PySecScanner - 安全扫描平台", themename="darkly")
        else:
            self.root = tk.Tk()
            self.root.title("PySecScanner - 安全扫描平台")

        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # 应用主题引擎
        self.theme_engine = ThemeEngine(self.root)
        self.style = self.theme_engine.apply_theme(self.root, mode='dark')
        self.sm = StyleConfigManager(self.theme_engine)
        self.colors = self.theme_engine.colors
        self.fonts = self.theme_engine.fonts

        # 全局字体设置
        self.root.option_add('*Font', self.fonts['ui'])

        # 窗口居中
        self._center_window()

        # 状态变量
        self.current_page = None
        self.nav_buttons = {}
        self.is_scanning = False
        self.pulse_active = False
        self.toast_queue = []
        self.db = Database()
        self.ai_chat_history = []
        self.last_scan_target = ""
        self.deepseek_client = None
        self._init_deepseek()

    def _init_deepseek(self):
        """初始化DeepSeek客户端"""
        try:
            api_key = os.getenv('DEEPSEEK_API_KEY', '')
            if api_key:
                self.deepseek_client = DeepSeekClient()
                print("[INFO] DeepSeek client initialized")
            else:
                print("[WARN] DEEPSEEK_API_KEY not set, AI will use simulation mode")
        except Exception as e:
            print(f"[ERROR] DeepSeek init failed: {e}")

        # 构建UI
        self._build_layout()
        self._build_sidebar()

        # 默认显示扫描页（_switch_page 会构建内容区）
        self._switch_page('scan')

    def _center_window(self):
        """窗口居中显示"""
        self.root.update_idletasks()
        width = 1200
        height = 800
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    # ============================================================
    # 1. 整体布局：侧边栏 + 内容区
    # ============================================================
    def _build_layout(self):
        """构建主布局框架"""
        # 主容器使用grid，支持自适应
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # 左侧边栏
        self.sidebar = ttk.Frame(self.root, style='Sidebar.TFrame', width=200)
        self.sidebar.grid(row=0, column=0, sticky='nsew')
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        # 内容区
        self.content = ttk.Frame(self.root, style='TFrame')
        self.content.grid(row=0, column=1, sticky='nsew', padx=0, pady=0)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    # ============================================================
    # 2. 侧边导航栏
    # ============================================================
    def _build_sidebar(self):
        """构建侧边导航栏"""
        c = self.colors

        # 顶部Logo区域
        logo_frame = tk.Frame(self.sidebar, bg=c['sidebar'], height=70)
        logo_frame.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        logo_frame.grid_propagate(False)
        logo_frame.grid_columnconfigure(0, weight=1)

        tk.Label(logo_frame, text="🔒 PySecScanner",
                 bg=c['sidebar'], fg=c['primary'],
                 font=self.fonts['ui_title']).place(relx=0.5, rely=0.5, anchor='center')

        # 分隔线
        divider = tk.Frame(self.sidebar, bg=c['border'], height=1)
        divider.grid(row=1, column=0, sticky='ew', padx=16, pady=(0, 8))

        # 导航项配置
        nav_items = [
            ('scan',    '🔍', '新建扫描'),
            ('results', '📊', '扫描结果'),
            ('ai',      '🤖', 'AI 分析'),
            ('settings','⚙️', '系统设置'),
        ]

        self.nav_frame = tk.Frame(self.sidebar, bg=c['sidebar'])
        self.nav_frame.grid(row=2, column=0, sticky='nsew', padx=8)
        self.nav_frame.grid_columnconfigure(0, weight=1)

        for idx, (key, icon, text) in enumerate(nav_items):
            btn = tk.Button(self.nav_frame,
                            text=f"{icon}   {text}",
                            bg=c['sidebar'],
                            fg=c['fg_secondary'],
                            font=self.fonts['ui'],
                            bd=0, padx=16, pady=12,
                            anchor='w',
                            cursor='hand2',
                            command=lambda k=key: self._switch_page(k))
            btn.grid(row=idx, column=0, sticky='ew', pady=4)
            btn.bind('<Enter>', lambda e, b=btn: self._on_nav_hover(b, True))
            btn.bind('<Leave>', lambda e, b=btn: self._on_nav_hover(b, False))
            self.nav_buttons[key] = btn

        # 底部主题切换
        bottom_frame = tk.Frame(self.sidebar, bg=c['sidebar'])
        bottom_frame.grid(row=3, column=0, sticky='sew', padx=8, pady=(16, 12))
        self.sidebar.grid_rowconfigure(3, weight=1)

        theme_btn = tk.Button(bottom_frame,
                              text="🌓 切换主题",
                              bg=c['sidebar'],
                              fg=c['fg_secondary'],
                              font=self.fonts['ui_small'],
                              bd=0, padx=16, pady=8,
                              anchor='w',
                              cursor='hand2',
                              command=self._toggle_theme)
        theme_btn.pack(fill='x', side='bottom')

    def _on_nav_hover(self, btn, entering):
        """导航按钮hover效果"""
        c = self.colors
        if btn == self.nav_buttons.get(self.current_page):
            return
        if entering:
            btn.config(bg=c['sidebar_hover'], fg=c['primary'])
        else:
            btn.config(bg=c['sidebar'], fg=c['fg_secondary'])

    def _switch_page(self, page_key):
        """切换页面"""
        c = self.colors

        # 更新导航按钮状态
        for key, btn in self.nav_buttons.items():
            if key == page_key:
                btn.config(bg=c['sidebar_active'], fg=c['primary'],
                           font=self.fonts['ui_bold'])
            else:
                btn.config(bg=c['sidebar'], fg=c['fg_secondary'],
                           font=self.fonts['ui'])

        self.current_page = page_key

        # 淡入切换内容
        self._fade_in_content(page_key)

    def _fade_in_content(self, page_key):
        """内容淡入效果（通过透明度模拟，用前景色过渡）"""
        # 清除内容区
        for widget in self.content.winfo_children():
            widget.destroy()

        # 创建容器（增加留白）
        container = ttk.Frame(self.content)
        container.grid(row=0, column=0, sticky='nsew', padx=40, pady=32)
        container.grid_columnconfigure(0, weight=1)

        # 根据页面key构建内容
        builders = {
            'scan':     self._build_scan_page,
            'results':  self._build_results_page,
            'ai':       self._build_ai_page,
            'settings': self._build_settings_page,
        }
        build_fn = builders.get(page_key, self._build_scan_page)
        build_fn(container)

    # ============================================================
    # 3. 扫描页面
    # ============================================================
    def _build_scan_page(self, parent):
        """构建扫描页面"""
        c = self.colors
        sm = self.sm

        # 页面标题
        header = tk.Frame(parent, bg=c['bg_primary'])
        header.pack(fill='x', pady=(0, 28))
        tk.Label(header, text="🔍 新建扫描", bg=c['bg_primary'], fg=c['fg'],
                 font=self.fonts['ui_title']).pack(anchor='w')
        tk.Label(header, text="输入目标地址，选择扫描模块，开始安全检测",
                 bg=c['bg_primary'], fg=c['fg_secondary'],
                 font=self.fonts['ui']).pack(anchor='w', pady=(8, 0))

        # 主卡片
        card = tk.Frame(parent, bg=c['bg_card'], padx=32, pady=32)
        card.pack(fill='x')
        card.config(highlightbackground=c['border'], highlightthickness=1)

        # 目标输入
        tk.Label(card, text="目标地址", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w')
        self.target_entry = tk.Entry(card,
                                     bg=c['bg_secondary'],
                                     fg=c['fg_disabled'],
                                     insertbackground=c['fg'],
                                     font=self.fonts['ui'],
                                     relief='flat',
                                     highlightthickness=1,
                                     highlightcolor=c['border_focus'],
                                     highlightbackground=c['border'])
        self.target_entry.pack(fill='x', pady=(8, 16), ipady=8)
        self.target_entry.insert(0, "请输入域名或IP，例如 example.com")
        self.target_entry.bind('<FocusIn>',
                               lambda e: self._clear_placeholder(self.target_entry,
                                                                  "请输入域名或IP，例如 example.com"))
        self.target_entry.bind('<FocusOut>',
                               lambda e: self._restore_placeholder(self.target_entry,
                                                                    "请输入域名或IP，例如 example.com"))

        # 模块选择
        tk.Label(card, text="扫描模块", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w')

        modules_frame = tk.Frame(card, bg=c['bg_card'])
        modules_frame.pack(fill='x', pady=(8, 16))

        self.module_vars = {}
        modules = [
            ('port_scan', '🔌 端口扫描'),
            ('subdomain', '🌐 子域名枚举'),
            ('dir_scan', '📁 目录扫描'),
            ('fingerprint', '👆 指纹识别'),
            ('sqli', '💉 SQL 注入'),
            ('xss', '❌ XSS 漏洞'),
            ('ssrf', '🔄 SSRF 漏洞'),
            ('sensitive', '🔍 敏感信息'),
        ]
        for idx, (key, label) in enumerate(modules):
            var = tk.BooleanVar(value=True)
            self.module_vars[key] = var
            cb = tk.Checkbutton(modules_frame, text=label,
                                bg=c['bg_card'], fg=c['fg'],
                                selectcolor=c['bg_secondary'],
                                activebackground=c['bg_card'],
                                activeforeground=c['primary'],
                                font=self.fonts['ui'],
                                variable=var,
                                cursor='hand2')
            cb.grid(row=idx // 3, column=idx % 3, sticky='w', padx=(0, 24), pady=4)

        # 操作按钮区
        btn_frame = tk.Frame(card, bg=c['bg_card'])
        btn_frame.pack(fill='x', pady=(8, 0))

        if TTKBOOTSTRAP_AVAILABLE:
            self.scan_btn = ttk.Button(btn_frame, text="▶ 开始扫描",
                                       style='success.TButton',
                                       command=self._on_scan_click)
            self.scan_btn.pack(side='left', padx=(0, 12))

            self.stop_btn = ttk.Button(btn_frame, text="⏹ 停止",
                                       style='danger.TButton',
                                       command=self._on_scan_stop,
                                       state='disabled')
            self.stop_btn.pack(side='left')
        else:
            self.scan_btn = tk.Button(btn_frame, text="▶ 开始扫描",
                                      bg=c['primary'], fg=c['bg_primary'],
                                      font=self.fonts['ui_bold'],
                                      bd=0, padx=24, pady=10,
                                      cursor='hand2',
                                      command=self._on_scan_click)
            self.scan_btn.pack(side='left', padx=(0, 12))

            self.stop_btn = tk.Button(btn_frame, text="⏹ 停止",
                                      bg=c['danger'], fg='#FFFFFF',
                                      font=self.fonts['ui_bold'],
                                      bd=0, padx=24, pady=10,
                                      cursor='hand2',
                                      command=self._on_scan_stop,
                                      state='disabled')
            self.stop_btn.pack(side='left')

        # 脉冲动画区域（扫描时显示）
        self.pulse_frame = tk.Frame(parent, bg=c['bg_primary'], height=120)
        self.pulse_frame.pack(fill='x', pady=(20, 0))
        self.pulse_frame.pack_propagate(False)
        self.pulse_frame.pack_forget()  # 初始隐藏

        self.pulse_label = tk.Label(self.pulse_frame, text="🔍 正在扫描...",
                                    bg=c['bg_primary'], fg=c['primary'],
                                    font=self.fonts['ui_large'])
        self.pulse_label.place(relx=0.5, rely=0.5, anchor='center')

        # 进度条
        self.progress = sm.create_progress(parent, mode='indeterminate')
        self.progress.pack(fill='x', pady=(16, 0))
        self.progress.pack_forget()

    def _clear_placeholder(self, entry, placeholder):
        if entry.get() == placeholder:
            entry.delete(0, 'end')
            entry.config(fg=self.colors['fg'])

    def _restore_placeholder(self, entry, placeholder):
        if not entry.get():
            entry.insert(0, placeholder)
            entry.config(fg=self.colors['fg_disabled'])

    # ============================================================
    # 4. 结果页面
    # ============================================================
    def _build_results_page(self, parent):
        """构建结果页面"""
        c = self.colors

        tk.Label(parent, text="📊 扫描结果", bg=c['bg_primary'], fg=c['fg'],
                 font=self.fonts['ui_title']).pack(anchor='w', pady=(0, 28))

        # 统计卡片行
        stats_frame = tk.Frame(parent, bg=c['bg_primary'])
        stats_frame.pack(fill='x', pady=(0, 28))

        stats = [
            ('total', '总扫描', '0', c['fg']),
            ('high', '高危', '0', c['danger']),
            ('medium', '中危', '0', c['warning']),
            ('low', '低危', '0', c['success']),
        ]
        self.stat_labels = {}
        for idx, (key, title, value, color) in enumerate(stats):
            card = tk.Frame(stats_frame, bg=c['bg_card'], padx=24, pady=20)
            card.grid(row=0, column=idx, padx=(0, 16), sticky='nsew')
            card.config(highlightbackground=c['border'], highlightthickness=1)
            stats_frame.grid_columnconfigure(idx, weight=1)

            val_label = tk.Label(card, text=value, bg=c['bg_card'], fg=color,
                     font=('Segoe UI', 24, 'bold'))
            val_label.pack(anchor='w')
            self.stat_labels[key] = val_label
            tk.Label(card, text=title, bg=c['bg_card'], fg=c['fg_secondary'],
                     font=self.fonts['ui_small']).pack(anchor='w')

        # 结果表格
        columns = ('severity', 'title', 'target', 'time')
        self.result_tree = ttk.Treeview(parent, style='Custom.Treeview',
                                        columns=columns, show='headings', height=14)

        self.result_tree.heading('severity', text='级别')
        self.result_tree.heading('title', text='漏洞名称')
        self.result_tree.heading('target', text='目标')
        self.result_tree.heading('time', text='时间')

        self.result_tree.column('severity', width=80, anchor='center')
        self.result_tree.column('title', width=400)
        self.result_tree.column('target', width=250)
        self.result_tree.column('time', width=120, anchor='center')

        # 滚动条
        scrollbar = ttk.Scrollbar(parent, orient='vertical', command=self.result_tree.yview,
                                  style='Custom.Vertical.TScrollbar')
        self.result_tree.configure(yscrollcommand=scrollbar.set)

        self.result_tree.pack(fill='both', expand=True, side='left')
        scrollbar.pack(fill='y', side='right')

        # 斑马纹
        self.result_tree.tag_configure('even', background=c['bg_secondary'])
        self.result_tree.tag_configure('odd', background=c['bg_card'])

        # 严重级别颜色标签
        self.result_tree.tag_configure('critical', foreground=c['danger'])
        self.result_tree.tag_configure('high', foreground='#FF6B6B')
        self.result_tree.tag_configure('medium', foreground=c['warning'])
        self.result_tree.tag_configure('low', foreground=c['success'])

        # 从数据库加载真实扫描结果
        self._load_db_results()

    def _load_db_results(self):
        """从数据库加载真实扫描结果"""
        try:
            scans = self.db.get_scans(limit=20)
            if not scans:
                return

            row_idx = 0
            for scan in scans:
                findings = self.db.get_findings(scan.id)
                for finding in findings:
                    sev = finding.severity or 'info'
                    title = finding.title or '未知'
                    target = finding.target or scan.target or '未知'
                    time_str = scan.start_time.strftime('%Y-%m-%d') if scan.start_time else '-'
                    tag = 'even' if row_idx % 2 == 0 else 'odd'
                    self.result_tree.insert('', 'end',
                                            values=(sev.upper(), title, target, time_str),
                                            tags=(tag, sev))
                    row_idx += 1

            # 更新统计卡片
            self._update_result_stats()
        except Exception as e:
            print(f"加载数据库结果失败: {e}")

    def _update_result_stats(self):
        """更新结果页统计数字"""
        try:
            stats = self.db.get_stats()
            total = stats.get('total_scans', 0)
            severity = stats.get('severity_distribution', {})
            if isinstance(severity, str):
                severity = json.loads(severity)
            high = severity.get('high', 0) + severity.get('critical', 0)
            medium = severity.get('medium', 0)
            low = severity.get('low', 0) + severity.get('info', 0)

            # 更新统计标签（如果存在）
            if hasattr(self, 'stat_labels'):
                self.stat_labels['total'].config(text=str(total))
                self.stat_labels['high'].config(text=str(high))
                self.stat_labels['medium'].config(text=str(medium))
                self.stat_labels['low'].config(text=str(low))
        except Exception as e:
            print(f"更新统计失败: {e}")

    def _refresh_results_page(self):
        """刷新结果页面数据"""
        try:
            # 清空现有数据
            for item in self.result_tree.get_children():
                self.result_tree.delete(item)
            # 重新加载数据库数据
            self._load_db_results()
            # 更新统计
            self._update_result_stats()
        except Exception as e:
            print(f"[ERROR] 刷新结果页面失败: {e}")

    def _refresh_ai_target_list(self):
        """刷新AI分析页面的目标列表"""
        try:
            scans = self.db.get_scans(limit=50)
            targets = []
            for scan in scans:
                if scan.target and scan.target not in targets:
                    targets.append(scan.target)
            if targets:
                self.ai_target_combo['values'] = targets
                if not self.ai_target_combo.get():
                    self.ai_target_combo.set(targets[0])
            else:
                self.ai_target_combo['values'] = ['']
                self.ai_target_combo.set('')
        except Exception as e:
            print(f"[ERROR] 刷新AI目标列表失败: {e}")

    # ============================================================
    # 4.5 AI 分析页面
    # ============================================================
    def _build_ai_page(self, parent):
        """构建AI分析页面"""
        c = self.colors

        # 页面标题
        tk.Label(parent, text="🤖 AI 智能分析", bg=c['bg_primary'], fg=c['fg'],
                 font=self.fonts['ui_title']).pack(anchor='w', pady=(0, 8))
        tk.Label(parent, text="选择扫描结果，使用AI进行漏洞分析和修复建议",
                 bg=c['bg_primary'], fg=c['fg_secondary'],
                 font=self.fonts['ui']).pack(anchor='w', pady=(0, 28))

        # 上半部分：选择区域
        select_card = tk.Frame(parent, bg=c['bg_card'], padx=32, pady=28)
        select_card.pack(fill='x')
        select_card.config(highlightbackground=c['border'], highlightthickness=1)

        tk.Label(select_card, text="选择扫描目标", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w')

        # 目标选择下拉框（从数据库读取）
        self.ai_target_var = tk.StringVar(value="")
        target_combo = tk.Frame(select_card, bg=c['bg_card'])
        target_combo.pack(fill='x', pady=(12, 16))

        self.ai_target_combo = ttk.Combobox(target_combo,
                                            textvariable=self.ai_target_var,
                                            font=self.fonts['ui'],
                                            width=48,
                                            state='normal')
        self.ai_target_combo.pack(side='left', ipady=4, padx=(0, 8))
        # 加载已有扫描目标
        self._refresh_ai_target_list()

        refresh_btn = tk.Button(target_combo, text="🔄 刷新",
                                bg=c['bg_secondary'], fg=c['fg'],
                                font=self.fonts['ui_small'],
                                bd=0, padx=12, pady=4,
                                cursor='hand2',
                                command=self._refresh_ai_target_list)
        refresh_btn.pack(side='left')

        # AI分析按钮
        btn_frame = tk.Frame(select_card, bg=c['bg_card'])
        btn_frame.pack(fill='x', pady=(8, 0))

        if TTKBOOTSTRAP_AVAILABLE:
            ttk.Button(btn_frame, text="🧠 开始AI分析",
                       style='success.TButton',
                       command=self._on_ai_analyze).pack(side='left', padx=(0, 12))
            ttk.Button(btn_frame, text="🔧 生成修复方案",
                       style='info.TButton',
                       command=self._on_ai_fix).pack(side='left')
        else:
            tk.Button(btn_frame, text="🧠 开始AI分析",
                      bg=c['primary'], fg=c['bg_primary'],
                      font=self.fonts['ui_bold'],
                      bd=0, padx=24, pady=10,
                      cursor='hand2',
                      command=self._on_ai_analyze).pack(side='left', padx=(0, 12))
            tk.Button(btn_frame, text="🔧 生成修复方案",
                      bg=c['accent'], fg='#FFFFFF',
                      font=self.fonts['ui_bold'],
                      bd=0, padx=24, pady=10,
                      cursor='hand2',
                      command=self._on_ai_fix).pack(side='left')

        # 中间部分：AI结果展示
        tk.Label(parent, text="AI 分析结果", bg=c['bg_primary'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w', pady=(28, 12))

        result_card = tk.Frame(parent, bg=c['bg_card'], padx=32, pady=28)
        result_card.pack(fill='x')
        result_card.config(highlightbackground=c['border'], highlightthickness=1)

        self.ai_result_text = tk.Text(result_card,
                                      bg=c['bg_card'],
                                      fg=c['fg'],
                                      font=self.fonts['code'],
                                      relief='flat',
                                      wrap='word',
                                      height=10)
        self.ai_result_text.pack(fill='both', expand=True)
        self.ai_result_text.insert('1.0',
            "🤖 欢迎使用AI智能分析功能\n\n"
            "点击「开始AI分析」按钮，AI将自动分析漏洞风险。\n"
            "点击「生成修复方案」按钮，AI将输出修复代码示例。\n"
            "你也可以在下方对话框中与AI直接交流。\n")
        self.ai_result_text.config(state='disabled')

        # 下半部分：AI对话区域
        tk.Label(parent, text="💬 AI 对话", bg=c['bg_primary'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w', pady=(24, 12))

        chat_card = tk.Frame(parent, bg=c['bg_card'], padx=32, pady=24)
        chat_card.pack(fill='both', expand=True)
        chat_card.config(highlightbackground=c['border'], highlightthickness=1)

        # 对话历史显示
        self.chat_text = tk.Text(chat_card,
                                 bg=c['bg_card'],
                                 fg=c['fg'],
                                 font=self.fonts['ui'],
                                 relief='flat',
                                 wrap='word',
                                 height=8)
        self.chat_text.pack(fill='both', expand=True, pady=(0, 12))
        self.chat_text.tag_configure('user', foreground=c['accent'], font=self.fonts['ui_bold'])
        self.chat_text.tag_configure('ai', foreground=c['primary'])
        self.chat_text.tag_configure('system', foreground=c['fg_secondary'], font=self.fonts['ui_small'])
        self.chat_text.insert('end', "系统: 你好！我是PySecScanner AI助手，可以帮你分析漏洞和生成修复方案。\n\n", 'system')
        self.chat_text.config(state='disabled')

        # 输入区域
        input_frame = tk.Frame(chat_card, bg=c['bg_card'])
        input_frame.pack(fill='x')

        self.chat_entry = tk.Entry(input_frame,
                                   bg=c['bg_secondary'],
                                   fg=c['fg'],
                                   font=self.fonts['ui'],
                                   relief='flat',
                                   highlightthickness=1,
                                   highlightcolor=c['border_focus'],
                                   highlightbackground=c['border'])
        self.chat_entry.pack(side='left', fill='x', expand=True, ipady=8, padx=(0, 12))
        self.chat_entry.bind('<Return>', lambda e: self._send_chat_message())

        if TTKBOOTSTRAP_AVAILABLE:
            ttk.Button(input_frame, text="发送", style='success.TButton',
                       command=self._send_chat_message).pack(side='right')
        else:
            tk.Button(input_frame, text="发送",
                      bg=c['primary'], fg=c['bg_primary'],
                      font=self.fonts['ui_bold'],
                      bd=0, padx=20, pady=8,
                      cursor='hand2',
                      command=self._send_chat_message).pack(side='right')

    def _on_ai_analyze(self):
        """AI分析按钮点击 - 从数据库读取最新扫描结果并调用DeepSeek分析"""
        target = self.ai_target_combo.get()
        if not target:
            self._show_toast("请先输入扫描目标", 'warning')
            return

        self._show_toast(f"AI 正在分析 {target} ...", 'info')
        self.ai_result_text.config(state='normal')
        self.ai_result_text.delete('1.0', 'end')
        self.ai_result_text.insert('1.0', "正在读取扫描结果并调用AI分析，请稍候...")
        self.ai_result_text.config(state='disabled')

        def do_analyze():
            try:
                # 从数据库获取该目标的最新扫描结果
                findings = self._get_latest_findings(target)
                if not findings:
                    self.root.after(0, lambda: self._show_ai_no_result(target))
                    return

                # 调用DeepSeek分析
                if self.deepseek_client:
                    result_text = self._call_deepseek_analysis(target, findings)
                    self.root.after(0, lambda: self._show_ai_result_real(target, result_text))
                else:
                    # 未配置API Key，使用本地分析
                    self.root.after(0, lambda: self._show_ai_result_local(target, findings))
            except Exception as e:
                self.root.after(0, lambda: self._show_ai_error(str(e)))

        t = threading.Thread(target=do_analyze)
        t.daemon = True
        t.start()

    def _get_latest_findings(self, target):
        """获取指定目标的最新扫描发现"""
        try:
            scans = self.db.get_scans(limit=50)
            for scan in scans:
                if target in (scan.target or ''):
                    findings = self.db.get_findings(scan.id)
                    if findings:
                        return findings
            # 如果找不到精确匹配，返回最新的扫描结果
            if scans:
                return self.db.get_findings(scans[0].id)
            return []
        except Exception as e:
            print(f"[ERROR] 获取扫描结果失败: {e}")
            return []

    def _call_deepseek_analysis(self, target, findings):
        """调用DeepSeek API进行漏洞分析"""
        try:
            # 构建漏洞数据
            vuln_list = []
            for f in findings:
                vuln_list.append({
                    "vulnerability_type": f.title or "未知漏洞",
                    "severity": f.severity or "info",
                    "location": f.target or target,
                    "description": f.description or "",
                    "evidence": f.evidence or ""
                })

            # 构建prompt并调用API
            system_prompt = "你是一位专业的网络安全专家，请根据提供的扫描结果进行详细分析。"
            user_prompt = f"请分析以下目标 {target} 的漏洞扫描结果：\n\n"
            for v in vuln_list:
                user_prompt += f"- [{v['severity']}] {v['vulnerability_type']} @ {v['location']}\n"
                if v['description']:
                    user_prompt += f"  描述: {v['description']}\n"
                if v['evidence']:
                    user_prompt += f"  证据: {v['evidence']}\n"
            user_prompt += "\n请提供：\n1. 风险概览（各等级漏洞数量、综合评分）\n2. 每个漏洞的详细分析（危害、成因、修复建议）\n3. 总体安全建议\n"

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]

            # 在线程中运行async
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            response = loop.run_until_complete(self.deepseek_client._call_api(messages))
            loop.close()

            content = response.choices[0].message.content
            return content
        except Exception as e:
            print(f"[ERROR] DeepSeek分析失败: {e}")
            return f"AI分析调用失败: {e}\n\n请检查DEEPSEEK_API_KEY是否配置正确。"

    def _show_ai_result_real(self, target, result_text):
        """显示AI分析结果（真实API返回）"""
        self.ai_result_text.config(state='normal')
        self.ai_result_text.delete('1.0', 'end')
        self.ai_result_text.insert('1.0', f"🤖 AI 漏洞分析报告 - {target}\n{'='*50}\n\n{result_text}")
        self.ai_result_text.config(state='disabled')
        self._show_toast("AI 分析完成", 'success')

    def _show_ai_result_local(self, target, findings):
        """显示本地分析结果（未配置DeepSeek时）"""
        self.ai_result_text.config(state='normal')
        self.ai_result_text.delete('1.0', 'end')
        lines = [f"🤖 漏洞分析 - {target}", "="*50, ""]
        high = sum(1 for f in findings if f.severity in ('high', 'critical'))
        medium = sum(1 for f in findings if f.severity == 'medium')
        low = sum(1 for f in findings if f.severity in ('low', 'info'))
        lines.append(f"📊 风险概览")
        lines.append(f"  • 高危: {high} 个")
        lines.append(f"  • 中危: {medium} 个")
        lines.append(f"  • 低危: {low} 个")
        lines.append("")
        lines.append("🔍 详细发现")
        for f in findings:
            lines.append(f"\n[{f.severity or 'info'}] {f.title or '未知'}")
            lines.append(f"  位置: {f.target or target}")
            if f.description:
                lines.append(f"  描述: {f.description}")
        lines.append("")
        lines.append("💡 提示")
        lines.append("  配置 DEEPSEEK_API_KEY 环境变量后可启用AI智能分析。")
        self.ai_result_text.insert('1.0', "\n".join(lines))
        self.ai_result_text.config(state='disabled')
        self._show_toast("本地分析完成（未启用AI）", 'info')

    def _show_ai_no_result(self, target):
        """显示无扫描结果提示"""
        self.ai_result_text.config(state='normal')
        self.ai_result_text.delete('1.0', 'end')
        self.ai_result_text.insert('1.0',
            f"未找到目标 {target} 的扫描结果。\n\n"
            f"请先前往「新建扫描」页面执行扫描，"
            f"扫描完成后AI会自动同步目标并分析结果。")
        self.ai_result_text.config(state='disabled')
        self._show_toast("无扫描结果", 'warning')

    def _show_ai_error(self, error_msg):
        """显示AI分析错误"""
        self.ai_result_text.config(state='normal')
        self.ai_result_text.delete('1.0', 'end')
        self.ai_result_text.insert('1.0', f"AI分析出错:\n{error_msg}")
        self.ai_result_text.config(state='disabled')
        self._show_toast("AI分析失败", 'danger')

    def _on_ai_fix(self):
        """生成修复方案（可替换为实际修复生成模块）"""
        self._show_toast("正在生成修复方案...", 'info')

        # ===== 可替换：接入你的修复生成模块 =====
        # from modules.fix.fix_generator import FixGenerator
        # fix_gen = FixGenerator()
        # fixes = fix_gen.generate_fixes()

        self.ai_result_text.config(state='normal')
        self.ai_result_text.delete('1.0', 'end')
        fix_code = '''🔧 漏洞修复方案
==================================================

1. SQL注入修复示例 (Python/Flask)

    # 修复前（不安全）
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    # 修复后（安全）
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))

2. 命令注入修复示例

    # 修复前（不安全）
    os.system(f"ping {ip_address}")

    # 修复后（安全）
    import subprocess
    subprocess.run(["ping", "-c", "4", ip_address], check=True)

3. XSS修复示例

    # 修复前（不安全）
    return f"<div>{user_input}</div>"

    # 修复后（安全）
    from html import escape
    return f"<div>{escape(user_input)}</div>"

4. 配置文件加固

    # nginx.conf 建议配置
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";

=================================================='''
        self.ai_result_text.insert('1.0', fix_code)
        self.ai_result_text.config(state='disabled')
        self._show_toast("修复方案已生成", 'success')

    def _send_chat_message(self):
        """发送AI对话消息 - 调用DeepSeek API"""
        msg = self.chat_entry.get().strip()
        if not msg:
            return

        self.chat_entry.delete(0, 'end')

        # 显示用户消息
        self.chat_text.config(state='normal')
        self.chat_text.insert('end', f"你: {msg}\n", 'user')
        self.chat_text.insert('end', "AI: 正在思考...\n", 'system')
        self.chat_text.see('end')
        self.chat_text.config(state='disabled')

        # 保存到历史
        self.ai_chat_history.append({"role": "user", "content": msg})

        def do_chat():
            try:
                if self.deepseek_client:
                    # 构建消息列表
                    system_msg = {"role": "system",
                                  "content": "你是PySecScanner的AI安全助手，擅长漏洞分析、安全加固和渗透测试建议。请用中文回答。"}
                    messages = [system_msg]
                    # 只保留最近10轮对话作为上下文
                    for h in self.ai_chat_history[-20:]:
                        messages.append({"role": h["role"], "content": h["content"]})

                    # 调用DeepSeek API
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    response = loop.run_until_complete(self.deepseek_client._call_api(messages))
                    loop.close()

                    content = response.choices[0].message.content
                    self.root.after(0, lambda: self._append_ai_reply(content))
                else:
                    # 未配置API Key，使用本地回复
                    reply = self._get_local_reply(msg)
                    self.root.after(0, lambda: self._append_ai_reply(reply))
            except Exception as e:
                error_reply = f"AI调用失败: {e}\n请检查DEEPSEEK_API_KEY是否配置正确。"
                self.root.after(0, lambda: self._append_ai_reply(error_reply))

        t = threading.Thread(target=do_chat)
        t.daemon = True
        t.start()

    def _get_local_reply(self, msg):
        """本地回复（未配置DeepSeek时）"""
        msg_lower = msg.lower()
        if any(k in msg_lower for k in ['hello', 'hi', '你好']):
            return "你好！我是PySecScanner AI助手。\n当前未配置DeepSeek API，请设置DEEPSEEK_API_KEY环境变量以启用智能对话。"
        if any(k in msg_lower for k in ['help', '帮助']):
            return "我可以帮你：\n1. 分析扫描结果中的漏洞\n2. 生成修复代码\n3. 评估安全风险等级\n4. 提供安全加固建议\n\n（当前为本地模式，配置API Key后启用AI智能回复）"
        if any(k in msg_lower for k in ['分析', '漏洞', '扫描']):
            return "请先在「新建扫描」页面执行扫描，然后在AI分析页面选择目标进行分析。\n配置DEEPSEEK_API_KEY后可启用AI智能分析。"
        return f"收到你的问题：{msg}\n\n当前为本地模拟模式。配置DEEPSEEK_API_KEY环境变量后，即可调用DeepSeek大模型进行智能回复。"

    def _append_ai_reply(self, text):
        """追加AI回复到对话区"""
        self.chat_text.config(state='normal')
        # 删除"正在思考..."
        last_line_start = self.chat_text.index("end-2l linestart")
        last_line_end = self.chat_text.index("end-2l lineend")
        self.chat_text.delete(last_line_start, last_line_end + "+1c")
        # 插入AI回复
        self.chat_text.insert('end', f"AI: {text}\n\n", 'ai')
        self.chat_text.see('end')
        self.chat_text.config(state='disabled')
        self.ai_chat_history.append({"role": "assistant", "content": text})

    # ============================================================
    # 5. 设置页面
    # ============================================================
    def _build_settings_page(self, parent):
        """构建设置页面"""
        c = self.colors

        tk.Label(parent, text="⚙️ 系统设置", bg=c['bg_primary'], fg=c['fg'],
                 font=self.fonts['ui_title']).pack(anchor='w', pady=(0, 28))

        # 通用设置卡片
        card1 = tk.Frame(parent, bg=c['bg_card'], padx=32, pady=28)
        card1.pack(fill='x', pady=(0, 24))
        card1.config(highlightbackground=c['border'], highlightthickness=1)

        tk.Label(card1, text="通用设置", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w', pady=(0, 12))

        # 线程数
        row1 = tk.Frame(card1, bg=c['bg_card'])
        row1.pack(fill='x', pady=4)
        tk.Label(row1, text="并发线程数", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui']).pack(side='left')
        thread_spin = tk.Spinbox(row1, from_=1, to=100, width=8,
                                 bg=c['bg_secondary'], fg=c['fg'],
                                 font=self.fonts['ui'],
                                 buttonbackground=c['bg_elevated'])
        thread_spin.pack(side='right')
        thread_spin.delete(0, 'end')
        thread_spin.insert(0, '50')

        # 超时设置
        row2 = tk.Frame(card1, bg=c['bg_card'])
        row2.pack(fill='x', pady=4)
        tk.Label(row2, text="请求超时(秒)", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui']).pack(side='left')
        timeout_spin = tk.Spinbox(row2, from_=1, to=60, width=8,
                                  bg=c['bg_secondary'], fg=c['fg'],
                                  font=self.fonts['ui'],
                                  buttonbackground=c['bg_elevated'])
        timeout_spin.pack(side='right')
        timeout_spin.delete(0, 'end')
        timeout_spin.insert(0, '10')

        # AI设置卡片
        card2 = tk.Frame(parent, bg=c['bg_card'], padx=32, pady=28)
        card2.pack(fill='x')
        card2.config(highlightbackground=c['border'], highlightthickness=1)

        tk.Label(card2, text="AI分析配置", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui_bold']).pack(anchor='w', pady=(0, 12))

        row3 = tk.Frame(card2, bg=c['bg_card'])
        row3.pack(fill='x', pady=4)
        tk.Label(row3, text="DeepSeek API Key", bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui']).pack(side='left')
        api_entry = tk.Entry(row3, bg=c['bg_secondary'], fg=c['fg'],
                             font=self.fonts['code_small'],
                             relief='flat',
                             highlightthickness=1,
                             highlightcolor=c['border_focus'],
                             highlightbackground=c['border'],
                             show='*',
                             width=40)
        api_entry.pack(side='right')

    # ============================================================
    # 7. 交互动画
    # ============================================================
    def _animate_button_click(self, widget):
        """按钮点击缩放动画"""
        if not isinstance(widget, tk.Button):
            return
        original_font = widget.cget('font')
        try:
            # 缩小
            widget.config(font=('Segoe UI', 8))
            self.root.after(100, lambda: widget.config(font=original_font))
        except:
            pass

    def _pulse_animation(self, active=True):
        """脉冲动画：扫描状态指示器"""
        if not active:
            self.pulse_active = False
            return
        self.pulse_active = True
        self._do_pulse()

    def _do_pulse(self, step=0):
        """执行脉冲动画帧"""
        if not self.pulse_active or not self.pulse_label.winfo_exists():
            return
        c = self.colors
        # 模拟透明度变化：通过调整颜色亮度
        brightness = 0.6 + 0.4 * abs((step % 20) - 10) / 10
        # 简单起见，切换标签颜色
        colors = [c['primary'], c['primary_light'], c['primary']]
        color_idx = (step // 7) % len(colors)
        self.pulse_label.config(fg=colors[color_idx])
        self.root.after(80, lambda: self._do_pulse(step + 1))

    # ============================================================
    # 8. Toast 通知
    # ============================================================
    def _show_toast(self, message, msg_type='info', duration=2000):
        """显示右下角Toast通知"""
        c = self.colors

        # 颜色映射
        color_map = {
            'info':    c['accent'],
            'success': c['success'],
            'warning': c['warning'],
            'error':   c['danger'],
        }
        border_color = color_map.get(msg_type, c['accent'])

        # 创建Toplevel
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes('-topmost', True)
        toast.config(bg=c['bg_card'])

        # 容器
        frame = tk.Frame(toast, bg=c['bg_card'], padx=16, pady=12)
        frame.pack(fill='both', expand=True)
        frame.config(highlightbackground=border_color, highlightthickness=2)

        # 消息文本
        tk.Label(frame, text=message, bg=c['bg_card'], fg=c['fg'],
                 font=self.fonts['ui'], wraplength=260).pack(anchor='w')

        # 定位到右下角
        self.root.update_idletasks()
        toast.update_idletasks()
        tw = toast.winfo_reqwidth()
        th = toast.winfo_reqheight()
        rx = self.root.winfo_x() + self.root.winfo_width() - tw - 24
        ry = self.root.winfo_y() + self.root.winfo_height() - th - 24
        toast.geometry(f"{tw}x{th}+{rx}+{ry}")

        # 自动关闭
        def close_toast():
            if toast.winfo_exists():
                # 淡出效果（通过调整位置向上移动模拟）
                for i in range(5):
                    toast.geometry(f"+{rx}+{ry + i * 5}")
                    toast.update()
                    time.sleep(0.02)
                toast.destroy()

        self.root.after(duration, close_toast)

    # ============================================================
    # 9. 扫描业务逻辑（可替换为你原有模块）
    # ============================================================
    def _on_scan_click(self):
        """开始扫描按钮点击"""
        self._animate_button_click(self.scan_btn)

        target = self.target_entry.get()
        placeholder = "请输入域名或IP，例如 example.com"
        if not target or target == placeholder:
            self._show_toast("请先输入扫描目标", 'warning')
            return

        self.is_scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.pulse_frame.pack(fill='x', pady=(20, 0))
        self.progress.pack(fill='x', pady=(16, 0))
        self.progress.start(15)
        self._pulse_animation(True)

        self._show_toast(f"扫描已开始: {target}", 'success')

        # ===== 可替换：接入你的扫描核心 =====
        # 示例：启动后台线程执行扫描
        self.scan_thread = threading.Thread(target=self._run_scan_simulation, args=(target,))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _run_scan_simulation(self, target):
        """模拟扫描过程（写入真实数据库记录）"""
        try:
            # 创建扫描记录
            modules = ["port_scan", "vuln_scan", "info_gather"]
            scan_id = self.db.create_scan(target, modules)
            
            # 模拟扫描延迟
            time.sleep(2)
            
            # 模拟发现一些漏洞（基于目标生成一些示例数据）
            import random
            vuln_types = [
                ("SQL注入", "high", "用户输入未做参数化处理，直接拼接SQL语句"),
                ("XSS反射型", "medium", "用户输入未转义直接输出到页面"),
                ("信息泄露", "low", "发现敏感文件或目录可访问"),
                ("开放端口", "info", "发现对外开放的服务端口"),
                ("命令注入", "high", "用户输入直接传入系统命令执行函数"),
                ("CSRF漏洞", "medium", "缺少CSRF Token验证机制"),
            ]
            
            num_findings = random.randint(2, 5)
            severity_dist = {}
            
            for i in range(num_findings):
                vuln_name, sev, desc = random.choice(vuln_types)
                finding = {
                    'result_type': 'vulnerability',
                    'title': f"{vuln_name}",
                    'description': desc,
                    'severity': sev,
                    'target': f"{target}/path{i+1}",
                    'evidence': f"HTTP 200 OK - {vuln_name} pattern detected in response",
                    'raw_data': {'confidence': random.randint(60, 95), 'payload': f"test{i}"}
                }
                self.db.add_finding(scan_id, finding)
                severity_dist[sev] = severity_dist.get(sev, 0) + 1
            
            # 更新扫描状态
            self.db.update_scan(scan_id, status='completed',
                               total_findings=num_findings,
                               severity_distribution=severity_dist)
            print(f"[INFO] 扫描完成: {target}, 发现 {num_findings} 个漏洞")
            
        except Exception as e:
            print(f"[ERROR] 模拟扫描写入数据库失败: {e}")
        
        self.root.after(0, lambda: self._on_scan_complete(target))

    def _on_scan_complete(self, target):
        """扫描完成回调"""
        self.is_scanning = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress.stop()
        self.progress.pack_forget()
        self.pulse_frame.pack_forget()
        self._pulse_animation(False)
        self.last_scan_target = target
        # 同步扫描目标到AI分析页面
        if hasattr(self, 'ai_target_combo'):
            self._refresh_ai_target_list()
            # 选中新扫描的目标
            values = list(self.ai_target_combo['values'])
            if target in values:
                self.ai_target_combo.set(target)
            else:
                self.ai_target_combo.set(target)
        
        # 刷新结果页面
        self._refresh_results_page()
        
        self._show_toast(f"扫描完成: {target}", 'success')

    def _on_scan_stop(self):
        """停止扫描"""
        self.is_scanning = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress.stop()
        self.progress.pack_forget()
        self.pulse_frame.pack_forget()
        self._pulse_animation(False)
        self._show_toast("扫描已停止", 'info')

    def _toggle_theme(self):
        """切换明暗主题"""
        self.theme_engine.toggle_mode()
        self.colors = self.theme_engine.colors
        self._show_toast(f"已切换至{'亮色' if self.theme_engine.current_mode == 'light' else '暗色'}主题", 'info')
        # 重建UI以应用新主题
        self._switch_page(self.current_page)
        self._rebuild_sidebar()

    def _rebuild_sidebar(self):
        """重建侧边栏以应用主题色"""
        for widget in self.sidebar.winfo_children():
            widget.destroy()
        self.nav_buttons = {}
        self._build_sidebar()
        # 恢复当前选中状态
        self._switch_page(self.current_page)

    def run(self):
        """启动GUI"""
        self.root.mainloop()


def main():
    """入口函数"""
    app = ModernScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
