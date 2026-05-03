"""
Rich 格式化输出模块
提供终端层 Rich Panel、Table、Progress 的格式化输出
"""

from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.box import ROUNDED
from rich.text import Text
from core.base import ScanResult, Severity


class RichFormatter:
    """
    Rich 格式化输出器
    用于 CLI 模式的彩色格式化输出
    """
    
    # 严重级别颜色映射（十六进制）
    SEVERITY_COLORS = {
        'critical': '#FF4D4D',  # 红色
        'high': '#FF4D4D',      # 红色
        'medium': '#FFA500',    # 橙色
        'low': '#00D166',       # 绿色
        'info': '#00FFFF',      # 青色
    }
    
    # 严重级别 Emoji
    SEVERITY_EMOJI = {
        'critical': '💥',
        'high': '🚨',
        'medium': '⚠️',
        'low': 'ℹ️',
        'info': '📋',
    }
    
    def __init__(self, console: Optional[Console] = None):
        """
        初始化 Rich 格式化器
        
        Args:
            console: Rich Console 对象，None 则创建新实例
        """
        self.console = console or Console()
    
    def create_summary_panel(self, target: str, duration: float, 
                            total_findings: int, 
                            severity_distribution: Dict[str, int]) -> Panel:
        """
        创建扫描结果摘要面板
        
        Args:
            target: 扫描目标
            duration: 扫描耗时（秒）
            total_findings: 总发现数
            severity_distribution: 严重级别分布
            
        Returns:
            Rich Panel 对象
        """
        # 构建摘要内容
        summary_text = Text()
        summary_text.append(f"目标: ", style="white")
        summary_text.append(f"{target}\n", style="cyan bold")
        
        summary_text.append(f"耗时: ", style="white")
        summary_text.append(f"{duration:.2f} 秒\n", style="green")
        
        summary_text.append(f"发现: ", style="white")
        summary_text.append(f"{total_findings} 个结果\n", style="yellow")
        
        if severity_distribution:
            summary_text.append("\n严重程度分布:\n", style="white bold")
            for sev, count in severity_distribution.items():
                emoji = self.SEVERITY_EMOJI.get(sev.lower(), '')
                color = self.SEVERITY_COLORS.get(sev.lower(), 'white')
                summary_text.append(f"  {emoji} {sev.upper()}: {count}\n", style=color)
        
        return Panel(
            summary_text,
            title="🔍 扫描结果",
            border_style="cyan",
            box=ROUNDED,
            padding=(1, 2)
        )
    
    def create_findings_table(self, results: List[ScanResult]) -> Table:
        """
        创建扫描结果表格
        
        Args:
            results: 扫描结果列表
            
        Returns:
            Rich Table 对象
        """
        table = Table(
            title="🔒 发现详情",
            box=ROUNDED,
            header_style="bold #00FFAA",  # 青色
            title_style="bold white",
            show_header=True,
            show_edge=True,
            pad_edge=True
        )
        
        # 添加列
        table.add_column("序号", style="dim", width=6)
        table.add_column("严重程度", style="bold", width=12)
        table.add_column("类型", style="cyan", width=15)
        table.add_column("标题", style="white", width=30)
        table.add_column("目标", style="blue", width=30)
        
        # 添加数据行
        for idx, result in enumerate(results, 1):
            severity = result.severity.value.lower()
            color = self.SEVERITY_COLORS.get(severity, 'white')
            emoji = self.SEVERITY_EMOJI.get(severity, '')
            module_name = result.raw_data.get('module_name', 'unknown')
            
            table.add_row(
                str(idx),
                Text(f"{emoji} {result.severity.value}", style=color),
                module_name,
                result.title,
                result.target
            )
        
        return table
    
    def create_progress_bar(self) -> Progress:
        """
        创建进度条
        
        Returns:
            Rich Progress 对象，带自定义样式
        """
        # 自定义进度条样式
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                bar_width=None,
                complete_style="#00FFAA",  # 青色填充
                finished_style="#00D166",   # 绿色完成
                pulse_style="#00FFFF",      # 青色脉冲
            ),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        )
        return progress
    
    def print_scan_complete(self, report: 'ScanReport') -> None:
        """
        打印扫描完成信息（包含面板和表格）
        
        Args:
            report: 扫描报告对象
        """
        # 打印分隔线
        self.console.print()
        
        # 打印摘要面板
        summary = report.get_summary()
        panel = self.create_summary_panel(
            target=summary['target'],
            duration=summary['duration'],
            total_findings=summary['total_findings'],
            severity_distribution=summary.get('severity_distribution', {})
        )
        self.console.print(panel)
        
        # 如果有结果，打印详情表格
        if report.results:
            self.console.print()
            table = self.create_findings_table(report.results)
            self.console.print(table)
        
        self.console.print()


# 创建全局实例
rich_formatter = RichFormatter()
