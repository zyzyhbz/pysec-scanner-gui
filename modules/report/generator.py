"""
报告生成模块
支持HTML和JSON格式报告
"""

import json
import os
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from jinja2 import Template

from core.config import Config
from core.logger import Logger
from core.scanner import ScanReport
from core.base import Severity
from modules.ai.deepseek_client import DeepSeekClient


# HTML报告模板
# HTML报告模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner 安全扫描报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1A1A2E 0%, #16213E 100%);
            color: #e6edf3;
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        /* 封面区域 - 居中布局 */
        .cover-section {
            text-align: center;
            padding: 60px 20px;
            background: rgba(22, 27, 34, 0.8);
            border-radius: 15px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .cover-section h1 {
            font-size: 3em;
            color: #00FFAA;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 255, 170, 0.5);
            font-weight: bold;
        }

        .cover-section .subtitle {
            color: #8b949e;
            font-size: 1.3em;
            margin-bottom: 30px;
        }

        .cover-info {
            display: flex;
            justify-content: center;
            gap: 40px;
            flex-wrap: wrap;
            margin-top: 20px;
        }

        .cover-info-item {
            color: #8b949e;
            font-size: 0.95em;
        }

        .cover-info-item strong {
            color: #00FFAA;
        }

        /* 统计概览 - Grid响应式布局 */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }

        @media (max-width: 1199px) and (min-width: 768px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 767px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }

        .summary-card {
            background: rgba(22, 27, 34, 0.8);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0, 255, 170, 0.2);
        }

        .summary-card h3 {
            color: #8b949e;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00FFAA;
        }

        /* 严重级别颜色 */
        .severity-critical { color: #FF4D4D !important; }
        .severity-high { color: #FF4D4D !important; }
        .severity-medium { color: #FFA500 !important; }
        .severity-low { color: #0088FF !important; }
        .severity-info { color: #00FFAA !important; }

        /* 区域样式 */
        .section {
            background: rgba(22, 27, 34, 0.8);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }

        .section h2 {
            color: #00FFAA;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(0, 255, 170, 0.3);
            font-size: 1.5em;
        }

        .section h3 {
            color: #00FFAA;
            margin-bottom: 10px;
            font-size: 1.2em;
        }

        .section p {
            color: #8b949e;
            margin-bottom: 15px;
            line-height: 1.8;
        }

        /* 严重级别徽章 */
        .severity-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.critical {
            background: #FF4D4D;
            color: #ffffff;
            animation: pulse 2s infinite;
        }

        .severity-badge.high {
            background: #FF4D4D;
            color: #ffffff;
        }

        .severity-badge.medium {
            background: #FFA500;
            color: #ffffff;
        }

        .severity-badge.low {
            background: #0088FF;
            color: #ffffff;
        }

        .severity-badge.info {
            background: #00FFAA;
            color: #0d1117;
        }

        /* Critical 徽章脉冲动画 */
        @keyframes pulse {
            0% {
                box-shadow: 0 0 0 0 rgba(255, 77, 77, 0.7);
            }
            70% {
                box-shadow: 0 0 0 10px rgba(255, 77, 77, 0);
            }
            100% {
                box-shadow: 0 0 0 0 rgba(255, 77, 77, 0);
            }
        }

        /* 扫描结果 - 响应式卡片布局 */
        .results-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        @media (max-width: 767px) {
            .results-grid {
                grid-template-columns: 1fr;
            }
        }

        .result-card {
            background: rgba(13, 17, 23, 0.8);
            border-radius: 10px;
            padding: 25px;
            border-left: 4px solid #00FFAA;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .result-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0, 255, 170, 0.15);
        }

        .result-card.critical { border-left-color: #FF4D4D; }
        .result-card.high { border-left-color: #FF4D4D; }
        .result-card.medium { border-left-color: #FFA500; }
        .result-card.low { border-left-color: #0088FF; }
        .result-card.info { border-left-color: #00FFAA; }

        .result-card h4 {
            color: #ffffff;
            margin-bottom: 15px;
            font-size: 1.1em;
        }

        .result-card .meta {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        .result-card .meta span {
            color: #8b949e;
            font-size: 0.9em;
        }

        /* 代码块样式 */
        .evidence {
            background: #0d1117;
            border-radius: 8px;
            padding: 15px;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-all;
            color: #e6edf3;
            border-left: 3px solid #00FFAA;
            margin-top: 10px;
            overflow-x: auto;
        }

        /* 页脚 */
        .footer {
            text-align: center;
            padding: 30px;
            color: #8b949e;
            font-size: 0.9em;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            margin-top: 40px;
        }

        /* 无结果状态 */
        .no-results {
            text-align: center;
            padding: 60px 20px;
            color: #8b949e;
        }

        .no-results p {
            font-size: 1.2em;
        }

        /* 响应式优化 */
        @media (max-width: 768px) {
            .cover-section h1 {
                font-size: 2em;
            }

            .cover-section .subtitle {
                font-size: 1em;
            }

            .summary-card .value {
                font-size: 2em;
            }

            .section {
                padding: 20px;
            }

            .section h2 {
                font-size: 1.3em;
            }
        }

        /* 打印优化 */
        @media print {
            body {
                background: white;
                color: black;
            }

            .container {
                max-width: 100%;
            }

            .cover-section,
            .summary-card,
            .section,
            .result-card {
                background: white;
                color: black;
                backdrop-filter: none;
                border: 1px solid #ccc;
            }

            .cover-section h1 {
                color: black;
            }

            .summary-card .value {
                color: black;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 封面区 -->
        <div class="cover-section">
            <h1>🔒 PySecScanner</h1>
            <p class="subtitle">安全扫描报告</p>
            <div class="cover-info">
                <div class="cover-info-item">
                    <strong>扫描目标:</strong> {{ target }}
                </div>
                <div class="cover-info-item">
                    <strong>扫描时间:</strong> {{ scan_time }}
                </div>
                <div class="cover-info-item">
                    <strong>发现问题:</strong> {{ total_findings }} 个
                </div>
            </div>
        </div>

        <!-- 统计概览 -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3>扫描耗时</h3>
                <div class="value">{{ "%.2f"|format(duration) }}s</div>
            </div>
            <div class="summary-card">
                <h3>发现问题</h3>
                <div class="value">{{ total_findings }}</div>
            </div>
            <div class="summary-card">
                <h3>扫描目标</h3>
                <div class="value" style="font-size: 1.5em;">{{ target }}</div>
            </div>
        </div>

        <!-- 严重级别分布 -->
        <div class="summary-grid">
            {% for sev, count in severity_distribution.items() %}
            <div class="summary-card">
                <h3>{{ sev.upper() }}</h3>
                <div class="value severity-{{ sev }}">{{ count }}</div>
            </div>
            {% endfor %}
        </div>

        <!-- AI分析摘要 -->
        <div class="section">
            <h2>🤖 AI安全分析摘要</h2>
            {% if ai_summary %}
            <h3>总体概览</h3>
            <p>{{ ai_summary.overview }}</p>
            <h3>风险评估</h3>
            <p>{{ ai_summary.risk_overview }}</p>
            <h3>修复建议总览</h3>
            <p>{{ ai_summary.recommendations }}</p>
            {% else %}
            <p>AI摘要生成失败，已回退到基础报告。</p>
            {% endif %}
        </div>

        <!-- 扫描结果详情 -->
        <div class="section">
            <h2>📋 扫描结果详情</h2>
            {% if results %}
            <div class="results-grid">
                {% for result in results %}
                <div class="result-card {{ result.severity }}">
                    <h4>{{ result.title }}</h4>
                    <div class="meta">
                        {{ severity_badge(result.severity) }}
                        <span>📍 {{ result.target }}</span>
                        <span>📁 {{ result.result_type }}</span>
                    </div>
                    <p style="margin-bottom: 15px; color: #8b949e;">{{ result.description }}</p>
                    {% if result.evidence %}
                    <div class="evidence">{{ result.evidence }}</div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="no-results">
                <p>✅ 未发现安全问题</p>
            </div>
            {% endif %}
        </div>

        <!-- 页脚 -->
        <div class="footer">
            <p>Generated by PySecScanner v1.0.0 | {{ generation_time }}</p>
        </div>
    </div>

    <!-- Jinja2 宏定义 -->
    {% macro severity_badge(severity) %}
    <span class="severity-badge {{ severity }}">{{ severity.upper() }}</span>
    {% endmacro %}
</body>
</html>
"""

class ReportGenerator:
    """
    报告生成器
    支持HTML和JSON格式
    """
    
    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None):
        self.config = config
        self.logger = logger
    
    def generate(self, report: ScanReport, output_path: str, format: str = 'html') -> str:
        """
        生成报告
        
        Args:
            report: 扫描报告对象
            output_path: 输出路径
            format: 报告格式 (html, json)
            
        Returns:
            生成的报告文件路径
        """
        # 确保输出目录存在
        output_dir = os.path.dirname(output_path)
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        if format == 'json':
            return self._generate_json(report, output_path)
        else:
            return self._generate_html(report, output_path)
    
    def _generate_html(self, report: ScanReport, output_path: str) -> str:
        """生成HTML报告"""
        template = Template(HTML_TEMPLATE)
        
        # 准备数据
        severity_distribution = {}
        for result in report.results:
            sev = result.severity.value
            severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
        
        # 确保所有严重级别都有
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev not in severity_distribution:
                severity_distribution[sev] = 0
        
        # 按严重程度排序结果
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_results = sorted(
            report.results,
            key=lambda x: severity_order.get(x.severity.value, 5)
        )

        # 使用 DeepSeek 生成 AI 报告摘要（默认）
        ai_summary = self._generate_ai_summary(report, sorted_results)
        
        html_content = template.render(
            target=report.target,
            duration=report.duration,
            total_findings=len(report.results),
            scan_time=datetime.fromtimestamp(report.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            severity_distribution=severity_distribution,
            ai_summary=ai_summary,
            results=[{
                'title': r.title,
                'description': r.description,
                'severity': r.severity.value,
                'target': r.target,
                'result_type': r.result_type.value,
                'evidence': r.evidence
            } for r in sorted_results]
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if self.logger:
            self.logger.success(f"HTML报告已生成: {output_path}")
        
        return output_path
    
    def _generate_json(self, report: ScanReport, output_path: str) -> str:
        """生成JSON报告"""
        ai_summary = self._generate_ai_summary(report, report.results)

        report_data = {
            'meta': {
                'target': report.target,
                'start_time': report.start_time,
                'end_time': report.end_time,
                'duration': report.duration,
                'total_findings': len(report.results),
                'generated_at': datetime.now().isoformat(),
                'ai_summary': ai_summary or {},
            },
            'summary': report.get_summary(),
            'module_stats': report.module_stats,
            'results': [r.to_dict() for r in report.results]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        if self.logger:
            self.logger.success(f"JSON报告已生成: {output_path}")
        
        return output_path

    def _generate_ai_summary(self, report: ScanReport, results: List[Any]) -> Optional[Dict[str, str]]:
        """
        使用 DeepSeek 生成整体报告摘要。
        默认始终尝试 DeepSeek；失败时返回 None 并回退到非AI报告。
        """
        try:
            client = DeepSeekClient()

            # 精简传给模型的结果数据，避免过长
            top_results = []
            for r in results[:20]:
                try:
                    top_results.append({
                        "title": getattr(r, "title", ""),
                        "severity": getattr(r, "severity", Severity.INFO).value,
                        "result_type": getattr(r, "result_type", "").value if getattr(r, "result_type", None) else "",
                        "target": getattr(r, "target", ""),
                        "description": getattr(r, "description", ""),
                        "evidence": (getattr(r, "evidence", "") or "")[:400],
                    })
                except Exception:
                    continue

            summary = report.get_summary()
            payload = {
                "target": summary.get("target"),
                "duration": summary.get("duration"),
                "total_findings": summary.get("total_findings"),
                "severity_distribution": summary.get("severity_distribution"),
                "top_results": top_results,
            }

            system_prompt = (
                "你是一名资深安全顾问，请基于给定的扫描结果撰写一段简洁、专业的扫描报告摘要。\n"
                "必须输出 JSON，对象包含以下字段：\n"
                "  - overview: 对本次扫描总体情况的中文总结（1-3句话）\n"
                "  - risk_overview: 对整体风险水平和重点风险点的描述（1-3句话）\n"
                "  - recommendations: 总体修复与后续改进建议（2-5条合并成一段话即可）\n"
                "不要输出任何多余文字或Markdown，只输出一个 JSON 对象。"
            )

            user_prompt = (
                "以下是本次安全扫描的结构化结果，请基于此生成报告摘要（注意使用中文）：\n\n"
                f"{json.dumps(payload, ensure_ascii=False)}"
            )

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

            async def _do_call():
                raw = await client._call_api(messages)  # type: ignore[attr-defined]
                return client._parse_response(raw)

            parsed = asyncio.run(_do_call())

            return {
                "overview": parsed.get("overview", "") or parsed.get("analysis", ""),
                "risk_overview": parsed.get("risk_overview", "") or parsed.get("risk_assessment", ""),
                "recommendations": parsed.get("recommendations", ""),
            }
        except Exception as e:
            if self.logger:
                self.logger.warning(f"AI报告摘要生成失败，将使用基础模板: {e}")
            return None
