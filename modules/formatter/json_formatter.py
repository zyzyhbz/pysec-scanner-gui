"""
JSON格式化器
支持将扫描结果格式化为标准JSON格式
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from core.base import ScanResult, ResultType, Severity
from core.scanner import ScanReport


class JSONFormatter:
    """JSON格式化器，将扫描结果转换为标准JSON格式"""
    
    def __init__(self):
        """初始化JSON格式化器"""
        self.format_version = "1.0"
    
    def format_result(self, result: ScanResult) -> Dict[str, Any]:
        """
        格式化单个扫描结果为标准JSON格式（任务1）
        
        Args:
            result: 扫描结果对象
            
        Returns:
            标准JSON格式的字典
        """
        # 基础字段
        formatted = {
            "format_version": self.format_version,
            "result_type": result.result_type.value,
            "title": result.title,
            "description": result.description,
            "timestamp": datetime.fromtimestamp(result.timestamp).isoformat(),
        }
        
        # 可选字段
        if result.severity:
            formatted["severity"] = result.severity.value
        if result.target:
            formatted["target"] = result.target
        if result.evidence:
            formatted["evidence"] = result.evidence
        if result.raw_data:
            formatted["raw_data"] = result.raw_data
        
        # 扩展字段（AI分析结果和修复建议）
        if "ai_analysis" in result.raw_data:
            formatted["ai_analysis"] = result.raw_data["ai_analysis"]
        if "fix_suggestion" in result.raw_data:
            formatted["fix_suggestion"] = result.raw_data["fix_suggestion"]
        
        return formatted
    
    def _format_port_result(self, result: ScanResult, formatted: Dict[str, Any]) -> Dict[str, Any]:
        """格式化端口扫描结果（任务2）"""
        raw = result.raw_data
        formatted["port"] = {
            "port": raw.get("port", 0),
            "status": raw.get("status", "open"),
            "service": raw.get("service", ""),
            "version": raw.get("version", ""),
            "banner": raw.get("banner", ""),
        }
        return formatted
    
    def _format_subdomain_result(self, result: ScanResult, formatted: Dict[str, Any]) -> Dict[str, Any]:
        """格式化子域名枚举结果（任务2）"""
        raw = result.raw_data
        formatted["subdomain"] = {
            "domain": raw.get("domain", result.target),
            "ip_address": raw.get("ip_address", ""),
            "status": raw.get("status", "active"),
        }
        return formatted
    
    def _format_directory_result(self, result: ScanResult, formatted: Dict[str, Any]) -> Dict[str, Any]:
        """格式化目录扫描结果（任务2）"""
        raw = result.raw_data
        formatted["directory"] = {
            "path": raw.get("path", ""),
            "response_status": raw.get("response_status", 0),
            "size": raw.get("size", 0),
        }
        return formatted
    
    def _format_service_result(self, result: ScanResult, formatted: Dict[str, Any]) -> Dict[str, Any]:
        """格式化服务指纹结果（任务2）"""
        raw = result.raw_data
        formatted["service"] = {
            "service_name": raw.get("service_name", ""),
            "version": raw.get("version", ""),
            "technology_stack": raw.get("technology_stack", []),
        }
        return formatted
    
    def _format_web_crawler_result(self, result: ScanResult, formatted: Dict[str, Any]) -> Dict[str, Any]:
        """格式化Web爬虫结果（任务2）"""
        raw = result.raw_data
        formatted["web_page"] = {
            "url": raw.get("url", result.target),
            "title": raw.get("title", ""),
            "content_summary": raw.get("content_summary", ""),
        }
        return formatted
    
    def _format_vulnerability_result(self, result: ScanResult, formatted: Dict[str, Any]) -> Dict[str, Any]:
        """格式化漏洞检测结果（任务3）"""
        raw = result.raw_data
        vuln_type = raw.get("vulnerability_type", "")
        
        vuln_info = {
            "vulnerability_type": vuln_type,
        }
        
        # 根据不同漏洞类型添加特定字段
        if vuln_type == "sql_injection":
            vuln_info.update({
                "injection_point": raw.get("injection_point", ""),
                "injection_type": raw.get("injection_type", ""),
                "payload": raw.get("payload", ""),
                "attack_evidence": raw.get("attack_evidence", ""),
            })
        elif vuln_type == "xss":
            vuln_info.update({
                "injection_point_location": raw.get("injection_point_location", ""),
                "payload_type": raw.get("payload_type", ""),
                "dom_structure": raw.get("dom_structure", ""),
            })
        elif vuln_type == "csrf":
            vuln_info.update({
                "target_url": raw.get("target_url", result.target),
                "exploitability": raw.get("exploitability", ""),
                "form_info": raw.get("form_info", ""),
            })
        elif vuln_type == "command_injection":
            vuln_info.update({
                "injection_parameter": raw.get("injection_parameter", ""),
                "command_type": raw.get("command_type", ""),
                "echo_info": raw.get("echo_info", ""),
            })
        elif vuln_type == "file_inclusion":
            vuln_info.update({
                "file_path": raw.get("file_path", ""),
                "inclusion_type": raw.get("inclusion_type", ""),
                "success_evidence": raw.get("success_evidence", ""),
            })
        elif vuln_type == "ssrf":
            vuln_info.update({
                "target_url": raw.get("target_url", result.target),
                "accessible_internal_address": raw.get("accessible_internal_address", ""),
                "response_info": raw.get("response_info", ""),
            })
        elif vuln_type == "xxe":
            vuln_info.update({
                "xml_parser_info": raw.get("xml_parser_info", ""),
                "payload_type": raw.get("payload_type", ""),
                "exploit_evidence": raw.get("exploit_evidence", ""),
            })
        elif vuln_type == "sensitive_info":
            vuln_info.update({
                "info_type": raw.get("info_type", ""),
                "location": raw.get("location", ""),
                "content_summary": raw.get("content_summary", ""),
            })
        elif vuln_type == "poc":
            vuln_info.update({
                "vulnerability_name": raw.get("vulnerability_name", ""),
                "poc_info": raw.get("poc_info", ""),
                "vulnerability_description": raw.get("vulnerability_description", ""),
            })
        
        formatted["vulnerability"] = vuln_info
        return formatted
    
    def format_scan_result(self, result: ScanResult) -> Dict[str, Any]:
        """
        格式化扫描结果，根据结果类型选择合适的格式化方法
        结合任务1、2、3的功能
        
        Args:
            result: 扫描结果对象
            
        Returns:
            格式化后的字典
        """
        # 先应用基础格式化（任务1）
        formatted = self.format_result(result)
        
        # 根据结果类型进行扩展格式化（任务2、3）
        result_type = result.result_type
        
        if result_type == ResultType.PORT:
            formatted = self._format_port_result(result, formatted)
        elif result_type == ResultType.SUBDOMAIN:
            formatted = self._format_subdomain_result(result, formatted)
        elif result_type == ResultType.DIRECTORY:
            formatted = self._format_directory_result(result, formatted)
        elif result_type == ResultType.SERVICE:
            formatted = self._format_service_result(result, formatted)
        elif result_type == ResultType.INFO:
            # Web爬虫结果使用INFO类型
            if "url" in result.raw_data:
                formatted = self._format_web_crawler_result(result, formatted)
        elif result_type == ResultType.VULNERABILITY:
            formatted = self._format_vulnerability_result(result, formatted)
        
        return formatted
    
    def format_report(self, report: ScanReport) -> Dict[str, Any]:
        """
        格式化完整扫描报告为标准JSON格式（任务4）
        
        Args:
            report: 扫描报告对象
            
        Returns:
            标准JSON格式的报告字典
        """
        # 报告基本信息
        formatted_report = {
            "format_version": self.format_version,
            "report_type": "scan_report",
            "target": report.target,
            "start_time": datetime.fromtimestamp(report.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(report.end_time).isoformat(),
            "duration": report.duration,
        }
        
        # 格式化所有结果
        formatted_results = [self.format_scan_result(r) for r in report.results]
        formatted_report["results"] = formatted_results
        
        # 模块统计信息
        if report.module_stats:
            formatted_report["module_stats"] = report.module_stats
        
        # 扫描摘要（包含严重程度分布）
        summary = report.get_summary()
        formatted_report["summary"] = summary
        
        return formatted_report
    
    def format_report_filtered(
        self,
        report: ScanReport,
        result_type_filter: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        格式化报告，支持按结果类型或严重程度筛选（任务4）
        
        Args:
            report: 扫描报告对象
            result_type_filter: 按结果类型筛选（可选）
            severity_filter: 按严重程度筛选（可选）
            
        Returns:
            筛选后的格式化报告
        """
        filtered_results = report.results.copy()
        
        # 按结果类型筛选
        if result_type_filter:
            filtered_results = [
                r for r in filtered_results
                if r.result_type.value in result_type_filter
            ]
        
        # 按严重程度筛选
        if severity_filter:
            filtered_results = [
                r for r in filtered_results
                if r.severity.value in severity_filter
            ]
        
        # 创建临时报告对象
        filtered_report = ScanReport(
            target=report.target,
            start_time=report.start_time,
            end_time=report.end_time,
            results=filtered_results,
            module_stats=report.module_stats
        )
        
        return self.format_report(filtered_report)
    
    def to_json_string(self, data: Dict[str, Any], indent: int = 2) -> str:
        """
        将格式化后的字典转换为JSON字符串
        
        Args:
            data: 格式化后的字典
            indent: JSON缩进空格数
            
        Returns:
            JSON格式字符串
        """
        return json.dumps(data, indent=indent, ensure_ascii=False)
    
    def save_to_file(self, data: Dict[str, Any], filepath: str, indent: int = 2) -> None:
        """
        保存JSON格式数据到文件
        
        Args:
            data: 格式化后的字典
            filepath: 保存路径
            indent: JSON缩进空格数
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
