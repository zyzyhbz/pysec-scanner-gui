"""
修复建议生成器
协调模板和AI结果生成具体修复建议
"""

from typing import Dict, List, Any, Optional
import asyncio

from core.base import ScanResult
from modules.fix.fix_template_library import FixTemplateLibrary
from modules.ai.ai_service_adapter import AIAnalysisResult


class FixGenerator:
    """修复建议生成器（任务10）"""
    
    def __init__(
        self,
        template_library: Optional[FixTemplateLibrary] = None,
        ai_service_adapter: Optional[Any] = None
    ):
        """
        初始化修复建议生成器
        
        Args:
            template_library: 模板库实例
            ai_service_adapter: AI服务适配器实例
        """
        self.template_library = template_library or FixTemplateLibrary()
        self.ai_service_adapter = ai_service_adapter
    
    async def generate_fix(
        self,
        result: ScanResult,
        analysis_result: Optional[AIAnalysisResult] = None
    ) -> Dict[str, Any]:
        """
        生成修复建议（任务10 - 模板+AI混合策略）
        
        Args:
            result: 扫描结果
            analysis_result: AI分析结果
            
        Returns:
            修复建议字典
        """
        # 确定漏洞类型
        vulnerability_type = self._get_vulnerability_type(result)
        
        # 收集上下文信息
        context = self._build_context(result, analysis_result)
        
        # 使用模板生成基础修复建议（模板+AI混合策略）
        suggestion = self.template_library.apply_template(vulnerability_type, context)
        
        # 如果有AI服务，AI增强建议内容
        if self.ai_service_adapter and analysis_result:
            try:
                ai_enhanced = await self.ai_service_adapter.generate_fix_suggestion(
                    result.to_dict(),
                    analysis_result
                )
                suggestion = self._merge_ai_suggestion(suggestion, ai_enhanced)
            except Exception:
                # AI失败，继续使用模板建议
                pass
        
        # 上下文适配（根据具体漏洞场景调整建议内容）
        suggestion = self._adapt_to_context(suggestion, result, context)
        
        # 修复建议格式化输出
        formatted_suggestion = self._format_suggestion(suggestion)
        
        return formatted_suggestion
    
    async def generate_fixes_batch(
        self,
        results: List[ScanResult],
        analysis_results: Optional[List[AIAnalysisResult]] = None
    ) -> List[Dict[str, Any]]:
        """
        批量生成修复建议
        
        Args:
            results: 扫描结果列表
            analysis_results: AI分析结果列表
            
        Returns:
            修复建议列表
        """
        suggestions = []
        
        for i, result in enumerate(results):
            analysis = analysis_results[i] if analysis_results and i < len(analysis_results) else None
            suggestion = await self.generate_fix(result, analysis)
            suggestions.append(suggestion)
        
        # 修复优先级排序
        suggestions = self._sort_by_priority(suggestions)
        
        return suggestions
    
    def _get_vulnerability_type(self, result: ScanResult) -> str:
        """
        从扫描结果中获取漏洞类型
        
        Args:
            result: 扫描结果
            
        Returns:
            漏洞类型字符串
        """
        # 从raw_data中获取
        vuln_type = result.raw_data.get("vulnerability_type", "")
        if vuln_type:
            return vuln_type
        
        # 根据结果类型推断
        result_type = result.result_type.value
        if result_type == "port":
            return "port_security"
        elif "injection" in result.title.lower() or "注入" in result.title:
            if "sql" in result.title.lower():
                return "sql_injection"
            elif "command" in result.title.lower() or "命令" in result.title:
                return "command_injection"
        elif "xss" in result.title.lower():
            return "xss"
        elif "csrf" in result.title.lower():
            return "csrf"
        elif "file_inclusion" in result.raw_data:
            return "file_inclusion"
        elif "ssrf" in result.raw_data:
            return "ssrf"
        elif "xxe" in result.raw_data:
            return "xxe"
        
        return "general"
    
    def _build_context(
        self,
        result: ScanResult,
        analysis_result: Optional[AIAnalysisResult]
    ) -> Dict[str, Any]:
        """
        构建上下文信息
        
        Args:
            result: 扫描结果
            analysis_result: AI分析结果
            
        Returns:
            上下文字典
        """
        context = {
            "target": result.target,
            "result_type": result.result_type.value,
            "title": result.title,
            "description": result.description,
            "severity": result.severity.value,
            "evidence": result.evidence,
            "raw_data": result.raw_data
        }
        
        if analysis_result:
            context.update({
                "root_cause": analysis_result.root_cause,
                "impact_scope": analysis_result.impact_scope,
                "attack_path": analysis_result.attack_path,
                "cvss_score": analysis_result.cvss_score,
                "cvss_justification": analysis_result.cvss_justification,
                "additional_insights": analysis_result.additional_insights
            })
        
        return context
    
    def _merge_ai_suggestion(
        self,
        template_suggestion: Dict[str, Any],
        ai_suggestion: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        合并模板建议和AI建议
        
        Args:
            template_suggestion: 模板生成的建议
            ai_suggestion: AI生成的建议
            
        Returns:
            合并后的建议
        """
        merged = template_suggestion.copy()
        
        # 合并修复步骤（Mock 风格: steps）
        template_steps = template_suggestion.get("fix_steps", [])
        ai_steps = ai_suggestion.get("steps", [])
        if ai_steps:
            merged["fix_steps"] = {
                "from_template": template_steps,
                "from_ai_enhanced": ai_steps,
                "combined": template_steps + [step for step in ai_steps if step not in template_steps]
            }
        
        # DeepSeek 风格: additional_measures -> 视为补充修复步骤
        if "additional_measures" in ai_suggestion and ai_suggestion["additional_measures"]:
            measures = ai_suggestion["additional_measures"]
            if not isinstance(measures, list):
                measures = [str(measures)]
            extra_steps = [str(m) for m in measures]
            existing = merged.get("fix_steps")
            if isinstance(existing, dict):
                combined = existing.get("combined", [])
                merged["fix_steps"]["combined"] = combined + [s for s in extra_steps if s not in combined]
                merged["fix_steps"]["from_ai_additional"] = extra_steps
            elif isinstance(existing, list):
                merged["fix_steps"] = existing + [s for s in extra_steps if s not in existing]
            else:
                merged["fix_steps"] = extra_steps
        
        # 合并代码示例（Mock 风格: code_example）
        template_examples = template_suggestion.get("code_examples", {})
        ai_examples = ai_suggestion.get("code_example", "")
        if ai_examples:
            if isinstance(ai_examples, dict):
                merged["code_examples"] = {**template_examples, **ai_examples}
            else:
                merged["code_examples"] = {
                    **template_examples,
                    "ai_enhanced_example": ai_examples
                }
        
        # DeepSeek 风格: fix_code -> 代码示例
        if "fix_code" in ai_suggestion and ai_suggestion["fix_code"]:
            code = ai_suggestion["fix_code"]
            code_examples = merged.get("code_examples", {})
            if isinstance(code, dict):
                code_examples.update(code)
            else:
                code_examples["ai_fix_code"] = code
            merged["code_examples"] = code_examples
        
        # DeepSeek 风格: fix_explanation -> 描述增强
        if "fix_explanation" in ai_suggestion and ai_suggestion["fix_explanation"]:
            base_desc = merged.get("description", "")
            extra = str(ai_suggestion["fix_explanation"])
            if base_desc:
                merged["description"] = f"{base_desc}\n\n[AI修复说明]\n{extra}"
            else:
                merged["description"] = extra
        
        # 合并验证方法（Mock 风格）
        if "verification_method" in ai_suggestion:
            merged["verification_methods"] = {
                "template_method": template_suggestion.get("verification_method", ""),
                "ai_method": ai_suggestion["verification_method"]
            }
        
        # 添加AI标记
        merged["ai_enhanced"] = True
        merged["ai_source"] = ai_suggestion
        
        return merged
    
    def _adapt_to_context(
        self,
        suggestion: Dict[str, Any],
        result: ScanResult,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        上下文适配（任务10 - 根据具体漏洞场景调整建议内容）
        
        Args:
            suggestion: 修复建议
            result: 扫描结果
            context: 上下文信息
            
        Returns:
            适配后的建议
        """
        # 根据具体漏洞证据调整描述
        if "injection_point" in result.raw_data:
            injection_point = result.raw_data["injection_point"]
            suggestion["affected_location"] = injection_point
        
        if "vulnerability_type" in result.raw_data:
            vuln_type = result.raw_data["vulnerability_type"]
            if vuln_type == "sql_injection":
                injection_type = result.raw_data.get("injection_type", "")
                suggestion["injection_type_details"] = injection_type
                if injection_type == "boolean":
                    suggestion["description"] += " (盲注类型，需要特别注意检测)"
            elif vuln_type == "xss":
                payload_type = result.raw_data.get("payload_type", "")
                if payload_type == "stored":
                    suggestion["priority"] = "high"
                    suggestion["description"] += " (存储型XSS危害较大，优先修复)"
        
        # 根据目标环境调整
        target = result.target.lower()
        if ".php" in target:
            suggestion["applicable_technologies"] = ["PHP"]
        elif ".jsp" in target or ".java" in target:
            suggestion["applicable_technologies"] = ["Java"]
        elif ".asp" in target:
            suggestion["applicable_technologies"] = ["ASP.NET"]
        elif ".py" in target:
            suggestion["applicable_technologies"] = ["Python"]
        
        # 根据严重程度调整优先级
        cvss_score = context.get("cvss_score", 0.0)
        if cvss_score >= 9.0:
            suggestion["priority"] = "critical"
        elif cvss_score >= 7.0:
            suggestion["priority"] = "high"
        elif cvss_score >= 4.0:
            suggestion["priority"] = "medium"
        
        return suggestion
    
    def _format_suggestion(self, suggestion: Dict[str, Any]) -> Dict[str, Any]:
        """
        修复建议格式化输出（任务10）
        
        Args:
            suggestion: 原始建议
            
        Returns:
            格式化后的建议
        """
        formatted = {
            "suggestion_id": f"fix_{hash(str(suggestion)) % 10000:04d}",
            "vulnerability_type": suggestion.get("vulnerability_type", "unknown"),
            "title": suggestion.get("name", suggestion.get("title", "修复建议")),
            "description": suggestion.get("description", ""),
            "priority": suggestion.get("priority", "medium"),
            "fix_type": suggestion.get("fix_type", "code"),
            "timestamp": asyncio.get_event_loop().time()
        }
        
        # 修复步骤
        if "fix_steps" in suggestion:
            steps = suggestion["fix_steps"]
            if isinstance(steps, dict):
                # 复杂结构，直接保留
                formatted["fix_steps"] = steps
            else:
                # 简单列表，添加进度指示
                formatted["fix_steps"] = [
                    f"{i+1}. {step}" for i, step in enumerate(steps)
                ]
        
        # 代码示例
        if "code_examples" in suggestion and suggestion["code_examples"]:
            formatted["code_examples"] = suggestion["code_examples"]
        
        # 配置示例
        if "configuration_examples" in suggestion and suggestion["configuration_examples"]:
            formatted["configuration_examples"] = suggestion["configuration_examples"]
        
        # 验证方法
        if "verification_methods" in suggestion:
            formatted["verification"] = suggestion["verification_methods"]
        elif "verification_method" in suggestion:
            formatted["verification"] = {
                "method": suggestion["verification_method"]
            }
        
        # 附加信息
        extra_fields = ["affected_target", "affected_location", "applicable_technologies",
                      "vulnerability_evidence", "root_cause_analysis", "ai_enhanced", "ai_source"]
        for field in extra_fields:
            if field in suggestion:
                formatted[field] = suggestion[field]
        
        # 参考资料
        if "references" in suggestion:
            formatted["references"] = suggestion["references"]
        
        return formatted
    
    def _sort_by_priority(self, suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        修复优先级排序（任务10）
        
        Args:
            suggestions: 修复建议列表
            
        Returns:
            排序后的建议列表
        """
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        
        def get_priority_weight(suggestion: Dict[str, Any]) -> int:
            priority = suggestion.get("priority", "medium")
            return priority_order.get(priority, 2)
        
        return sorted(suggestions, key=get_priority_weight)
