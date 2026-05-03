"""
AI服务适配器接口
定义统一的AI服务接口，支持多种AI服务接入
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import asyncio
import time


@dataclass
class AIAnalysisResult:
    """AI分析结果数据类"""
    root_cause: str = ""
    impact_scope: str = ""
    attack_path: str = ""
    cvss_score: float = 0.0
    cvss_justification: str = ""
    additional_insights: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "root_cause": self.root_cause,
            "impact_scope": self.impact_scope,
            "attack_path": self.attack_path,
            "cvss_score": self.cvss_score,
            "cvss_justification": self.cvss_justification,
            "additional_insights": self.additional_insights or {}
        }


class AIServiceAdapter(ABC):
    """AI服务适配器抽象基类（任务5）"""
    
    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        model: str = "",
        **kwargs
    ):
        """
        初始化AI服务适配器
        
        Args:
            endpoint: AI服务端点URL
            api_key: API密钥
            model: 模型名称
            **kwargs: 其他配置参数
        """
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.config = kwargs
        self._max_retries = kwargs.get("max_retries", 3)
        self._retry_delay = kwargs.get("retry_delay", 1.0)
        self._timeout = kwargs.get("timeout", 30.0)
    
    @abstractmethod
    async def analyze_vulnerability(
        self,
        vulnerability_data: Dict[str, Any]
    ) -> AIAnalysisResult:
        """
        分析单个漏洞（抽象方法，子类必须实现）
        
        Args:
            vulnerability_data: 漏洞数据字典
            
        Returns:
            AI分析结果
            
        需求: [FR-005]
        """
        pass
    
    @abstractmethod
    async def analyze_batch(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[AIAnalysisResult]:
        """
        批量分析漏洞（抽象方法，子类必须实现）
        
        Args:
            vulnerabilities: 漏洞数据列表
            
        Returns:
            AI分析结果列表
            
        需求: [FR-005, FR-013]
        """
        pass
    
    @abstractmethod
    async def generate_fix_suggestion(
        self,
        vulnerability_data: Dict[str, Any],
        analysis_result: AIAnalysisResult
    ) -> Dict[str, Any]:
        """
        生成修复建议（抽象方法，子类必须实现）
        
        Args:
            vulnerability_data: 漏洞数据字典
            analysis_result: AI分析结果
            
        Returns:
            修复建议字典
            
        需求: [FR-005]
        """
        pass
    
    async def _retry_on_failure(
        self,
        func,
        *args,
        **kwargs
    ) -> Any:
        """
        失败重试机制（错误处理和重试）
        
        Args:
            func: 要执行的异步函数
            *args: 位置参数
            **kwargs: 关键字参数
            
        Returns:
            函数执行结果
        """
        last_error = None
        
        for attempt in range(self._max_retries):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self._timeout
                )
            except asyncio.TimeoutError as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay)
                    continue
                raise Exception(f"AI服务请求超时: {e}")
            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay)
                    continue
                raise Exception(f"AI服务请求失败: {e}")
        
        raise Exception(f"AI服务重试{self._max_retries}次后仍然失败: {last_error}")
    
    def _normalize_response(self, raw_response: Any) -> Dict[str, Any]:
        """
        标准化AI服务响应格式
        
        Args:
            raw_response: AI服务原始响应
            
        Returns:
            标准化后的响应字典
        """
        # 子类可以覆盖此方法以适配不同的响应格式
        if isinstance(raw_response, dict):
            return raw_response
        elif hasattr(raw_response, "__dict__"):
            return raw_response.__dict__
        else:
            return {"response": str(raw_response)}


class OpenAIAdapter(AIServiceAdapter):
    """OpenAI服务适配器（示例实现）"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.api_key:
            raise ValueError("OpenAI API密钥未配置")
        
        # 这里可以添加OpenAI客户端初始化代码
        # 示例: self.client = openai.AsyncOpenAI(api_key=self.api_key)
    
    async def analyze_vulnerability(
        self,
        vulnerability_data: Dict[str, Any]
    ) -> AIAnalysisResult:
        """分析单个漏洞（使用OpenAI）"""
        try:
            # 构建提示词
            prompt = self._build_analysis_prompt(vulnerability_data)
            
            # 这里应该是实际的OpenAI API调用
            # response = await self.client.chat.completions.create(
            #     model=self.model or "gpt-4",
            #     messages=[{"role": "user", "content": prompt}]
            # )
            
            # 示例返回（实际应该解析API响应）
            return self._parse_analysis_response({
                "root_cause": "API未正确验证用户输入",
                "impact_scope": "可能导致数据泄露和系统控制",
                "attack_path": "恶意SQL注入 -> 数据库访问 -> 数据泄露",
                "cvss_score": 8.6,
                "cvss_justification": "高影响+可远程利用"
            })
        except Exception as e:
            raise Exception(f"OpenAI漏洞分析失败: {e}")
    
    async def analyze_batch(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[AIAnalysisResult]:
        """批量分析漏洞（使用OpenAI）"""
        results = []
        for vuln in vulnerabilities:
            result = await self.analyze_vulnerability(vuln)
            results.append(result)
        return results
    
    async def generate_fix_suggestion(
        self,
        vulnerability_data: Dict[str, Any],
        analysis_result: AIAnalysisResult
    ) -> Dict[str, Any]:
        """生成修复建议（使用OpenAI）"""
        try:
            # 构建提示词
            prompt = self._build_fix_prompt(vulnerability_data, analysis_result)
            
            # 示例返回
            return {
                "fix_type": "代码修复",
                "description": "使用参数化查询防止SQL注入",
                "steps": [
                    "替换拼接SQL字符串",
                    "使用ORM框架",
                    "添加输入验证"
                ],
                "code_example": "使用prepared statement",
                "verification_method": "再次执行漏洞扫描"
            }
        except Exception as e:
            raise Exception(f"OpenAI修复建议生成失败: {e}")
    
    def _build_analysis_prompt(
        self,
        vulnerability_data: Dict[str, Any]
    ) -> str:
        """构建漏洞分析提示词"""
        vuln_type = vulnerability_data.get("vulnerability_type", "unknown")
        return f"分析以下漏洞的根本原因、影响范围和攻击路径：{vuln_type}"
    
    def _build_fix_prompt(
        self,
        vulnerability_data: Dict[str, Any],
        analysis_result: AIAnalysisResult
    ) -> str:
        """构建修复建议提示词"""
        return "根据漏洞分析结果，提供修复建议"
    
    def _parse_analysis_response(
        self,
        response: Dict[str, Any]
    ) -> AIAnalysisResult:
        """解析AI分析响应"""
        return AIAnalysisResult(
            root_cause=response.get("root_cause", ""),
            impact_scope=response.get("impact_scope", ""),
            attack_path=response.get("attack_path", ""),
            cvss_score=response.get("cvss_score", 0.0),
            cvss_justification=response.get("cvss_justification", "")
        )


class MockAIServiceAdapter(AIServiceAdapter):
    """模拟AI服务适配器（用于测试和演示）"""
    
    async def analyze_vulnerability(
        self,
        vulnerability_data: Dict[str, Any]
    ) -> AIAnalysisResult:
        """模拟分析单个漏洞"""
        vuln_type = vulnerability_data.get("vulnerability_type", "unknown")
        
        # 模拟分析结果
        if vuln_type == "sql_injection":
            return AIAnalysisResult(
                root_cause="未对用户输入进行充分验证，直接拼接到SQL查询中",
                impact_scope="可能导致数据库信息泄露、数据篡改甚至服务器控制",
                attack_path="恶意输入 -> SQL注入 -> 数据库查询 -> 敏感数据泄露",
                cvss_score=8.6,
                cvss_justification="高危漏洞，可远程利用，影响严重",
                additional_insights={
                    "confidence": "high",
                    "data_types_at_risk": ["credentials", "personal_data"]
                }
            )
        elif vuln_type == "xss":
            return AIAnalysisResult(
                root_cause="未对用户输入进行转义处理，直接输出到页面",
                impact_scope="可能导致用户会话劫持、钓鱼攻击、恶意脚本执行",
                attack_path="恶意脚本注入 -> 用户浏览器执行 -> 会话窃取",
                cvss_score=6.1,
                cvss_justification="中危漏洞，需要用户交互",
                additional_insights={
                    "confidence": "high",
                    "xss_types": ["reflected", "stored"]
                }
            )
        else:
            return AIAnalysisResult(
                root_cause="需要进一步分析",
                impact_scope="待评估",
                attack_path="待分析",
                cvss_score=5.0,
                cvss_justification="默认评分"
            )
    
    async def analyze_batch(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[AIAnalysisResult]:
        """模拟批量分析漏洞"""
        results = []
        for vuln in vulnerabilities:
            result = await self.analyze_vulnerability(vuln)
            results.append(result)
        return results
    
    async def generate_fix_suggestion(
        self,
        vulnerability_data: Dict[str, Any],
        analysis_result: AIAnalysisResult
    ) -> Dict[str, Any]:
        """模拟生成修复建议"""
        vuln_type = vulnerability_data.get("vulnerability_type", "unknown")
        
        if vuln_type == "sql_injection":
            return {
                "fix_type": "代码修复",
                "description": "使用参数化查询或ORM框架防止SQL注入",
                "steps": [
                    "替换所有字符串拼接的SQL语句",
                    "使用预编译语句(prepared statement)",
                    "实现ORM映射层",
                    "添加输入验证和过滤"
                ],
                "code_example": {
                    "vulnerable": "SELECT * FROM users WHERE id = '" + user_input + "'",
                    "fixed": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))"
                },
                "verification_method": "使用相同Payload重新测试，应无法注入",
                "priority": "high"
            }
        elif vuln_type == "xss":
            return {
                "fix_type": "代码修复+配置修复",
                "description": "对输出进行HTML转义并配置CSP策略",
                "steps": [
                    "对所有用户输入进行HTML实体编码",
                    "配置内容安全策略(CSP)头部",
                    "启用HttpOnly和Secure Cookie标记"
                ],
                "code_example": {
                    "vulnerable": "<div>" + user_input + "</div>",
                    "fixed": "<div>" + escape(user_input) + "</div>"
                },
                "verification_method": "检查响应头中是否存在CSP，尝试XSS Payload应失效",
                "priority": "medium"
            }
        else:
            return {
                "fix_type": "通用加固",
                "description": "建议进行安全审计和渗透测试",
                "steps": [
                    "进行代码审查",
                    "执行深度安全测试",
                    "应用安全最佳实践"
                ],
                "verification_method": "重新执行扫描",
                "priority": "medium"
            }
