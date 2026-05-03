"""
DeepSeek AI服务适配器实现
集成DeepSeek API进行智能漏洞分析
"""
import json
import hashlib
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from openai import AsyncOpenAI
from dotenv import load_dotenv
import os

# 加载环境变量
# 尝试多个可能的.env文件路径
env_paths = ['.env', 'pysec-scanner/.env', os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')]
for env_path in env_paths:
    if os.path.exists(env_path):
        load_dotenv(env_path)
        break

from modules.ai.ai_service_adapter import AIServiceAdapter, AIAnalysisResult
from core.logger import logger


@dataclass
class PromptTemplates:
    """提示词模板"""
    system_prompt: str
    user_prompt: str
    fix_prompt: str


class DeepSeekClient(AIServiceAdapter):
    """DeepSeek API客户端实现"""
    
    def __init__(self, **kwargs):
        """
        初始化DeepSeek客户端
        
        从环境变量读取配置:
        - DEEPSEEK_API_KEY: API密钥 (必需)
        - DEEPSEEK_BASE_URL: API基础URL (可选，默认: https://api.deepseek.com)
        - DEEPSEEK_MODEL: 模型名称 (可选，默认: deepseek-chat)
        - DEEPSEEK_TEMPERATURE: 温度参数 (可选，默认: 0.7)
        - DEEPSEEK_MAX_TOKENS: 最大token数 (可选，默认: 2000)
        - DEEPSEEK_STREAM: 是否流式输出 (可选，默认: False)
        - DEEPSEEK_TIMEOUT: 超时时间(秒) (可选，默认: 30)
        - DEEPSEEK_MAX_RETRIES: 最大重试次数 (可选，默认: 3)
        - DEEPSEEK_RETRY_DELAY: 重试延迟(秒) (可选，默认: 1.0)
        """
        # 从环境变量读取配置
        api_key = os.getenv('DEEPSEEK_API_KEY', kwargs.get('api_key', ''))
        base_url = os.getenv('DEEPSEEK_BASE_URL', kwargs.get('base_url', 'https://api.deepseek.com'))
        model = os.getenv('DEEPSEEK_MODEL', kwargs.get('model', 'deepseek-chat'))
        temperature = float(os.getenv('DEEPSEEK_TEMPERATURE', kwargs.get('temperature', 0.7)))
        max_tokens = int(os.getenv('DEEPSEEK_MAX_TOKENS', kwargs.get('max_tokens', 2000)))
        stream = os.getenv('DEEPSEEK_STREAM', kwargs.get('stream', 'false')).lower() == 'true'
        timeout = float(os.getenv('DEEPSEEK_TIMEOUT', kwargs.get('timeout', 30.0)))
        max_retries = int(os.getenv('DEEPSEEK_MAX_RETRIES', kwargs.get('max_retries', 3)))
        retry_delay = float(os.getenv('DEEPSEEK_RETRY_DELAY', kwargs.get('retry_delay', 1.0)))
        
        # 调用父类初始化
        super().__init__(
            endpoint=base_url,
            api_key=api_key,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay
        )
        
        # 保存额外属性（父类不保存这些）
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.stream = stream
        self.base_url = base_url
        
        # 初始化OpenAI客户端
        self.client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=base_url,
            timeout=self._timeout
        )
        
        # 初始化提示词模板
        self.prompt_templates = PromptTemplates(
            system_prompt="""你是一位专业的应用安全分析师。请基于提供的“结构化漏洞数据”和“证据”做分析。

严格输出要求（必须满足）：
1) 只输出 **一个** JSON 对象（不要包含任何多余文字、markdown、代码块）
2) JSON 必须包含以下字段（字段名必须完全一致）：
   - root_cause: string（漏洞成因/根因，尽量具体到“缺少什么校验/在哪里拼接/在哪里输出未转义/哪里可控”）
   - impact_scope: string（影响范围：能造成什么后果、影响哪些资产/用户/系统边界）
   - attack_path: string（攻击路径：攻击者需要的前置条件、如何触发、如何扩大影响）
   - cvss_score: number（0-10，可为小数）
   - cvss_justification: string（为什么是这个分数，简短但要有依据）
   - additional_insights: object（可包含: prerequisites, exploitability, evidence_summary, recommended_next_steps 等）
3) 如果信息不足，请在 additional_insights.recommended_next_steps 给出“需要补充采集哪些证据/如何验证”，但 root_cause/impact_scope/attack_path 仍要给出基于现有信息的最合理推断。""",
            user_prompt="""请分析以下漏洞（尽量利用 raw_data 中的结构化字段）：

vulnerability_type: {vulnerability_type}
title: {title}
severity: {severity}
target: {target}
description: {description}
evidence_text: {evidence}
raw_data: {raw_data_json}

输出必须符合 system_prompt 的 JSON 格式要求。""",
            fix_prompt="""请为以下漏洞提供修复建议：

漏洞类型：{vulnerability_type}
漏洞代码：{code}
漏洞位置：{location}

请提供：
1. 具体的修复代码
2. 修复原理说明
3. 其他安全加固建议"""
        )
        
        logger.info(f"DeepSeekClient初始化完成 (model: {self.model}, temperature: {self.temperature})")
    
    async def analyze_vulnerability(
        self, 
        vulnerability_data: Dict[str, Any],
        **kwargs
    ) -> AIAnalysisResult:
        """
        分析单个漏洞 (任务5 - 漏洞分析接口)
        
        Args:
            vulnerability_data: 漏洞数据字典，包含:
                - vulnerability_type: 漏洞类型
                - description: 漏洞描述
                - location: 漏洞位置
                - evidence: 漏洞证据
                - 其他漏洞相关数据
        
        Returns:
            AIAnalysisResult: 分析结果
        """
        prompt = self._build_analysis_prompt(vulnerability_data)
        raw_response = await self._call_api(prompt)
        parsed_result = self._parse_response(raw_response)
        
        return AIAnalysisResult(
            root_cause=parsed_result.get("root_cause", parsed_result.get("analysis", f"{vulnerability_data.get('vulnerability_type', '未知漏洞')}: 需要进一步分析")),
            impact_scope=parsed_result.get("impact_scope", parsed_result.get("potential_impact", "待评估")),
            attack_path=parsed_result.get("attack_path", "待分析"),
            cvss_score=parsed_result.get("cvss_score", 7.0),
            cvss_justification=parsed_result.get("cvss_justification", f"基于AI分析结果 (模型: {self.model})"),
            additional_insights={
                "model": self.model,
                "vulnerability_type": vulnerability_data.get("vulnerability_type", ""),
                "ai_analysis": parsed_result.get("analysis", ""),
                "risk_assessment": parsed_result.get("risk_assessment", "")
            }
        )
    
    async def analyze_batch(
        self,
        vulnerability_list: List[Dict[str, Any]],
        **kwargs
    ) -> List[AIAnalysisResult]:
        """
        批量分析漏洞 (任务9 - 批量分析接口)
        
        Args:
            vulnerability_list: 漏洞数据列表
        
        Returns:
            List[AIAnalysisResult]: 分析结果列表
        """
        results = []
        
        # 并发分析
        tasks = [
            self.analyze_vulnerability(vuln_data)
            for vuln_data in vulnerability_list
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量分析第{i+1}项失败: {result}")
                final_results.append(
                    AIAnalysisResult(
                        root_cause=f"分析失败: {str(result)}",
                        impact_scope="未知",
                        attack_path="未知",
                        cvss_score=0.0,
                        cvss_justification="分析失败",
                        additional_insights={}
                    )
                )
            else:
                final_results.append(result)
        
        return final_results
    
    async def generate_fix_suggestion(
        self,
        vulnerability_data: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """
        生成修复建议 (任务7 - 修复建议接口)
        
        Args:
            vulnerability_data: 漏洞数据，包含:
                - vulnerability_type: 漏洞类型
                - code: 漏洞代码
                - location: 漏洞位置
        
        Returns:
            Dict: 修复建议，包含:
                - fix_code: 修复代码
                - fix_explanation: 修复说明
                - additional_measures: 其他安全措施
        """
        prompt = self._build_fix_prompt(vulnerability_data)
        raw_response = await self._call_api(prompt)
        parsed_result = self._parse_response(raw_response)
        
        return {
            "fix_code": parsed_result.get("fix_code", ""),
            "fix_explanation": parsed_result.get("fix_explanation", ""),
            "additional_measures": parsed_result.get("additional_measures", [])
        }
    
    def _build_analysis_prompt(self, vulnerability_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        构建分析提示词
        
        Args:
            vulnerability_data: 漏洞数据
        
        Returns:
            List[Dict]: 消息列表
        """
        # 系统提示词
        messages = [
            {"role": "system", "content": self.prompt_templates.system_prompt}
        ]
        
        # 用户提示词
        vuln_type = vulnerability_data.get("vulnerability_type", "未知")
        description = vulnerability_data.get("description", "无描述")
        evidence = vulnerability_data.get("evidence", vulnerability_data.get("payload", "无证据"))

        # 将结构化字段也提供给模型
        raw_data = vulnerability_data.get("raw_data", {})
        try:
            raw_data_json = json.dumps(raw_data, ensure_ascii=False)
        except Exception:
            raw_data_json = str(raw_data)
        
        user_prompt = self.prompt_templates.user_prompt.format(
            vulnerability_type=vuln_type,
            title=vulnerability_data.get("title", ""),
            severity=vulnerability_data.get("severity", ""),
            target=vulnerability_data.get("target", ""),
            description=description,
            evidence=evidence,
            raw_data_json=raw_data_json
        )
        
        messages.append({"role": "user", "content": user_prompt})
        
        return messages
    
    def _build_fix_prompt(self, vulnerability_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        构建修复建议提示词
        
        Args:
            vulnerability_data: 漏洞数据
        
        Returns:
            List[Dict]: 消息列表
        """
        messages = [
            {"role": "system", "content": "你是一位专业的安全工程师，擅长代码安全修复。请提供准确的修复代码和清晰的说明。"}
        ]
        
        vuln_type = vulnerability_data.get("vulnerability_type", "未知")
        code = vulnerability_data.get("code", "无代码")
        location = vulnerability_data.get("location", "未知位置")
        
        fix_prompt = self.prompt_templates.fix_prompt.format(
            vulnerability_type=vuln_type,
            code=code,
            location=location
        )
        
        messages.append({"role": "user", "content": fix_prompt})
        
        return messages
    
    async def _call_api(self, messages: List[Dict[str, str]]) -> Any:
        """
        调用DeepSeek API（非流式）
        
        Args:
            messages: 消息列表
        
        Returns:
            Any: API响应
        """
        # 使用重试机制
        return await self._retry_on_failure(
            self._make_api_call,
            messages
        )
    
    async def _call_api_streaming(
        self,
        messages: List[Dict[str, str]],
        callback=None
    ) -> str:
        """
        调用DeepSeek API（流式）
        
        Args:
            messages: 消息列表
            callback: 流式数据回调函数，接收每次产生的文本块
        
        Returns:
            str: 完整的响应文本
        """
        try:
            logger.debug(f"调用DeepSeek API（流式），模型: {self.model}，消息数: {len(messages)}")
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True  # 启用流式输出
            )
            
            full_content = ""
            
            # 迭代流式响应
            async for chunk in response:
                if chunk.choices and chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_content += content
                    
                    # 调用回调函数（如果提供）
                    if callback:
                        callback(content)
            
            logger.debug(f"流式API调用完成，总长度: {len(full_content)}")
            return full_content
            
        except Exception as e:
            logger.error(f"流式API调用失败: {type(e).__name__}: {e}")
            raise
    
    async def _make_api_call(self, messages: List[Dict[str, str]]) -> Any:
        """
        执行实际的API调用
        
        Args:
            messages: 消息列表
        
        Returns:
            Any: API响应
        """
        try:
            logger.debug(f"调用DeepSeek API，模型: {self.model}，消息数: {len(messages)}")
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=self.stream
            )
            
            logger.debug(f"API调用成功，响应类型: {type(response)}")
            return response
            
        except Exception as e:
            logger.error(f"API调用失败: {type(e).__name__}: {e}")
            raise
    
    def _parse_response(self, response: Any) -> Dict[str, Any]:
        """
        解析API响应
        
        Args:
            response: API响应对象
        
        Returns:
            Dict: 解析后的结果字典
        """
        try:
            # 从响应对象中提取内容
            content = response.choices[0].message.content
            
            # 尝试解析JSON（容错：提取首个{...}片段）
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                start = content.find("{")
                end = content.rfind("}")
                if start != -1 and end != -1 and end > start:
                    result = json.loads(content[start:end+1])
                else:
                    raise
            
            logger.debug(f"响应解析成功: {list(result.keys())}")
            return result
            
        except (AttributeError, IndexError, json.JSONDecodeError) as e:
            logger.error(f"响应解析失败: {type(e).__name__}: {e}")
            
            # 返回默认结果
            return {
                "root_cause": "AI响应解析失败（模型输出未返回可解析JSON）",
                "impact_scope": "影响范围无法自动评估",
                "attack_path": "攻击路径待进一步验证",
                "cvss_score": 5.0,
                "cvss_justification": "由于模型输出不可解析，给出保守中等分值",
                "additional_insights": {
                    "ai_parse_error": True,
                    "recommended_next_steps": [
                        "检查网络/密钥/模型配置",
                        "开启日志查看原始响应内容",
                        "重试并确保模型按JSON输出"
                    ]
                }
            }
    
    def _normalize_response(self, raw_response: Any) -> Dict[str, Any]:
        """
        标准化API响应
        
        Args:
            raw_response: 原始API响应
        
        Returns:
            Dict: 标准化后的响应
        """
        return self._parse_response(raw_response)
    
    def _generate_cache_key(self, vulnerability_data: Dict[str, Any]) -> str:
        """
        生成缓存键 (任务4 - 缓存机制)
        
        Args:
            vulnerability_data: 漏洞数据
        
        Returns:
            str: SHA256哈希值
        """
        # 将漏洞数据转换为JSON字符串
        data_str = json.dumps(vulnerability_data, sort_keys=True)
        
        # 生成SHA256哈希
        hash_obj = hashlib.sha256(data_str.encode())
        return hash_obj.hexdigest()
