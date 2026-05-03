"""
AI分析编排器
协调AI服务进行漏洞分析
"""

from typing import Dict, List, Any, Optional
import asyncio
from dotenv import load_dotenv

from core.base import ScanResult, ResultType
from modules.ai.ai_service_adapter import AIServiceAdapter, AIAnalysisResult
from modules.ai.deepseek_client import DeepSeekClient
from core.logger import logger

# 加载环境变量
load_dotenv('pysec-scanner/.env')

class AIAnalyzer:
    """AI分析编排器，协调各种类型的分析（任务6、7、8）"""
    
    def __init__(
        self,
        ai_service: Optional[AIServiceAdapter] = None
    ):
        """
        初始化AI分析器
        
        Args:
            ai_service: AI服务适配器实例，如果为None则自动创建DeepSeekClient
        """
        # 自动创建DeepSeekClient如果未提供ai_service
        if ai_service is None:
            logger.info("未提供AI服务，自动创建DeepSeekClient")
            self.ai_service = DeepSeekClient()
            logger.info(f"DeepSeekClient已创建，模型: {self.ai_service.model}")
        else:
            self.ai_service = ai_service
            logger.info("使用提供的AI服务适配器")
        
        self._analysis_cache = {}
        logger.info("AIAnalyzer初始化完成")
    
    async def analyze(self, result: ScanResult) -> AIAnalysisResult:
        """
        分析单个扫描结果（任务6 - AI分析编排）
        
        Args:
            result: 扫描结果对象
            
        Returns:
            AI分析结果
        """
        if not self.ai_service:
            return self._generate_default_analysis(result)
        
        try:
            # 根据结果类型选择分析策略
            result_type = result.result_type
            
            if result_type == ResultType.PORT:
                analysis = await self._analyze_port(result)
            elif result_type == ResultType.VULNERABILITY or (isinstance(result.raw_data, dict) and result.raw_data.get("vulnerability_type")):
                analysis = await self._analyze_vulnerability(result)
            else:
                # 其他类型使用通用分析
                analysis = await self._analyze_generic(result)
            
            return analysis
        except Exception as e:
            # AI服务失败时返回默认分析
            return self._generate_default_analysis(result, error=str(e))
    
    async def _analyze_vulnerability(self, result: ScanResult) -> AIAnalysisResult:
        """
        分析Web漏洞（任务8 - Web漏洞AI深度分析）
        
        Args:
            result: 漏洞扫描结果
            
        Returns:
            深度分析结果
        """
        vuln_type = ""
        if isinstance(result.raw_data, dict):
            vuln_type = result.raw_data.get("vulnerability_type", "") or ""
        if not vuln_type:
            vuln_type = self._infer_vulnerability_type(result)
        vulnerability_data = result.to_dict()
        vulnerability_data["vulnerability_type"] = vuln_type
        if isinstance(result.raw_data, dict):
            # 把结构化证据也带给AI服务（如果有）
            vulnerability_data["raw_data"] = result.raw_data
        
        # 记录日志：开始漏洞分析
        logger.info(f"开始漏洞分析，类型: {vuln_type}")
        
        # 调用AI服务进行基础分析
        try:
            analysis = await self.ai_service.analyze_vulnerability(vulnerability_data)
            logger.info(f"漏洞分析完成: {vuln_type}")
        except Exception as e:
            logger.error(f"漏洞分析异常: {type(e).__name__}: {e}")
            raise
        
        # 根据漏洞类型进行补充分析
        if vuln_type == "sql_injection":
            analysis = self._enhance_sqli_analysis(result, analysis)
        elif vuln_type == "xss":
            analysis = self._enhance_xss_analysis(result, analysis)
        elif vuln_type == "csrf":
            analysis = self._enhance_csrf_analysis(result, analysis)
        elif vuln_type == "command_injection":
            analysis = self._enhance_command_injection_analysis(result, analysis)
        elif vuln_type == "file_inclusion" or vuln_type == "ssrf":
            analysis = self._enhance_lateral_movement_analysis(result, analysis)
        elif vuln_type == "xxe":
            analysis = self._enhance_xxe_analysis(result, analysis)
        elif vuln_type == "sensitive_info":
            analysis = self._enhance_sensitive_info_analysis(result, analysis)
        elif vuln_type == "open_redirect":
            analysis = self._enhance_open_redirect_analysis(result, analysis)
        elif vuln_type == "path_traversal":
            analysis = self._enhance_path_traversal_analysis(result, analysis)
        
        # 漏洞链分析
        analysis = self._analyze_vulnerability_chain(result, analysis)
        
        return analysis

    def _infer_vulnerability_type(self, result: ScanResult) -> str:
        """
        尝试从标题/描述/原始数据推断漏洞类型（用于模块未提供标准字段时兜底）
        """
        title = (result.title or "").lower()
        desc = (result.description or "").lower()
        raw = result.raw_data if isinstance(result.raw_data, dict) else {}

        # raw_data 特征优先
        if "inclusion_type" in raw:
            return "file_inclusion"
        if "missing_token" in raw or "missing_referer_check" in raw:
            return "csrf"
        if "os_type" in raw or "command_type" in raw:
            return "command_injection"
        if "ssrf_type" in raw:
            return "ssrf"
        if "payload_type" in raw and "context" in raw:
            return "xss"
        if "injection_type" in raw and ("sql" in title or "sql" in desc):
            return "sql_injection"
        if "sensitive_type" in raw or "matched_content" in raw:
            return "sensitive_info"

        # 文本关键词兜底
        text = f"{title} {desc}"
        if "sql" in text and ("注入" in text or "injection" in text):
            return "sql_injection"
        if "xss" in text:
            return "xss"
        if "ssrf" in text:
            return "ssrf"
        if "csrf" in text:
            return "csrf"
        if "命令注入" in text or "command injection" in text:
            return "command_injection"
        if "文件包含" in text or "lfi" in text or "rfi" in text:
            return "file_inclusion"
        if "敏感信息" in text or "泄露" in text:
            return "sensitive_info"
        if "重定向" in text or "open redirect" in text:
            return "open_redirect"
        if "遍历" in text or "traversal" in text:
            return "path_traversal"
        return "general"

    def _enhance_sensitive_info_analysis(self, result: ScanResult, analysis: AIAnalysisResult) -> AIAnalysisResult:
        raw = result.raw_data if isinstance(result.raw_data, dict) else {}
        sensitive_type = raw.get("sensitive_type", "")
        url = raw.get("url", result.target)

        analysis.root_cause = analysis.root_cause or "应用将敏感信息直接暴露在可被未授权访问的位置"
        analysis.impact_scope = analysis.impact_scope or "可能导致凭证泄露、配置泄露、隐私数据泄露，并引发进一步横向移动"
        analysis.attack_path = analysis.attack_path or f"访问公开资源 -> 获取敏感信息({sensitive_type or '未知类型'}) -> 利用泄露信息进一步入侵"
        analysis.cvss_score = analysis.cvss_score or 6.5
        analysis.cvss_justification = analysis.cvss_justification or "信息泄露通常可被远程利用，影响依泄露内容而定"

        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "url": url,
            "sensitive_type": sensitive_type,
            "recommended_actions": [
                "移除公开暴露的敏感文件/信息",
                "对敏感配置启用访问控制（鉴权/白名单/内网隔离）",
                "替换已泄露的密钥/Token并审计历史访问"
            ]
        })
        return analysis

    def _enhance_open_redirect_analysis(self, result: ScanResult, analysis: AIAnalysisResult) -> AIAnalysisResult:
        analysis.root_cause = analysis.root_cause or "重定向目标可被用户输入控制，且缺少白名单校验"
        analysis.impact_scope = analysis.impact_scope or "可用于钓鱼、OAuth跳转劫持、绕过部分安全校验"
        analysis.attack_path = analysis.attack_path or "构造恶意跳转URL -> 用户点击 -> 跳转到攻击者站点/恶意页面"
        analysis.cvss_score = analysis.cvss_score or 4.3
        analysis.cvss_justification = analysis.cvss_justification or "通常需要用户交互，影响以钓鱼/链路劫持为主"
        return analysis

    def _enhance_path_traversal_analysis(self, result: ScanResult, analysis: AIAnalysisResult) -> AIAnalysisResult:
        analysis.root_cause = analysis.root_cause or "文件路径参数可控且未做规范化/边界限制，导致目录遍历"
        analysis.impact_scope = analysis.impact_scope or "可能读取任意文件（配置、源码、凭证），在特定条件下可导致代码执行"
        analysis.attack_path = analysis.attack_path or "可控路径参数 -> 目录遍历序列(../) -> 读取敏感文件/包含文件"
        analysis.cvss_score = analysis.cvss_score or 7.1
        analysis.cvss_justification = analysis.cvss_justification or "通常可远程利用，信息泄露影响较大"
        return analysis
    
    def _enhance_sqli_analysis(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        增强SQL注入分析（任务8）
        
        Args:
            result: SQL注入扫描结果
            analysis: 基础分析结果
            
        Returns:
            增强后的分析结果
        """
        raw = result.raw_data
        injection_type = raw.get("injection_type", "")
        comp_hint = ""
        if isinstance(raw, dict) and raw.get("elapsed_ms") and "time" in str(injection_type).lower():
            comp_hint = f"（耗时证据: {raw.get('elapsed_ms')}ms）"
        
        # 分析利用难度和数据泄露风险
        exploitability = "高" if injection_type in ["boolean", "union", "error-based"] else "中"
        data_risk = "高" if injection_type == "union" else "中"
        
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "exploitability": exploitability,
            "data_leak_risk": data_risk,
            "evidence_summary": f"param={raw.get('param') or raw.get('injection_point')}; type={injection_type}{comp_hint}; matched={raw.get('matched_pattern')}",
            "test_url": raw.get("test_url") or raw.get("url") or result.target,
            "common_attack_vectors": [
                "通过注入获取数据库版本",
                "通过UNION查询获取表结构",
                "通过布尔盲注逐位提取数据"
            ],
            "impact_assessment": {
                "data_integrity": "受影响",
                "data_confidentiality": "严重",
                "system_availability": "可能受影响"
            }
        })
        
        return analysis
    
    def _enhance_xss_analysis(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        增强XSS分析（任务8）
        
        Args:
            result: XSS扫描结果
            analysis: 基础分析结果
            
        Returns:
            增强后的分析结果
        """
        raw = result.raw_data
        payload_type = raw.get("payload_type", "")
        
        # 分析影响范围和攻击复杂度
        complexity = "低" if payload_type == "reflected" else "中"
        impact_scope = {
            "reflected": "单个用户会话",
            "stored": "所有访问用户",
            "dom": "当前页面上下文"
        }.get(payload_type, "未知")
        
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "attack_complexity": complexity,
            "impact_scope": impact_scope,
            "evidence_summary": f"param={raw.get('param') or raw.get('injection_point')}; context={raw.get('context')}; payload_reflect={'Payload被原样反射' in str(raw.get('evidence',''))}",
            "test_url": raw.get("test_url") or raw.get("url") or result.target,
            "potential_impacts": [
                "会话劫持",
                "钓鱼攻击",
                "恶意脚本执行",
                "用户浏览器控制"
            ],
            "dom_details": raw.get("dom_structure", "")
        })
        
        return analysis
    
    def _enhance_csrf_analysis(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        增强CSRF分析（任务8）
        
        Args:
            result: CSRF扫描结果
            analysis: 基础分析结果
            
        Returns:
            增强后的分析结果
        """
        raw = result.raw_data
        exploitability = raw.get("exploitability", "待评估")
        
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "csrf_feasibility": exploitability,
            "business_impact": [
                "用户账户操作",
                "敏感信息修改",
                "非授权交易执行"
            ],
            "required_elements": raw.get("form_info", {})
        })
        
        return analysis
    
    def _enhance_command_injection_analysis(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        增强命令注入分析（任务8）
        
        Args:
            result: 命令注入扫描结果
            analysis: 基础分析结果
            
        Returns:
            增强后的分析结果
        """
        raw = result.raw_data
        command_type = raw.get("command_type", "")
        matched = raw.get("matched_pattern", "")
        elapsed_ms = raw.get("elapsed_ms")
        
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "system_impact": "critical" if command_type == "reverse_shell" else "high",
            "evidence_summary": f"param={raw.get('param')}; matched={matched}; elapsed_ms={elapsed_ms}",
            "test_url": raw.get("test_url") or raw.get("url") or result.target,
            "potential_capabilities": [
                "读取任意文件",
                "写入任意文件",
                "执行系统命令",
                "反弹Shell获取系统访问"
            ],
            "privilege_escalation_risk": "高"
        })
        
        return analysis
    
    def _enhance_lateral_movement_analysis(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        增强横向移动分析（文件包含/SSRF）（任务8）
        
        Args:
            result: 扫描结果
            analysis: 基础分析结果
            
        Returns:
            增强后的分析结果
        """
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "lateral_movement_risk": "高",
            "internal_network_access": [
                "访问内网服务",
                "扫描内网端口",
                "读取内网资源",
                "横向移动到其他系统"
            ],
            "data_exfiltration_risk": "中"
        })
        
        return analysis
    
    def _enhance_xxe_analysis(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        增强XXE分析（任务8）
        
        Args:
            result: XXE扫描结果
            analysis: 基础分析结果
            
        Returns:
            增强后的分析结果
        """
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "data_theft_risk": {
                "local_files": "高",
                "network_resources": "可能",
                "sensitive_config": "高"
            },
            "potential_impacts": [
                "读取本地文件",
                "SSRF攻击",
                "拒绝服务",
                "RCE(特定解析器)"
            ],
            "xml_parser_info": result.raw_data.get("xml_parser_info", "")
        })
        
        return analysis
    
    def _analyze_vulnerability_chain(
        self,
        result: ScanResult,
        analysis: AIAnalysisResult
    ) -> AIAnalysisResult:
        """
        漏洞链分析（任务8）
        
        Args:
            result: 当前漏洞
            analysis: 分析结果
            
        Returns:
            包含漏洞链信息的分析结果
        """
        analysis.additional_insights = analysis.additional_insights or {}
        analysis.additional_insights.update({
            "vulnerability_chain_analysis": {
                "description": "分析与其他漏洞的组合利用可能性",
                "potential_combinations": [
                    "XSS + CSRF = 自动化攻击",
                    "SQL注入 + 文件上传 = WebShell",
                    "SSRF + 内网服务 = 内网渗透",
                    "命令注入 + 权限提升 = 完整系统控制"
                ],
                "related_vulnerabilities": {
                    "sql_injection": ["file_inclusion", "command_injection"],
                    "xss": ["csrf", "sensitive_info"],
                    "ssrf": ["file_inclusion", "command_injection"]
                },
                "recommendation": "优先修复高CVSS评分漏洞，打断攻击链"
            }
        })
        
        return analysis
    
    async def _analyze_port(self, result: ScanResult) -> AIAnalysisResult:
        """
        分析端口扫描结果（任务7 - 端口扫描结果AI分析）
        
        Args:
            result: 端口扫描结果
            
        Returns:
            端口分析结果
        """
        raw = result.raw_data
        port = raw.get("port", 0)
        service = raw.get("service", "")
        version = raw.get("version", "")
        
        # 开放端口安全风险识别
        risk_level = self._assess_port_risk(port, service)
        
        # 服务版本已知漏洞分析
        known_vulnerabilities = self._check_service_vulnerabilities(service, version)
        
        # 端口服务配置安全性评估
        config_issues = self._assess_port_config(port, service)
        
        # 非必要开放端口识别
        is_necessary = self._is_port_necessary(port, service)
        
        # 服务加固建议
        hardening_suggestions = self._generate_hardening_suggestions(port, service, version)
        
        analysis = AIAnalysisResult(
            root_cause=f"端口 {port}/{service} 处于开放状态",
            impact_scope=self._generate_port_impact(port, service, risk_level),
            attack_path=f"开放端口 {port} -> {service}服务 -> 潜在安全风险",
            cvss_score=self._calculate_port_cvss(risk_level, len(known_vulnerabilities)),
            cvss_justification=f"风险等级: {risk_level}, 已知漏洞数量: {len(known_vulnerabilities)}",
            additional_insights={
                "risk_level": risk_level,
                "known_vulnerabilities": known_vulnerabilities,
                "config_issues": config_issues,
                "is_necessary": is_necessary,
                "hardening_suggestions": hardening_suggestions,
                "service_details": {
                    "port": port,
                    "service": service,
                    "version": version,
                    "banner": raw.get("banner", "")
                }
            }
        )
        
        return analysis
    
    def _assess_port_risk(self, port: int, service: str) -> str:
        """评估端口安全风险"""
        high_risk_ports = [21, 22, 23, 25, 135, 139, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 27017]
        
        if port in high_risk_ports:
            return "high"
        elif service in ["ftp", "telnet", "rsh", "rlogin"]:
            return "high"
        elif 1 <= port <= 1024:
            return "medium"
        else:
            return "low"
    
    def _check_service_vulnerabilities(self, service: str, version: str) -> List[str]:
        """检查服务版本已知漏洞（简化示例）"""
        vulnerabilities = []
        
        # 这里应该查询CVE数据库，此处为示例
        if service == "ssh" and version:
            if "7.2p2" in version and "7.4" not in version:
                vulnerabilities.append("CVE-2016-0777: SSH客户端信息泄露")
        elif service == "nginx" and version:
            if version.startswith("1.18."):
                vulnerabilities.append("CVE-2021-23017: 内存损坏漏洞")
        
        return vulnerabilities
    
    def _assess_port_config(self, port: int, service: str) -> List[str]:
        """评估端口服务配置安全性"""
        issues = []
        
        if port == 22:
            issues.append("建议使用密钥认证，禁用密码认证")
            issues.append("建议限制允许访问的IP范围")
        elif port == 3306:
            issues.append("MySQL不应暴露到公网")
        elif port == 3389:
            issues.append("RDP是常见攻击目标，建议使用VPN访问")
        
        return issues
    
    def _is_port_necessary(self, port: int, service: str) -> bool:
        """判断端口是否必要开放"""
        common_ports = {80, 443, 22, 8080}
        return port in common_ports
    
    def _generate_hardening_suggestions(
        self,
        port: int,
        service: str,
        version: str
    ) -> List[str]:
        """生成服务加固建议"""
        suggestions = []
        
        if service == "ssh":
            suggestions.append("升级到最新版本")
            suggestions.append("配置使用密钥认证")
            suggestions.append("限制root登录")
            suggestions.append("设置连接超时")
        elif service == "nginx":
            suggestions.append("启用安全headers")
            suggestions.append("配置SSL/TLS")
            suggestions.append("隐藏版本号")
        
        if len(suggestions) == 0:
            suggestions.append("更新服务到最新稳定版本")
            suggestions.append("配置防火墙规则")
            suggestions.append("启用访问日志和审计")
        
        return suggestions
    
    def _generate_port_impact(
        self,
        port: int,
        service: str,
        risk_level: str
    ) -> str:
        """生成端口影响范围描述"""
        impacts = {
            "high": "可能导致远程代码执行、数据泄露或服务拒绝",
            "medium": "可能被进行信息泄露或未授权访问",
            "low": "信息泄露风险有限，但建议审查"
        }
        return impacts.get(risk_level, "影响范围待评估")
    
    def _calculate_port_cvss(self, risk_level: str, vuln_count: int) -> float:
        """计算端口扫描结果的CVSS评分"""
        base_scores = {"high": 7.5, "medium": 5.0, "low": 3.0}
        base = base_scores.get(risk_level, 3.0)
        
        # 根据已知漏洞数量加分
        vuln_bonus = min(vuln_count * 1.5, 2.0)
        
        return min(base + vuln_bonus, 10.0)
    
    async def _analyze_generic(self, result: ScanResult) -> AIAnalysisResult:
        """
        通用分析（非漏洞/端口扫描结果）
        
        Args:
            result: 扫描结果
            
        Returns:
            通用分析结果
        """
        return AIAnalysisResult(
            root_cause=f"{result.title} 检测到",
            impact_scope="需要进一步评估",
            attack_path="待分析",
            cvss_score=0.0,
            cvss_justification="非漏洞类型，不适用CVSS评分"
        )
    
    def _generate_default_analysis(
        self,
        result: ScanResult,
        error: str = ""
    ) -> AIAnalysisResult:
        """生成默认分析结果（当AI服务不可用时）"""
        return AIAnalysisResult(
            root_cause=f"{result.title}: 需要进一步手动分析",
            impact_scope="因AI服务未启用而无法自动评估",
            attack_path="待分析",
            cvss_score=result.severity.value == "critical" and 9.0 or result.severity.value == "high" and 7.0 or result.severity.value == "medium" and 5.0 or 3.0,
            cvss_justification=f"基于严重程度: {result.severity.value} (AI分析不可用)",
            additional_insights={
                "ai_analysis_unavailable": True,
                "error": error if error else "AI服务未配置"
            }
        )
