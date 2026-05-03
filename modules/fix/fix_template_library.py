"""
修复建议模板库
提供各类漏洞的修复建议模板（任务11-15）
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class FixTemplate:
    """
    修复建议模板数据类（任务11-14）
    """
    template_id: str
    vulnerability_type: str
    name: str
    description: str
    fix_type: str  # code, config, architecture
    fix_steps: List[str]
    code_examples: Optional[Dict[str, str]] = None
    configuration_examples: Optional[Dict[str, str]] = None
    verification_method: str = ""
    priority: str = "medium"  # critical, high, medium, low
    references: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "template_id": self.template_id,
            "vulnerability_type": self.vulnerability_type,
            "name": self.name,
            "description": self.description,
            "fix_type": self.fix_type,
            "fix_steps": self.fix_steps,
            "code_examples": self.code_examples or {},
            "configuration_examples": self.configuration_examples or {},
            "verification_method": self.verification_method,
            "priority": self.priority,
            "references": self.references or []
        }


class FixTemplateLibrary:
    """
    修复建议模板库（任务15）
    管理所有漏洞类型的修复建议模板
    """
    
    def __init__(self):
        """初始化模板库"""
        self._templates: Dict[str, FixTemplate] = {}
        self._load_builtin_templates()
    
    def _load_builtin_templates(self) -> None:
        """加载内置修复建议模板（任务11-14）"""
        
        # SQL注入修复建议模板（任务11）
        sqli_template = FixTemplate(
            template_id="fix_sqli_001",
            vulnerability_type="sql_injection",
            name="SQL注入参数化查询修复",
            description="使用参数化查询(prepared statement)或ORM框架防止SQL注入攻击",
            fix_type="code",
            fix_steps=[
                "识别所有使用字符串拼接构造SQL语句的位置",
                "将拼接SQL替换为参数化查询(参数化语句)",
                "对于动态SQL，使用白名单过滤或严格的输入验证",
                "使用ORM框架(如SQLAlchemy, Django ORM)替代原生SQL",
                "为数据库用户设置最小权限",
                "定期审查和审计SQL查询代码"
            ],
            code_examples={
                "vulnerable": "query = \"SELECT * FROM users WHERE id = '\" + user_input + \"'\"",
                "fixed_python": "# 使用参数化查询\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))\n\n# 或使用ORM\nUser.objects.filter(id=user_input)",
                "fixed_java": "// 使用PreparedStatement\nString query = \"SELECT * FROM users WHERE id = ?\";\nPreparedStatement stmt = connection.prepareStatement(query);\nstmt.setString(1, user_input);",
                "fixed_php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $user_input]);"
            },
            verification_method="使用相同Payload重新测试，应无法注入或返回通用错误信息",
            priority="high",
            references=[
                "OWASP SQL Injection Prevention Cheat Sheet",
                "CWE-89: SQL Injection"
            ]
        )
        self._templates[sqli_template.template_id] = sqli_template
        
        # XSS修复建议模板（任务12）
        xss_template = FixTemplate(
            template_id="fix_xss_001",
            vulnerability_type="xss",
            name="XSS输入输出编码修复",
            description="对用户输入进行HTML转义并配置内容安全策略(CSP)",
            fix_type="code",
            fix_steps=[
                "对所有用户输入进行HTML实体编码(输出编码)",
                "对于非HTML内容，使用textContent替代innerHTML",
                "配置HTTP Content-Security-Policy头部",
                "为Cookie设置HttpOnly和Secure属性",
                "实现输入白名单验证",
                "使用现代框架自动编码(React, Vue.js)"
            ],
            code_examples={
                "vulnerable": "response.write('<div>' + user_input + '</div>')",
                "fixed_python": "from html import escape; response.write('<div>' + escape(user_input) + '</div>')",
                "fixed_js": "使用escapeHtml函数进行HTML实体编码",
                "fixed_csp": "Content-Security-Policy: default-src 'self'; script-src 'self'"
            },
            configuration_examples={
                "CSP配置": "Content-Security-Policy: default-src 'self'; script-src 'self'",
                "Cookie安全": "Set-Cookie: sessionid=xxx; HttpOnly; Secure; SameSite=Strict"
            },
            verification_method="检查响应头中是否存在CSP，尝试XSS Payload应失效或被编码",
            priority="medium",
            references=[
                "OWASP XSS Prevention Cheat Sheet",
                "CWE-79: Cross-site Scripting"
            ]
        )
        self._templates[xss_template.template_id] = xss_template
        
        # CSRF修复建议模板（任务13）
        csrf_template = FixTemplate(
            template_id="fix_csrf_001",
            vulnerability_type="csrf",
            name="CSRF Token防护修复",
            description="实现CSRF Token机制和SameSite Cookie配置",
            fix_type="code",
            fix_steps=[
                "为所有状态改变操作生成唯一的CSRF Token",
                "在用户会话中存储Token及过期时间",
                "在表单中包含Token(隐藏字段或自定义头)",
                "服务端验证请求中的Token与会话中的一致",
                "配置Cookie的SameSite属性为Strict或Lax",
                "重要操作要求二次确认(重要交易)"
            ],
            code_examples={
                "vulnerable": "<form method=\"POST\" action=\"/transfer\">\n  <input name=\"account\" value=\"...\">\n  <button>转账</button>\n</form>",
                "fixed_template": "<form method=\"POST\" action=\"/transfer\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  <input name=\"account\" value=\"...\">\n  <button>转账</button>\n</form>",
                "fixed_flask": "from flask_wtf.csrf import CSRFProtect\n\ncsrf = CSRFProtect(app)\n\n# 使用时在模板中: {{ csrf_token() }}",
                "fixed_cookie": "Set-Cookie: sessionid=xxx; SameSite=Strict; Secure; HttpOnly"
            },
            verification_method="伪造跨站请求，应被拒绝并返回403 Forbidden",
            priority="high",
            references=[
                "OWASP CSRF Prevention Cheat Sheet",
                "CWE-352: Cross-Site Request Forgery"
            ]
        )
        self._templates[csrf_template.template_id] = csrf_template
        
        # 通用安全加固建议模板（任务14 - 端口扫描相关）
        port_hardening_template = FixTemplate(
            template_id="fix_port_001",
            vulnerability_type="port_security",
            name="端口安全加固建议",
            description="限制开放端口，加强访问控制，升级服务版本",
            fix_type="config",
            fix_steps=[
                "关闭不必要的开放端口",
                "配置防火墙规则，限制访问来源IP",
                "升级服务到最新稳定版本，修复已知漏洞",
                "禁用不安全的协议(如Telnet, FTP)",
                "启用访问日志和审计",
                "定期进行安全扫描和漏洞评估"
            ],
            configuration_examples={
                "SSH加固": "# /etc/ssh/sshd_config\nPermitRootLogin no\nPasswordAuthentication no\nAllowUsers user@指定IP",
                "防火墙规则": "# iptables\niptables -A INPUT -p tcp --dport 22 -s 允许的IP -j ACCEPT\niptables -A INPUT -p tcp --dport 22 -j DROP",
                "Web服务器加固": "# Nginx\nserver_tokens off;\nadd_header X-Frame-Options DENY;\nadd_header X-Content-Type-Options nosniff;"
            },
            verification_method="重新进行端口扫描，确认只开放必要端口",
            priority="medium",
            references=[
                "CIS Benchmarks",
                "NIST Security Configuration"
            ]
        )
        self._templates[port_hardening_template.template_id] = port_hardening_template
        
        # 其他漏洞类型的模板（简要示例）
        
        # 命令注入修复
        cmd_injection_template = FixTemplate(
            template_id="fix_cmd_001",
            vulnerability_type="command_injection",
            name="命令注入防御",
            description="避免直接执行用户输入，使用安全的系统调用",
            fix_type="code",
            fix_steps=[
                "避免使用系统命令执行函数(如os.system, eval)",
                "使用语言内置的安全API替代shell命令",
                "如必须执行命令，使用白名单过滤输入参数",
                "使用参数化执行而非字符串拼接",
                "执行前转义危险字符",
                "限制执行命令的权限"
            ],
            verification_method="尝试注入命令，应失效并记录告警",
            priority="critical"
        )
        self._templates[cmd_injection_template.template_id] = cmd_injection_template
        
        # 文件包含修复
        file_inclusion_template = FixTemplate(
            template_id="fix_file_001",
            vulnerability_type="file_inclusion",
            name="文件包含漏洞修复",
            description="严格验证文件路径，使用白名单过滤",
            fix_type="code",
            fix_steps=[
                "禁止用户直接控制文件路径",
                "使用白名单限制可访问的文件",
                "过滤路径遍历字符(.. / \\)",
                "对文件名进行验证和规范化",
                "设置文件系统权限限制",
                "使用chroot或容器隔离"
            ],
            verification_method="尝试包含系统敏感文件，应被拒绝",
            priority="high"
        )
        self._templates[cmd_injection_template.template_id] = cmd_injection_template
        
        # SSRF修复
        ssrf_template = FixTemplate(
            template_id="fix_ssrf_001",
            vulnerability_type="ssrf",
            name="SSRF漏洞修复",
            description="限制可访问URL范围，使用DNS重绑定防御",
            fix_type="code",
            fix_steps=[
                "构建URL的白名单，只访问受信域名",
                "过滤内网IP地址段(127.0.0.0/8, 10.0.0.0/8等)",
                "使用DNS解析验证目标，不使用用户提供的IP",
                "禁止重定向或限制重定向次数",
                "网络隔离，应用服务器不直接访问内网",
                "使用安全的HTTP客户端库"
            ],
            verification_method="尝试访问内网地址，应被拒绝",
            priority="high"
        )
        self._templates[ssrf_template.template_id] = ssrf_template
        
        # XXE修复
        xxe_template = FixTemplate(
            template_id="fix_xxe_001",
            vulnerability_type="xxe",
            name="XXE漏洞修复",
            description="禁用XML外部实体解析，使用安全的XML解析器",
            fix_type="code",
            fix_steps=[
                "禁用XML解析器的外部实体解析(DTD)",
                "使用安全的XML解析器配置",
                "禁用XInclude功能",
                "验证XML内容格式和结构",
                "使用JSON替代XML格式",
                "升级XML解析器到最新版本"
            ],
            code_examples={
                "python_lxml": "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, load_dtd=False)",
                "java": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"
            },
            verification_method="尝试XXE Payload，应报错或无攻击效果",
            priority="high"
        )
        self._templates[xxe_template.template_id] = xxe_template
    
    def get_template(self, vulnerability_type: str) -> Optional[FixTemplate]:
        """
        根据漏洞类型获取模板（任务15）
        
        Args:
            vulnerability_type: 漏洞类型
            
        Returns:
            修复建议模板
        """
        # 精确匹配
        for template in self._templates.values():
            if template.vulnerability_type == vulnerability_type:
                return template
        
        # 模糊匹配（如port_security匹配端口相关）
        if "port" in vulnerability_type:
            return self._templates.get("fix_port_001")
        
        return None
    
    def apply_template(
        self,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        应用模板生成具体修复建议（任务10）
        
        Args:
            vulnerability_type: 漏洞类型
            context: 上下文信息（如漏洞具体内容、AI分析结果等）
            
        Returns:
            具体修复建议
        """
        template = self.get_template(vulnerability_type)
        
        if not template:
            # 返回通用修复建议
            return {
                "type": "general_hardening",
                "title": "通用安全加固建议",
                "description": "建议进行安全审计并应用安全最佳实践",
                "fix_steps": [
                    "进行代码审查",
                    "执行深度安全测试",
                    "应用OWASP安全指南"
                ],
                "priority": "medium",
                "references": [
                    "OWASP Top 10",
                    "CWE/SANS Top 25"
                ]
            }
        
        # 应用模板，填充上下文
        suggestion = template.to_dict()
        
        # 根据上下文调整建议内容
        if "target" in context:
            suggestion["affected_target"] = context["target"]
        
        if "evidence" in context:
            suggestion["vulnerability_evidence"] = context["evidence"]
        
        # 优先级排序（基于AI分析的CVSS评分）
        if "CVSS评分" in str(context):
            try:
                cvss = context.get("cvss_score", 5.0)
                if cvss >= 9.0:
                    suggestion["priority"] = "critical"
                elif cvss >= 7.0:
                    suggestion["priority"] = "high"
                elif cvss >= 4.0:
                    suggestion["priority"] = "medium"
                else:
                    suggestion["priority"] = "low"
            except:
                pass
        
        # 添加AI分析上下文
        if "root_cause" in context:
            suggestion["root_cause_analysis"] = context["root_cause"]
        
        return suggestion
    
    def load_templates(self, filepath: str) -> None:
        """
        从文件加载模板（任务15）
        
        Args:
            filepath: 模板文件路径
        """
        import json
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                templates_data = json.load(f)
            
            for template_data in templates_data:
                template = FixTemplate(**template_data)
                self._templates[template.template_id] = template
        
        except FileNotFoundError:
            pass
        except Exception as e:
            raise Exception(f"加载模板失败: {e}")
    
    def save_templates(self, filepath: str) -> None:
        """
        保存模板到文件（任务15）
        
        Args:
            filepath: 模板文件路径
        """
        import json
        
        templates_data = [template.to_dict() for template in self._templates.values()]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(templates_data, f, indent=2, ensure_ascii=False)
    
    def list_templates(self) -> List[Dict[str, str]]:
        """
        列出所有可用模板
        
        Returns:
            模板信息列表
        """
        return [
            {
                "template_id": template.template_id,
                "vulnerability_type": template.vulnerability_type,
                "name": template.name,
                "priority": template.priority
            }
            for template in self._templates.values()
        ]
