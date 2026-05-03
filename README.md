# PySecScanner - 智能安全扫描工具

一个集成 AI 分析能力的现代化安全扫描框架，支持 GUI 可视化操作和命令行模式，适用于安全测试、漏洞评估和学习研究。

## ⚠️ 免责声明

**本工具仅供安全研究和授权测试使用。未经授权对他人系统进行扫描是违法行为。使用者需自行承担所有法律责任。**

## ✨ 功能特性

### 🔍 信息搜集模块

|模块|功能|
|-|-|
|端口扫描|TCP 连接扫描、服务识别、操作系统探测|
|子域名枚举|字典爆破、DNS 解析|
|目录扫描|敏感文件发现、状态码分析|
|Web 爬虫|自动爬取页面、发现参数、提取表单|
|指纹识别|识别 CMS、框架、服务器、WAF 等技术栈|
|批量扫描|多目标批量扫描、支持文件导入|

### 🛡️ 漏洞扫描模块

|模块|功能|
|-|-|
|SQL 注入|错误注入、时间盲注、布尔盲注检测|
|XSS|反射型 XSS 检测|
|SSRF|服务端请求伪造检测|
|CSRF|跨站请求伪造检测|
|XXE|XML 外部实体注入检测|
|文件包含|LFI/RFI 检测|
|命令注入|OS 命令注入检测|
|敏感信息|API 密钥、密码、配置文件泄露检测|
|POC 验证|已知漏洞 POC 验证|

### 🤖 AI 智能分析

* **DeepSeek API 集成**: 自动分析扫描结果中的漏洞风险
* **智能对话**: 与 AI 助手交流安全问题、获取修复建议
* **修复方案生成**: AI 自动生成漏洞修复代码示例

### 🖥️ 现代化 GUI

* **侧边导航栏**: 新建扫描、扫描结果、AI 分析、系统设置
* **主题引擎**: 支持明暗主题切换，基于 ttkbootstrap
* **交互动画**: 按钮缩放、脉冲效果、Toast 通知、淡入动画
* **实时同步**: 扫描完成后自动刷新结果页面和 AI 目标列表

### 💾 数据持久化

* **SQLite 数据库**: 保存扫描历史、漏洞发现、统计信息
* **自动同步**: 扫描结果自动同步到结果页面和 AI 分析页面

## 📦 安装

### 环境要求

* Python 3.11+
* Windows / Linux / macOS

### 直接安装

```bash
# 克隆或解压项目
cd pysec-scanner

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\\Scripts\\activate
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 配置 AI 功能（可选）

```bash
# 复制环境变量模板
copy .env.example .env

# 编辑 .env 文件，填入 DeepSeek API 密钥
DEEPSEEK\_API\_KEY=your-api-key-here
```

> 未配置 API 密钥时，AI 功能将使用本地分析模式，仍可正常使用。

## 🚀 使用方法

### GUI 模式（推荐）

```bash
# Windows
cd pysec-scanner
start.bat

# 或手动启动
python gui/modern\_gui.py
```

GUI 界面包含四大功能模块：

* **🔍 新建扫描**: 输入目标域名/IP，选择扫描模块，开始扫描
* **📊 扫描结果**: 查看历史扫描记录、漏洞列表、风险统计
* **🤖 AI 分析**: 选择扫描目标，AI 自动分析漏洞并提供修复建议
* **⚙️ 系统设置**: 切换明暗主题

### 命令行模式

```bash
# 查看帮助
python main.py --help

# 完整扫描
python main.py scan http://example.com

# 指定模块扫描
python main.py scan http://example.com -m sqli -m xss -m poc

# 批量扫描
python main.py batch targets.txt

# 端口扫描
python main.py portscan 192.168.1.1 -p common

# 子域名枚举
python main.py subdomain example.com

# 目录扫描
python main.py dirscan http://example.com

# Web 爬虫
python main.py crawl http://example.com --depth 3

# 指纹识别
python main.py fingerprint http://example.com

# POC 验证
python main.py poc http://example.com

# 单独漏洞扫描
python main.py sqli "http://example.com/page?id=1"
python main.py xss "http://example.com/search?q=test"
python main.py ssrf "http://example.com/fetch?url="
python main.py sensitive http://example.com

# 查看可用模块
python main.py list-modules

# 查看扫描历史
python main.py history

# 查看统计
python main.py stats
```

### Web 界面模式

```bash
# 启动 Web 服务
python main.py web

# 指定端口
python main.py web -p 9000
```

访问 http://localhost:8000 即可使用 Web 界面。

## 📁 项目结构

```
pysec-scanner/
├── main.py                   # 命令行入口
├── run.py                    # 程序入口
├── config.yaml              # 配置文件
├── requirements.txt         # 依赖列表
│
├── core/                    # 核心框架
│   ├── config.py           # 配置管理
│   ├── logger.py           # 日志系统
│   ├── base.py             # 模块基类
│   ├── scanner.py          # 扫描器核心
│   ├── database.py         # SQLite 数据库管理
│   └── http\_evidence.py    # HTTP 证据收集
│
├── gui/                     # 图形界面
│   ├── modern\_gui.py       # 现代化主界面
│   ├── theme\_engine.py     # 主题引擎
│   └── app.py              # GUI 入口
│
├── modules/                 # 扫描模块
│   ├── recon/              # 信息搜集
│   │   ├── port\_scanner.py
│   │   ├── advanced\_port\_scanner.py
│   │   ├── subdomain\_enum.py
│   │   ├── dir\_scanner.py
│   │   ├── web\_crawler.py
│   │   ├── fingerprint.py
│   │   └── batch\_scanner.py
│   │
│   ├── vulnscan/           # 漏洞扫描
│   │   ├── sql\_injection.py
│   │   ├── xss\_scanner.py
│   │   ├── ssrf\_scanner.py
│   │   ├── csrf\_scanner.py
│   │   ├── xxe\_scanner.py
│   │   ├── file\_inclusion.py
│   │   ├── command\_injection.py
│   │   ├── sensitive\_info.py
│   │   └── poc\_scanner.py
│   │
│   ├── ai/                 # AI 分析
│   │   ├── deepseek\_client.py
│   │   ├── analyzer.py
│   │   └── batch\_analyzer.py
│   │
│   ├── fix/                # 修复方案
│   │   ├── fix\_generator.py
│   │   └── fix\_template\_library.py
│   │
│   └── formatter/          # 格式化输出
│       └── json\_formatter.py
│
├── web/                     # Web 界面
│   └── app.py              # FastAPI 应用
│
├── utils/                   # 工具函数
│   ├── helpers.py
│   ├── proxy.py
│   └── rich\_formatter.py
│
├── tests/                   # 单元测试
│   ├── test\_core.py
│   └── test\_utils.py
│
└── data/                    # 数据文件
    ├── wordlists/          # 字典文件
    │   ├── subdomains.txt
    │   └── directories.txt
    ├── payloads/           # Payload 文件
    │   ├── sqli.txt
    │   └── xss.txt
    └── scanner.db          # SQLite 数据库
```

## ⚙️ 配置说明

编辑 `config.yaml` 自定义扫描行为：

```yaml
# 扫描配置
scan:
  timeout: 10          # 请求超时（秒）
  concurrency: 50      # 并发数
  proxy: null          # 代理地址

# 端口扫描
port\_scan:
  ports: "common"      # common, top100, top1000
  service\_detection: true

# 漏洞扫描
vuln\_scan:
  sql\_injection: true
  xss: true
  ssrf: true
  # ...

# 代理配置
proxy:
  enabled: false
  url: "http://127.0.0.1:8080"
  rotate: true
```

## 🔧 扩展开发

### 添加新扫描模块

```python
from core.base import BaseModule, ScanResult, Severity, ResultType

class MyScanner(BaseModule):
    name = "my\_scanner"
    description = "我的扫描模块"
    version = "1.0.0"
    
    async def scan(self, target: str) -> list:
        results = \[]
        # 实现扫描逻辑...
        results.append(ScanResult(
            result\_type=ResultType.VULNERABILITY,
            title="发现漏洞",
            description="漏洞描述",
            severity=Severity.HIGH,
            target=target
        ))
        return results
```

## 🛡️ 技术栈

* **Python 3.11+**
* **tkinter + ttkbootstrap** - 现代化 GUI
* **asyncio + aiohttp** - 异步并发扫描
* **Click + Rich** - 命令行界面
* **FastAPI + uvicorn** - Web 服务
* **SQLite** - 数据持久化
* **DeepSeek API** - AI 智能分析

## 🧪 运行测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行单个测试文件
pytest tests/test\_core.py -v
```

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

