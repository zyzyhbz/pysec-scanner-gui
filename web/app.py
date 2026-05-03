"""
FastAPI Web界面
提供REST API和Web界面
"""

import sys
import os

# 添加项目路径，确保能找到核心模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import hashlib
import secrets
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.config import Config
from core.scanner import Scanner, ScanReport
from core.database import Database, db
from core.logger import logger


# ==================== 认证工具 ====================

def hash_password(password: str) -> str:
    """密码哈希（使用SHA256 + salt）"""
    salt = secrets.token_hex(16)
    pwdhash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${pwdhash}"

def verify_password(password: str, hashed: str) -> bool:
    """验证密码"""
    try:
        salt, stored_hash = hashed.split('$')
        pwdhash = hashlib.sha256((password + salt).encode()).hexdigest()
        return pwdhash == stored_hash
    except ValueError:
        return False

# 内存token存储（生产环境应使用Redis）
active_tokens: Dict[str, Dict[str, Any]] = {}

def generate_token(user_id: int, username: str) -> str:
    """生成认证token"""
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        'user_id': user_id,
        'username': username,
        'created_at': datetime.now().isoformat()
    }
    return token

def verify_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """验证token"""
    if not token:
        return None
    return active_tokens.get(token)

async def get_current_user(x_token: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """获取当前用户（依赖注入）"""
    return verify_token(x_token)

async def require_auth(user: Optional[Dict[str, Any]] = Depends(get_current_user)) -> Dict[str, Any]:
    """要求认证的依赖"""
    if not user:
        raise HTTPException(status_code=401, detail="未登录或token已过期")
    return user

# Pydantic模型
class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    scan_id: int
    target: str
    status: str
    message: str


# 认证模型
class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    username: str
    message: str


# 创建FastAPI应用
app = FastAPI(
    title="PySecScanner",
    description="信息搜集与漏洞扫描工具 Web API",
    version="2.0.0"
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局变量
active_scans: Dict[int, bool] = {}


# ==================== API路由 ====================

@app.get("/")
async def root():
    """返回Web界面"""
    return HTMLResponse(content=get_index_html())


@app.get("/chat")
async def chat_page():
    """返回AI对话专用页面"""
    return HTMLResponse(content=get_chat_html())


@app.get("/login")
async def login_page():
    """返回登录页面"""
    return HTMLResponse(content=get_login_html())


# ==================== 认证API ====================

@app.post("/api/auth/register", response_model=AuthResponse)
async def register(request: RegisterRequest):
    """用户注册"""
    if len(request.username) < 3 or len(request.username) > 20:
        raise HTTPException(status_code=400, detail="用户名长度需在3-20个字符之间")
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="密码长度至少6个字符")
    
    # 检查用户名是否已存在
    if db.user_exists(request.username):
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 创建用户
    password_hash = hash_password(request.password)
    if not db.create_user(request.username, password_hash):
        raise HTTPException(status_code=500, detail="创建用户失败")
    
    # 获取用户信息并生成token
    user = db.get_user(request.username)
    token = generate_token(user['id'], user['username'])
    
    return AuthResponse(
        token=token,
        username=user['username'],
        message="注册成功"
    )


@app.post("/api/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    """用户登录"""
    user = db.get_user(request.username)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    if not verify_password(request.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    token = generate_token(user['id'], user['username'])
    
    return AuthResponse(
        token=token,
        username=user['username'],
        message="登录成功"
    )


@app.post("/api/auth/logout")
async def logout(x_token: Optional[str] = Header(None)):
    """用户登出"""
    if x_token and x_token in active_tokens:
        del active_tokens[x_token]
    return {"message": "登出成功"}


@app.get("/api/auth/me")
async def get_me(user: Dict[str, Any] = Depends(require_auth)):
    """获取当前用户信息"""
    return {
        "user_id": user['user_id'],
        "username": user['username']
    }


# ==================== 统计API ====================

@app.get("/api/stats")
async def get_stats(x_token: Optional[str] = Header(None)):
    """获取统计信息（按用户隔离，必须登录）"""
    user = verify_token(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录")
    return db.get_stats(user_id=user['user_id'])


@app.get("/api/scans")
async def list_scans(limit: int = 50, offset: int = 0, x_token: Optional[str] = Header(None)):
    """获取扫描列表（按用户隔离，必须登录）"""
    user = verify_token(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录")
    scans = db.get_scans(limit, offset, user_id=user['user_id'])
    return {
        "scans": [
            {
                "id": s.id,
                "target": s.target,
                "start_time": s.start_time.isoformat(),
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "duration": s.duration,
                "status": s.status,
                "total_findings": s.total_findings,
                "severity_distribution": s.severity_distribution
            }
            for s in scans
        ]
    }


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks, x_token: Optional[str] = Header(None)):
    """创建新扫描（必须登录）"""
    user = verify_token(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录")
    
    # 创建数据库记录
    modules = request.modules or []
    scan_id = db.create_scan(request.target, modules, user_id=user['user_id'])
    
    # 标记为活动扫描
    active_scans[scan_id] = True
    
    # 后台执行扫描
    background_tasks.add_task(run_scan_task, scan_id, request.target, request.modules)
    
    return ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="started",
        message="扫描已启动"
    )


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int, x_token: Optional[str] = Header(None)):
    """获取扫描详情（必须登录）"""
    user = verify_token(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录")
    
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="扫描不存在")
    
    findings = db.get_findings(scan_id)
    
    return {
        "scan": {
            "id": scan.id,
            "target": scan.target,
            "start_time": scan.start_time.isoformat(),
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "duration": scan.duration,
            "status": scan.status,
            "modules": scan.modules,
            "total_findings": scan.total_findings,
            "severity_distribution": scan.severity_distribution
        },
        "findings": [
            {
                "id": f.id,
                "result_type": f.result_type,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "target": f.target,
                "evidence": f.evidence
            }
            for f in findings
        ]
    }


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int, x_token: Optional[str] = Header(None)):
    """删除扫描记录（必须登录）"""
    user = verify_token(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录")
    
    # 停止活动扫描
    if scan_id in active_scans:
        active_scans[scan_id] = False
    
    if db.delete_scan(scan_id):
        return {"message": "扫描已删除"}
    raise HTTPException(status_code=404, detail="扫描不存在")


@app.get("/api/findings/search")
async def search_findings(
    query: str = Query(..., min_length=1),
    severity: Optional[str] = None,
    limit: int = 100
):
    """搜索发现结果"""
    findings = db.search_findings(query, severity, limit)
    return {
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "result_type": f.result_type,
                "title": f.title,
                "severity": f.severity,
                "target": f.target
            }
            for f in findings
        ]
    }


@app.get("/api/modules")
async def list_modules():
    """获取可用模块列表"""
    scanner = Scanner()
    modules = []
    
    for name in scanner.get_available_modules():
        info = scanner.get_module_info(name)
        if info:
            modules.append({
                "name": name,
                "display_name": info['name'],
                "description": info['description'],
                "version": info['version']
            })
    
    return {"modules": modules}


# ==================== 后台任务 ====================

async def run_scan_task(scan_id: int, target: str, modules: List[str] = None):
    """后台扫描任务"""
    try:
        scanner = Scanner()
        
        # 执行扫描
        report = await scanner.scan(target, modules)
        
        # 检查是否被取消
        if not active_scans.get(scan_id, False):
            db.update_scan(scan_id, status="cancelled")
            return
        
        # 保存结果到数据库
        severity_dist = {}
        for result in report.results:
            # 添加发现
            db.add_finding(scan_id, result.to_dict())
            
            # 统计严重程度
            sev = result.severity.value
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
        
        # 更新扫描状态
        db.update_scan(
            scan_id,
            status="completed",
            total_findings=len(report.results),
            severity_distribution=severity_dist
        )
        
    except Exception as e:
        logger.error(f"扫描任务失败: {e}")
        db.update_scan(scan_id, status="failed")
    
    finally:
        # 清理活动扫描标记
        if scan_id in active_scans:
            del active_scans[scan_id]


# ==================== AI对话API ====================

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = None
    scan_id: Optional[int] = None  # 可选的扫描ID，用于获取扫描上下文


class ChatResponse(BaseModel):
    response: str
    status: str


# 全局AI客户端实例
_ai_client = None

def get_ai_client():
    """获取或初始化AI客户端"""
    global _ai_client
    if _ai_client is None:
        try:
            from modules.ai.deepseek_client import DeepSeekClient
            _ai_client = DeepSeekClient()
        except Exception as e:
            logger.error(f"AI客户端初始化失败: {e}")
            return None
    return _ai_client


@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """AI对话接口 - 支持扫描上下文"""
    client = get_ai_client()
    if not client:
        raise HTTPException(status_code=503, detail="AI服务未配置或初始化失败")
    
    try:
        # 构建系统提示，包含扫描上下文
        system_prompt = "你是一位专业的安全分析AI助手。"
        
        # 如果提供了scan_id，获取扫描详情作为上下文
        scan_context = ""
        if request.scan_id:
            scan = db.get_scan(request.scan_id)
            if scan:
                findings = db.get_findings(request.scan_id)
                scan_context = f"""
当前扫描上下文：
- 目标: {scan.target}
- 状态: {scan.status}
- 发现数量: {scan.total_findings}
- 严重程度分布: {scan.severity_distribution}

扫描结果详情：
"""
                for f in findings[:10]:  # 最多10个发现
                    scan_context += f"- [{f.severity}] {f.title}: {f.description}\n"
                
                if len(findings) > 10:
                    scan_context += f"... 还有 {len(findings) - 10} 个发现\n"
                
                system_prompt += f"\n\n{scan_context}\n\n请基于以上扫描结果回答用户问题。"
        else:
            # 如果没有指定scan_id，获取最近一次完成的扫描
            recent_scans = db.get_scans(limit=1)
            if recent_scans and recent_scans[0].status == "completed":
                scan = recent_scans[0]
                findings = db.get_findings(scan.id)
                scan_context = f"""
最近一次扫描上下文（ID: {scan.id}）：
- 目标: {scan.target}
- 发现数量: {scan.total_findings}
- 严重程度分布: {scan.severity_distribution}

扫描结果详情：
"""
                for f in findings[:10]:
                    scan_context += f"- [{f.severity}] {f.title}: {f.description}\n"
                
                if len(findings) > 10:
                    scan_context += f"... 还有 {len(findings) - 10} 个发现\n"
                
                system_prompt += f"\n\n{scan_context}\n\n请基于以上扫描结果回答用户问题。"
        
        # 构建消息列表
        messages = [
            {"role": "system", "content": system_prompt}
        ]
        
        if request.history:
            for msg in request.history[-6:]:
                messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
        
        # 添加当前用户消息
        messages.append({"role": "user", "content": request.message})
        
        # 调用AI获取回复
        response = await client._make_api_call(messages)
        content = response.choices[0].message.content
        
        return ChatResponse(
            response=content,
            status="success"
        )
    except Exception as e:
        logger.error(f"AI对话失败: {e}")
        raise HTTPException(status_code=500, detail=f"AI对话失败: {str(e)}")


# ==================== Web界面HTML ====================

def get_index_html() -> str:
    """返回前端HTML页面"""
    return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner - 安全扫描平台</title>
    <style>
        /* ===== CSS 变量体系 ===== */
        :root {
            --bg-dark: #0d1117;
            --bg-darker: #0a0e14;
            --card-bg: rgba(22, 27, 34, 0.8);
            --border-color: rgba(0, 255, 170, 0.2);
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent: #00ffaa;
            --accent-hover: #00dd88;
            --accent-cyan: #00ffff;
            --accent-green: #00ff88;
            --danger: #FF4D4D;
            --success: #00D166;
            --warning: #FFA500;
        }

        /* ===== 全局基础 ===== */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Segoe UI", system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        /* ===== 头部 ===== */
        /* ===== 头部 ===== */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 30px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }
        .header-left { text-align: left; }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(90deg, var(--accent), var(--accent-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .header p { color: var(--text-secondary); }
        .header-right { display: flex; align-items: center; gap: 12px; }
        .btn-login {
            padding: 8px 20px;
            border-radius: 20px;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            color: #000000;
            text-decoration: none;
            font-size: 14px;
            font-weight: 600;
            transition: opacity 0.2s;
        }
        .btn-login:hover { opacity: 0.9; }
        .user-info {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
        }
        .user-name {
            color: var(--text-primary);
            font-weight: 500;
        }
        .btn-logout {
            padding: 6px 14px;
            border: 1px solid var(--border-color);
            border-radius: 16px;
            background: transparent;
            color: var(--text-secondary);
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-logout:hover {
            border-color: var(--danger);
            color: var(--danger);
        }
        /* ===== 统计卡片 Grid 响应式布局 ===== */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        /* ===== 毛玻璃卡片 (Glassmorphism) ===== */
        .stat-card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            border-color: var(--accent);
            box-shadow: 0 8px 32px rgba(0, 255, 170, 0.1);
            transform: translateY(-2px);
        }
        .stat-card h3 { color: var(--text-secondary); font-size: 0.9em; margin-bottom: 10px; }
        .stat-card .value {
            font-size: 48px;
            font-weight: 700;
            color: var(--accent);
            text-shadow: 0 0 20px rgba(0, 255, 170, 0.3);
        }

        /* ===== 主内容 Grid 响应式布局 ===== */
        .main-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        @media (min-width: 1200px) {
            .main-content { grid-template-columns: repeat(3, 1fr); }
            .stats-grid { grid-template-columns: repeat(3, 1fr); }
        }
        @media (min-width: 900px) and (max-width: 1199px) {
            .main-content { grid-template-columns: repeat(2, 1fr); }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 899px) {
            .main-content { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr; }
        }

        /* ===== 通用卡片 (Glassmorphism) ===== */
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        .card:hover {
            border-color: var(--accent);
            box-shadow: 0 8px 32px rgba(0, 255, 170, 0.1);
        }
        .card h2 { color: var(--accent-cyan); margin-bottom: 20px; font-size: 1.3em; }

        /* ===== 表单 ===== */
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: var(--text-secondary); }
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.3);
            color: var(--text-primary);
            font-size: 1em;
            transition: all 0.3s ease;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 10px rgba(0, 255, 170, 0.2);
        }

        /* ===== 渐变按钮 ===== */
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            color: #000000;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
        }
        .btn-primary:active {
            transform: translateY(0);
        }

        /* ===== 骨架屏加载动画 ===== */
        .skeleton {
            background: linear-gradient(90deg,
                rgba(255, 255, 255, 0.05) 0%,
                rgba(255, 255, 255, 0.1) 50%,
                rgba(255, 255, 255, 0.05) 100%
            );
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 8px;
        }
        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        /* 骨架屏 - 统计卡片 */
        .skeleton-stat {
            height: 120px;
            background: linear-gradient(90deg,
                rgba(255, 255, 255, 0.05) 0%,
                rgba(255, 255, 255, 0.1) 50%,
                rgba(255, 255, 255, 0.05) 100%
            );
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 15px;
        }

        /* 骨架屏 - 扫描列表项 */
        .skeleton-item {
            height: 60px;
            background: linear-gradient(90deg,
                rgba(255, 255, 255, 0.05) 0%,
                rgba(255, 255, 255, 0.1) 50%,
                rgba(255, 255, 255, 0.05) 100%
            );
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 8px;
            margin-bottom: 15px;
        }

        /* 骨架屏 - 模态框内容 */
        .skeleton-modal {
            height: 300px;
            background: linear-gradient(90deg,
                rgba(255, 255, 255, 0.05) 0%,
                rgba(255, 255, 255, 0.1) 50%,
                rgba(255, 255, 255, 0.05) 100%
            );
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 8px;
        }

        /* ===== Tab 内容淡入淡出 ===== */
        .tab-content {
            opacity: 1;
            transition: opacity 0.3s ease-in-out;
        }
        .tab-content.fade-out {
            opacity: 0;
        }
        .tab-content.fade-in {
            opacity: 0;
            animation: fadeIn 0.3s ease-in-out forwards;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        /* ===== Toast 通知 ===== */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 2000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .toast {
            padding: 15px 20px;
            border-radius: 8px;
            color: #ffffff;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            display: flex;
            align-items: center;
            gap: 10px;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            min-width: 300px;
        }
        .toast.show {
            opacity: 1;
            transform: translateX(0);
        }
        .toast.success {
            background: rgba(0, 209, 102, 0.9);
            border-left: 4px solid #00D166;
        }
        .toast.error {
            background: rgba(255, 77, 77, 0.9);
            border-left: 4px solid #FF4D4D;
        }
        .toast.info {
            background: rgba(0, 255, 255, 0.9);
            border-left: 4px solid #00FFFF;
            color: #000000;
        }
        .toast.warning {
            background: rgba(255, 165, 0, 0.9);
            border-left: 4px solid #FFA500;
            color: #000000;
        }

        /* ===== 滚动动画 ===== */
        .scroll-smooth {
            scroll-behavior: smooth;
        }
        .finding-item {
            transition: all 0.3s ease;
            opacity: 1;
        }
        .finding-item.scroll-in {
            animation: slideIn 0.4s ease-out;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* ===== 加载优化 ===== */
        .loading-fade-in {
            animation: fadeIn 0.3s ease-in-out;
        }

        /* ===== 扫描列表 ===== */
        .scan-list { max-height: 400px; overflow-y: auto; }
        .scan-item {
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .scan-item:hover { background: rgba(0, 255, 170, 0.05); }
        .scan-item .target { font-weight: bold; color: var(--text-primary); }
        .scan-item .meta { font-size: 0.85em; color: var(--text-secondary); margin-top: 5px; }

        /* ===== 状态徽章 ===== */
        .status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: bold;
        }
        .status-completed { background: rgba(0, 209, 102, 0.2); color: var(--success); }
        .status-running { background: rgba(0, 255, 170, 0.2); color: var(--accent); }
        .status-failed { background: rgba(255, 77, 77, 0.2); color: var(--danger); }

        /* ===== 严重级别颜色 ===== */
        .severity-critical { color: var(--danger); }
        .severity-high { color: #ff6b6b; }
        .severity-medium { color: var(--warning); }
        .severity-low { color: var(--success); }
        .severity-info { color: var(--accent-cyan); }

        /* ===== 模态框 (Glassmorphism) ===== */
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            overflow-y: auto;
        }
        .modal.active { display: flex; align-items: center; justify-content: center; padding: 20px; }
        .modal-content {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 15px;
            max-width: 900px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        .modal-header {
            padding: 20px 25px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h2 { color: var(--accent-cyan); }
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5em;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .modal-close:hover { color: var(--text-primary); }
        .modal-body { padding: 25px; }

        /* ===== 发现结果项 ===== */
        .finding-item {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--accent-cyan);
            transition: all 0.3s ease;
        }
        .finding-item.critical { border-left-color: var(--danger); }
        .finding-item.high { border-left-color: #ff6b6b; }
        .finding-item.medium { border-left-color: var(--warning); }
        .finding-item.low { border-left-color: var(--success); }
        .finding-item h4 { margin-bottom: 10px; color: var(--text-primary); }
        .finding-item .evidence {
            background: var(--bg-darker);
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            margin-top: 10px;
            color: var(--text-primary);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        /* ===== 复选框组 ===== */
        .checkbox-group { display: flex; flex-wrap: wrap; gap: 10px; }
        .checkbox-group label {
            display: flex;
            align-items: center;
            gap: 5px;
            padding: 8px 15px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .checkbox-group label:hover { background: rgba(0, 255, 170, 0.2); }

        /* ===== 表格样式 ===== */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background: rgba(0, 0, 0, 0.3);
            color: var(--text-secondary);
            font-weight: 600;
        }
        td { color: var(--text-primary); }
        tr:hover td { background: rgba(0, 255, 170, 0.05); }

        /* ===== 加载状态 ===== */
        .loading { text-align: center; padding: 40px; color: var(--text-secondary); }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid var(--border-color);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        /* ===== AI对话框 ===== */
        .ai-chat-widget {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 380px;
            height: 500px;
            background: var(--card-bg);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            display: flex;
            flex-direction: column;
            z-index: 1000;
            transition: transform 0.3s ease, opacity 0.3s ease;
        }
        .ai-chat-widget.collapsed {
            transform: translateY(calc(100% - 50px));
            opacity: 0.9;
        }
        .ai-chat-widget.expanded {
            width: 600px;
            height: 700px;
            right: 20px;
            bottom: 20px;
        }
        .ai-chat-header {
            padding: 12px 16px;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            border-radius: 12px 12px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        .ai-chat-header h3 {
            margin: 0;
            color: var(--bg-primary);
            font-size: 14px;
        }
        .ai-chat-actions {
            display: flex;
            gap: 4px;
            align-items: center;
        }
        .ai-chat-action-btn {
            background: rgba(255,255,255,0.15);
            border: none;
            color: var(--bg-primary);
            font-size: 14px;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 6px;
            transition: background 0.2s;
            line-height: 1;
        }
        .ai-chat-action-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        .ai-chat-toggle {
            background: none;
            border: none;
            color: var(--bg-primary);
            font-size: 18px;
            cursor: pointer;
            padding: 0 4px;
        }
        .ai-chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .ai-message {
            max-width: 85%;
            padding: 10px 14px;
            border-radius: 12px;
            font-size: 13px;
            line-height: 1.5;
            word-wrap: break-word;
        }
        .ai-message.user {
            align-self: flex-end;
            background: var(--accent);
            color: var(--bg-primary);
            border-bottom-right-radius: 4px;
        }
        .ai-message.assistant {
            align-self: flex-start;
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-bottom-left-radius: 4px;
        }
        .ai-message.loading {
            align-self: flex-start;
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-style: italic;
        }
        .ai-chat-input {
            padding: 12px 16px;
            border-top: 1px solid var(--border-color);
            display: flex;
            gap: 8px;
        }
        .ai-chat-input input {
            flex: 1;
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 20px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 13px;
            outline: none;
        }
        .ai-chat-input input:focus {
            border-color: var(--accent);
        }
        .ai-chat-input button {
            padding: 8px 16px;
            border: none;
            border-radius: 20px;
            background: var(--accent);
            color: var(--bg-primary);
            font-size: 13px;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .ai-chat-input button:hover {
            opacity: 0.9;
        }
        .ai-chat-input button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .ai-chat-fab {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            border: none;
            color: var(--bg-primary);
            font-size: 24px;
            cursor: pointer;
            box-shadow: 0 4px 16px rgba(0,255,170,0.3);
            z-index: 1001;
            display: none;
            transition: transform 0.2s;
        }
        .ai-chat-fab:hover {
            transform: scale(1.1);
        }
        .ai-chat-fab.visible {
            display: flex;
            align-items: center;
            justify-content: center;
        }
    </style>
</head>
<body class="scroll-smooth">
    <div class="container">
        <div class="header">
            <div class="header-left">
                <h1>🔒 PySecScanner</h1>
                <p>信息搜集与漏洞扫描平台</p>
            </div>
            <div class="header-right" id="user-area">
                <a href="/login" class="btn-login">登录 / 注册</a>
            </div>
        </div>
        <div class="stats-grid" id="stats">
            <div class="skeleton-stat"></div>
            <div class="skeleton-stat"></div>
            <div class="skeleton-stat"></div>
            <div class="skeleton-stat"></div>
        </div>
        <div class="main-content">
            <div class="card tab-content">
                <h2>🚀 新建扫描</h2>
                <form id="scan-form">
                    <div class="form-group">
                        <label>目标地址</label>
                        <input type="text" id="target" placeholder="例如: example.com" required>
                    </div>
                    <div class="form-group">
                        <label>扫描模块</label>
                        <div class="checkbox-group" id="modules-checkbox"></div>
                    </div>
                    <button type="submit" class="btn btn-primary">开始扫描</button>
                </form>
            </div>
            <div class="card tab-content">
                <h2>📋 扫描历史</h2>
                <div class="scan-list" id="scan-list">
                    <div class="skeleton-item"></div>
                    <div class="skeleton-item"></div>
                    <div class="skeleton-item"></div>
                </div>
            </div>
        </div>
    </div>
    <!-- Toast 通知容器 -->
    <div class="toast-container" id="toast-container"></div>
    <div class="modal" id="scan-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modal-title">扫描详情</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body"></div>
        </div>
    </div>
    <script>
        // ===== Toast 通知系统 =====
        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            
            const icons = {
                success: '✅',
                error: '❌',
                warning: '⚠️',
                info: 'ℹ️'
            };
            
            toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
            container.appendChild(toast);
            
            // 触发动画
            setTimeout(() => toast.classList.add('show'), 10);
            
            // 自动消失
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        // ===== Tab 切换淡入淡出 =====
        function fadeOut(element, callback) {
            element.classList.add('fade-out');
            element.classList.remove('fade-in');
            setTimeout(() => {
                if (callback) callback();
            }, 300);
        }

        function fadeIn(element) {
            element.classList.remove('fade-out');
            element.classList.add('fade-in');
            setTimeout(() => {
                element.classList.remove('fade-in');
            }, 300);
        }

        // ===== 滚动动画 =====
        function animateScrollIn() {
            const elements = document.querySelectorAll('.finding-item');
            elements.forEach((el, index) => {
                setTimeout(() => {
                    el.classList.add('scroll-in');
                }, index * 100);
            });
        }

        // ===== 加载统计信息（带骨架屏） =====
        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                const statsContainer = document.getElementById('stats');
                
                // 淡出骨架屏
                fadeOut(statsContainer, () => {
                    // 更新为真实数据
                    statsContainer.innerHTML = `
                        <div class="stat-card tab-content">
                            <h3>总扫描数</h3>
                            <div class="value" id="total-scans">${data.total_scans}</div>
                        </div>
                        <div class="stat-card tab-content">
                            <h3>总发现数</h3>
                            <div class="value" id="total-findings">${data.total_findings}</div>
                        </div>
                        <div class="stat-card tab-content">
                            <h3>高危漏洞</h3>
                            <div class="value severity-high" id="high-findings">
                                ${(data.severity_distribution.critical || 0) + (data.severity_distribution.high || 0)}
                            </div>
                        </div>
                        <div class="stat-card tab-content">
                            <h3>近7天扫描</h3>
                            <div class="value" id="recent-scans">${data.recent_scans_7d}</div>
                        </div>
                    `;
                    
                    // 淡入真实数据
                    fadeIn(statsContainer);
                });
            } catch (error) {
                console.error('加载统计信息失败:', error);
                showToast('加载统计信息失败', 'error');
            }
        }

        // ===== 加载模块 =====
        async function loadModules() {
            try {
                const res = await fetch('/api/modules');
                const data = await res.json();
                const container = document.getElementById('modules-checkbox');
                container.innerHTML = data.modules.map(m =>
                    `<input type="checkbox" id="mod-${m.name}" value="${m.name}" checked><label for="mod-${m.name}" title="${m.description}">${m.display_name}</label>`
                ).join('');
                showToast('模块加载完成', 'success');
            } catch (error) {
                console.error('加载模块失败:', error);
                showToast('加载模块失败', 'error');
            }
        }

        // ===== 加载扫描列表（带骨架屏） =====
        async function loadScans() {
            try {
                const res = await fetch('/api/scans');
                const data = await res.json();
                const container = document.getElementById('scan-list');
                
                if (data.scans.length === 0) {
                    container.innerHTML = '<p style="text-align:center;color:var(--text-secondary);padding:40px;">暂无扫描记录</p>';
                    return;
                }
                
                // 先显示骨架屏
                container.innerHTML = '<div class="skeleton-item"></div><div class="skeleton-item"></div><div class="skeleton-item"></div>';
                
                // 淡出骨架屏
                fadeOut(container, () => {
                    // 更新为真实数据
                    container.innerHTML = data.scans.map(s => `
                        <div class="scan-item tab-content" onclick="showScan(${s.id})">
                            <div class="target">${s.target}</div>
                            <div class="meta">
                                <span class="status-badge status-${s.status}">${s.status}</span>
                                ${s.total_findings} 个发现
                            </div>
                        </div>
                    `).join('');
                    
                    // 淡入真实数据
                    fadeIn(container);
                });
            } catch (error) {
                console.error('加载扫描列表失败:', error);
                showToast('加载扫描列表失败', 'error');
            }
        }

        // ===== 创建扫描 =====
        document.getElementById('scan-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = document.getElementById('target').value;
            const modules = Array.from(document.querySelectorAll('#modules-checkbox input:checked')).map(cb => cb.value);
            
            try {
                const res = await fetch('/api/scans', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, modules })
                });
                const data = await res.json();
                
                showToast('扫描已启动！ID: ' + data.scan_id, 'success');
                // 延迟刷新统计数据和扫描列表
                setTimeout(() => {
                    loadStats();
                    loadScans();
                }, 1000);
            } catch (error) {
                console.error('创建扫描失败:', error);
                showToast('创建扫描失败', 'error');
            }
        });

        // ===== 显示扫描详情 =====
        async function showScan(scanId) {
            try {
                const res = await fetch('/api/scans/' + scanId);
                const data = await res.json();
                
                // 记录当前查看的扫描ID
                currentScanId = scanId;
                
                document.getElementById('modal-title').textContent = '扫描: ' + data.scan.target;
                
                // 先显示骨架屏
                const modalBody = document.getElementById('modal-body');
                modalBody.innerHTML = '<div class="skeleton-modal"></div>';
                
                fadeOut(modalBody, () => {
                    let html = '<div style="margin-bottom:20px">';
                    html += '<p><strong>状态:</strong> <span class="status-badge status-' + data.scan.status + '">' + data.scan.status + '</span></p>';
                    html += '<p><strong>发现数量:</strong> ' + data.scan.total_findings + '</p>';
                    html += '</div>';
                    html += '<h3 style="margin-bottom:15px;color:var(--accent-cyan)">发现结果</h3>';
                    
                    if (data.findings.length === 0) {
                        html += '<p style="color:var(--text-secondary)">未发现问题</p>';
                    } else {
                        html += data.findings.map((f, index) => `
                            <div class="finding-item ${f.severity}" style="animation-delay: ${index * 0.1}s">
                                <h4>${f.title}</h4>
                                <p style="color:var(--text-secondary);margin-bottom:10px">${f.description}</p>
                                <p><strong>严重程度:</strong> <span class="severity-${f.severity}">${f.severity.toUpperCase()}</span></p>
                                ${f.evidence ? '<div class="evidence">' + f.evidence + '</div>' : ''}
                            </div>
                        `).join('');
                    }
                    
                    modalBody.innerHTML = html;
                    fadeIn(modalBody);
                    document.getElementById('scan-modal').classList.add('active');
                    
                    // 触发滚动动画
                    animateScrollIn();
                });
            } catch (error) {
                console.error('加载扫描详情失败:', error);
                showToast('加载扫描详情失败', 'error');
            }
        }

        // ===== 关闭模态框 =====
        function closeModal() {
            document.getElementById('scan-modal').classList.remove('active');
        }

        // ===== 点击模态框外部关闭 =====
        document.getElementById('scan-modal').addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                closeModal();
            }
        });

        // ===== 用户认证 =====
        let authToken = localStorage.getItem('auth_token');
        
        async function checkAuth() {
            if (!authToken) {
                // 未登录，强制跳转
                window.location.href = '/login';
                return false;
            }
            try {
                const res = await fetch('/api/auth/me', {
                    headers: { 'X-Token': authToken }
                });
                if (res.ok) {
                    const data = await res.json();
                    updateUserUI(data.username);
                    return true;
                } else {
                    // token无效，清除并跳转
                    localStorage.removeItem('auth_token');
                    localStorage.removeItem('username');
                    authToken = null;
                    window.location.href = '/login';
                    return false;
                }
            } catch (error) {
                console.error('验证登录状态失败:', error);
                window.location.href = '/login';
                return false;
            }
        }
        
        function updateUserUI(username) {
            const userArea = document.getElementById('user-area');
            userArea.innerHTML = `
                <div class="user-info">
                    <span class="user-name">👤 ${username}</span>
                    <button class="btn-logout" onclick="logout()">退出</button>
                </div>
            `;
        }
        
        async function logout() {
            if (authToken) {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: { 'X-Token': authToken }
                });
            }
            localStorage.removeItem('auth_token');
            localStorage.removeItem('username');
            authToken = null;
            window.location.href = '/login';
        }
        
        // 拦截fetch请求，自动添加token，处理401
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            // 确保options存在
            if (!args[1]) {
                args[1] = {};
            }
            // 确保headers存在
            if (!args[1].headers) {
                args[1].headers = {};
            }
            // 添加token
            if (authToken) {
                if (typeof args[1].headers === 'object') {
                    args[1].headers['X-Token'] = authToken;
                }
            }
            return originalFetch.apply(this, args).then(res => {
                if (res.status === 401) {
                    localStorage.removeItem('auth_token');
                    localStorage.removeItem('username');
                    window.location.href = '/login';
                }
                return res;
            });
        };

        // ===== 初始化 =====
        document.addEventListener('DOMContentLoaded', async () => {
            const isAuth = await checkAuth();
            if (isAuth) {
                loadStats();
                loadModules();
                loadScans();
                
                // 定时刷新
                setInterval(loadStats, 30000);
                setInterval(loadScans, 10000);
            }
        });
    </script>
    
    <!-- AI对话组件 -->
    <div class="ai-chat-widget" id="ai-chat-widget">
        <div class="ai-chat-header" onclick="toggleChat()">
            <h3>🤖 AI助手</h3>
            <div class="ai-chat-actions">
                <button class="ai-chat-action-btn" onclick="event.stopPropagation(); openChatInNewWindow()" title="在新窗口打开">↗</button>
                <button class="ai-chat-action-btn" id="ai-expand-btn" onclick="event.stopPropagation(); toggleExpand()" title="放大">⛶</button>
                <button class="ai-chat-action-btn" onclick="event.stopPropagation(); toggleChat()" title="最小化">−</button>
            </div>
        </div>
        <div class="ai-chat-messages" id="ai-chat-messages">
            <div class="ai-message assistant">你好！我是PySecScanner AI助手，可以帮你分析扫描结果或解答安全问题。</div>
        </div>
        <div class="ai-chat-input">
            <input type="text" id="ai-chat-input" placeholder="输入消息..." onkeypress="if(event.key==='Enter')sendChatMessage()">
            <button id="ai-chat-send" onclick="sendChatMessage()">发送</button>
        </div>
    </div>
    <button class="ai-chat-fab" id="ai-chat-fab" onclick="toggleChat()">🤖</button>
    
    <script>
        // ===== AI对话功能 =====
        let chatHistory = [];
        let isChatOpen = true;
        let currentScanId = null;  // 当前查看的扫描ID
        
        function toggleChat() {
            const widget = document.getElementById('ai-chat-widget');
            const fab = document.getElementById('ai-chat-fab');
            isChatOpen = !isChatOpen;
            
            if (isChatOpen) {
                widget.classList.remove('collapsed');
                fab.classList.remove('visible');
            } else {
                widget.classList.add('collapsed');
                fab.classList.add('visible');
            }
        }
        
        let isExpanded = false;
        function toggleExpand() {
            const widget = document.getElementById('ai-chat-widget');
            const btn = document.getElementById('ai-expand-btn');
            isExpanded = !isExpanded;
            
            if (isExpanded) {
                widget.classList.add('expanded');
                btn.innerHTML = '⛶';
                btn.title = '缩小';
            } else {
                widget.classList.remove('expanded');
                btn.innerHTML = '⛶';
                btn.title = '放大';
            }
        }
        
        function openChatInNewWindow() {
            // 在新标签页打开专门的AI对话页面
            window.open('/chat', '_blank');
        }
        
        async function sendChatMessage() {
            const input = document.getElementById('ai-chat-input');
            const sendBtn = document.getElementById('ai-chat-send');
            const messagesContainer = document.getElementById('ai-chat-messages');
            const message = input.value.trim();
            
            if (!message) return;
            
            // 添加用户消息
            const userMsgDiv = document.createElement('div');
            userMsgDiv.className = 'ai-message user';
            userMsgDiv.textContent = message;
            messagesContainer.appendChild(userMsgDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            
            // 清空输入框
            input.value = '';
            
            // 禁用发送按钮
            sendBtn.disabled = true;
            
            // 添加加载消息
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'ai-message loading';
            loadingDiv.textContent = 'AI正在思考...';
            loadingDiv.id = 'ai-loading-msg';
            messagesContainer.appendChild(loadingDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: message,
                        history: chatHistory,
                        scan_id: currentScanId
                    })
                });
                
                const data = await res.json();
                
                // 移除加载消息
                const loadingMsg = document.getElementById('ai-loading-msg');
                if (loadingMsg) loadingMsg.remove();
                
                // 添加AI回复
                const aiMsgDiv = document.createElement('div');
                aiMsgDiv.className = 'ai-message assistant';
                aiMsgDiv.textContent = data.response;
                messagesContainer.appendChild(aiMsgDiv);
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
                
                // 保存对话历史
                chatHistory.push({ role: 'user', content: message });
                chatHistory.push({ role: 'assistant', content: data.response });
                
                // 限制历史记录长度
                if (chatHistory.length > 12) {
                    chatHistory = chatHistory.slice(-12);
                }
                
            } catch (error) {
                console.error('AI对话失败:', error);
                
                // 移除加载消息
                const loadingMsg = document.getElementById('ai-loading-msg');
                if (loadingMsg) loadingMsg.remove();
                
                // 添加错误消息
                const errorDiv = document.createElement('div');
                errorDiv.className = 'ai-message assistant';
                errorDiv.style.color = '#ff6b6b';
                errorDiv.textContent = '抱歉，AI服务暂时不可用，请检查配置或稍后重试。';
                messagesContainer.appendChild(errorDiv);
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            } finally {
                sendBtn.disabled = false;
            }
        }
    </script>
</body>
</html>
'''


def get_chat_html() -> str:
    """返回AI对话专用页面"""
    return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner AI助手</title>
    <style>
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-tertiary: #1a2332;
            --card-bg: #151b2d;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #00ffaa;
            --accent-light: #00d4ff;
            --accent-cyan: #00d4ff;
            --border-color: #1e293b;
            --success: #00ffaa;
            --warning: #f59e0b;
            --error: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        .chat-header {
            padding: 16px 24px;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0;
        }
        .chat-header h1 {
            color: var(--bg-primary);
            font-size: 18px;
            margin: 0;
        }
        .back-link {
            color: var(--bg-primary);
            text-decoration: none;
            font-size: 14px;
            padding: 6px 12px;
            background: rgba(255,255,255,0.2);
            border-radius: 6px;
            transition: background 0.2s;
        }
        .back-link:hover { background: rgba(255,255,255,0.3); }
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
        }
        .ai-message {
            max-width: 80%;
            padding: 14px 18px;
            border-radius: 14px;
            font-size: 14px;
            line-height: 1.6;
            word-wrap: break-word;
            animation: fadeIn 0.3s ease;
        }
        .ai-message.user {
            align-self: flex-end;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            color: var(--bg-primary);
            border-bottom-right-radius: 4px;
        }
        .ai-message.assistant {
            align-self: flex-start;
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            border-bottom-left-radius: 4px;
        }
        .ai-message.loading {
            align-self: flex-start;
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-style: italic;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .chat-input-area {
            padding: 16px 24px;
            border-top: 1px solid var(--border-color);
            background: var(--card-bg);
            flex-shrink: 0;
        }
        .chat-input-wrapper {
            max-width: 900px;
            margin: 0 auto;
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .chat-input-wrapper input {
            flex: 1;
            padding: 12px 18px;
            border: 1px solid var(--border-color);
            border-radius: 24px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }
        .chat-input-wrapper input:focus { border-color: var(--accent); }
        .chat-input-wrapper button {
            padding: 12px 24px;
            border: none;
            border-radius: 24px;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            color: var(--bg-primary);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .chat-input-wrapper button:hover { opacity: 0.9; }
        .chat-input-wrapper button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        /* 滚动条 */
        .chat-messages::-webkit-scrollbar { width: 6px; }
        .chat-messages::-webkit-scrollbar-track { background: transparent; }
        .chat-messages::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
        .chat-messages::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }
    </style>
</head>
<body>
    <div class="chat-header">
        <h1>🤖 PySecScanner AI助手</h1>
        <a href="/" class="back-link">← 返回主页</a>
    </div>
    <div class="chat-messages" id="chat-messages">
        <div class="ai-message assistant">你好！我是PySecScanner AI助手，可以帮你分析扫描结果或解答安全问题。</div>
    </div>
    <div class="chat-input-area">
        <div class="chat-input-wrapper">
            <input type="text" id="chat-input" placeholder="输入消息，按回车发送..." onkeypress="if(event.key==='Enter')sendMessage()">
            <button id="chat-send" onclick="sendMessage()">发送</button>
        </div>
    </div>
    
    <script>
        let chatHistory = [];
        const authToken = localStorage.getItem('auth_token');
        
        // 检查登录状态
        if (!authToken) {
            window.location.href = '/login';
        }
        
        async function sendMessage() {
            const input = document.getElementById('chat-input');
            const sendBtn = document.getElementById('chat-send');
            const messagesContainer = document.getElementById('chat-messages');
            const message = input.value.trim();
            
            if (!message) return;
            
            // 添加用户消息
            const userMsgDiv = document.createElement('div');
            userMsgDiv.className = 'ai-message user';
            userMsgDiv.textContent = message;
            messagesContainer.appendChild(userMsgDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            
            input.value = '';
            sendBtn.disabled = true;
            
            // 添加加载消息
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'ai-message loading';
            loadingDiv.textContent = 'AI正在思考...';
            loadingDiv.id = 'loading-msg';
            messagesContainer.appendChild(loadingDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Token': authToken || ''
                    },
                    body: JSON.stringify({
                        message: message,
                        history: chatHistory
                    })
                });
                
                const data = await res.json();
                
                const loadingMsg = document.getElementById('loading-msg');
                if (loadingMsg) loadingMsg.remove();
                
                const aiMsgDiv = document.createElement('div');
                aiMsgDiv.className = 'ai-message assistant';
                aiMsgDiv.textContent = data.response;
                messagesContainer.appendChild(aiMsgDiv);
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
                
                chatHistory.push({ role: 'user', content: message });
                chatHistory.push({ role: 'assistant', content: data.response });
                
                if (chatHistory.length > 12) {
                    chatHistory = chatHistory.slice(-12);
                }
            } catch (error) {
                console.error('AI对话失败:', error);
                const loadingMsg = document.getElementById('loading-msg');
                if (loadingMsg) loadingMsg.remove();
                
                const errorDiv = document.createElement('div');
                errorDiv.className = 'ai-message assistant';
                errorDiv.style.color = '#ff6b6b';
                errorDiv.textContent = '抱歉，AI服务暂时不可用，请检查配置或稍后重试。';
                messagesContainer.appendChild(errorDiv);
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            } finally {
                sendBtn.disabled = false;
                input.focus();
            }
        }
        
        // 自动聚焦输入框
        document.addEventListener('DOMContentLoaded', () => {
            document.getElementById('chat-input').focus();
        });
    </script>
</body>
</html>
'''


def get_login_html() -> str:
    """返回登录页面"""
    return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - PySecScanner</title>
    <style>
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-tertiary: #1a2332;
            --card-bg: #151b2d;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #00ffaa;
            --accent-light: #00d4ff;
            --border-color: #1e293b;
            --error: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 40px;
            background: var(--card-bg);
            border-radius: 16px;
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        .login-header {
            text-align: center;
            margin-bottom: 32px;
        }
        .login-header h1 {
            font-size: 28px;
            margin-bottom: 8px;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .login-header p { color: var(--text-secondary); font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            color: var(--text-secondary);
        }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }
        .form-group input:focus { border-color: var(--accent); }
        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            color: var(--bg-primary);
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .toggle-mode {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
            color: var(--text-secondary);
        }
        .toggle-mode a {
            color: var(--accent);
            cursor: pointer;
            text-decoration: none;
        }
        .toggle-mode a:hover { text-decoration: underline; }
        .error-msg {
            color: var(--error);
            font-size: 13px;
            margin-top: 8px;
            text-align: center;
            display: none;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 16px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 13px;
        }
        .back-link:hover { color: var(--accent); }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔒 PySecScanner</h1>
            <p id="mode-desc">登录到您的账户</p>
        </div>
        <form id="login-form">
            <div class="form-group">
                <label>用户名</label>
                <input type="text" id="username" placeholder="请输入用户名" required>
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" id="password" placeholder="请输入密码" required>
            </div>
            <button type="submit" class="btn" id="submit-btn">登录</button>
            <div class="error-msg" id="error-msg"></div>
        </form>
        <div class="toggle-mode">
            <span id="toggle-text">还没有账户？</span>
            <a onclick="toggleMode()" id="toggle-link">立即注册</a>
        </div>
        <a href="/" class="back-link">← 返回主页</a>
    </div>
    
    <script>
        let isLoginMode = true;
        
        function toggleMode() {
            isLoginMode = !isLoginMode;
            document.getElementById('mode-desc').textContent = isLoginMode ? '登录到您的账户' : '创建新账户';
            document.getElementById('submit-btn').textContent = isLoginMode ? '登录' : '注册';
            document.getElementById('toggle-text').textContent = isLoginMode ? '还没有账户？' : '已有账户？';
            document.getElementById('toggle-link').textContent = isLoginMode ? '立即注册' : '立即登录';
            document.getElementById('error-msg').style.display = 'none';
        }
        
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const submitBtn = document.getElementById('submit-btn');
            const errorMsg = document.getElementById('error-msg');
            
            submitBtn.disabled = true;
            errorMsg.style.display = 'none';
            
            try {
                const endpoint = isLoginMode ? '/api/auth/login' : '/api/auth/register';
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await res.json();
                
                if (res.ok) {
                    // 保存token
                    localStorage.setItem('auth_token', data.token);
                    localStorage.setItem('username', data.username);
                    // 跳转到主页
                    window.location.href = '/';
                } else {
                    errorMsg.textContent = data.detail || '操作失败';
                    errorMsg.style.display = 'block';
                }
            } catch (error) {
                errorMsg.textContent = '网络错误，请稍后重试';
                errorMsg.style.display = 'block';
            } finally {
                submitBtn.disabled = false;
            }
        });
        
        // 如果已登录，自动跳转
        if (localStorage.getItem('auth_token')) {
            window.location.href = '/';
        }
    </script>
</body>
</html>
'''


def run_server(host: str = "0.0.0.0", port: int = 8000, open_browser: bool = True):
    """启动Web服务器"""
    import uvicorn
    import threading
    import time
    
    print(f"\n🚀 PySecScanner Web界面启动中...")
    print(f"📍 访问地址: http://{host}:{port}")
    print(f"📖 API文档: http://{host}:{port}/docs\n")
    
    # 自动打开浏览器
    if open_browser:
        def open_browser_delayed():
            time.sleep(2)  # 等待服务器启动
            try:
                import webbrowser
                url = f"http://{host}:{port}"
                webbrowser.open(url)
                print(f"🌐 已自动打开浏览器: {url}\n")
            except Exception as e:
                print(f"⚠️ 自动打开浏览器失败: {e}\n")
        
        browser_thread = threading.Thread(target=open_browser_delayed, daemon=True)
        browser_thread.start()
    
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
