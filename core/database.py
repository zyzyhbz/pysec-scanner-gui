"""
数据库存储模块
使用SQLite保存扫描历史和结果
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import threading

from core.logger import logger


@dataclass
class ScanRecord:
    """扫描记录"""
    id: int
    target: str
    start_time: datetime
    end_time: datetime
    duration: float
    status: str
    modules: str
    total_findings: int
    severity_distribution: str  # JSON


@dataclass
class FindingRecord:
    """发现记录"""
    id: int
    scan_id: int
    result_type: str
    title: str
    description: str
    severity: str
    target: str
    evidence: str
    raw_data: str  # JSON


class Database:
    """
    数据库管理类
    使用SQLite存储扫描结果
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_path: str = "data/scanner.db"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, db_path: str = "data/scanner.db"):
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_db()
        self._initialized = True
    
    def _ensure_db_dir(self):
        """确保数据库目录存在"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            Path(db_dir).mkdir(parents=True, exist_ok=True)
    
    def _get_connection(self) -> sqlite3.Connection:
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """初始化数据库表"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # 扫描记录表（带用户关联）
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 1,
                target TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                duration REAL,
                status TEXT DEFAULT 'running',
                modules TEXT,
                total_findings INTEGER DEFAULT 0,
                severity_distribution TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # 发现结果表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                result_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                target TEXT,
                evidence TEXT,
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        # 检查并添加user_id列（兼容旧数据库）
        try:
            cursor.execute('SELECT user_id FROM scans LIMIT 1')
        except sqlite3.OperationalError:
            # 旧数据库需要迁移
            cursor.execute('ALTER TABLE scans ADD COLUMN user_id INTEGER DEFAULT 1')
            logger.info("已为scans表添加user_id列")
        
        # 用户表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
        
        # 创建默认用户LHY（如果不存在）
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('LHY',))
        if cursor.fetchone()[0] == 0:
            import hashlib
            import secrets
            salt = secrets.token_hex(16)
            pwdhash = hashlib.sha256(('lhy123456' + salt).encode()).hexdigest()
            password_hash = f"{salt}${pwdhash}"
            cursor.execute('''
                INSERT INTO users (username, password_hash, is_admin)
                VALUES (?, ?, 1)
            ''', ('LHY', password_hash))
            logger.info("已创建默认用户 LHY")
        
        # 将现有扫描数据关联到LHY用户（user_id为NULL时）
        cursor.execute('UPDATE scans SET user_id = 1 WHERE user_id IS NULL')
        
        conn.commit()
        conn.close()
        conn.close()
    
    def create_scan(self, target: str, modules: List[str], user_id: int = 1) -> int:
        """创建新的扫描记录"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (user_id, target, start_time, modules, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, target, datetime.now(), json.dumps(modules), 'running'))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def update_scan(self, scan_id: int, status: str = None, 
                    total_findings: int = None, severity_distribution: Dict = None) -> None:
        """更新扫描记录"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        updates = ['end_time = ?']
        params = [datetime.now()]
        
        if status:
            updates.append('status = ?')
            params.append(status)
        
        if total_findings is not None:
            updates.append('total_findings = ?')
            params.append(total_findings)
        
        if severity_distribution:
            updates.append('severity_distribution = ?')
            params.append(json.dumps(severity_distribution))
        
        # 计算持续时间
        cursor.execute('SELECT start_time FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        if row:
            start_time = datetime.fromisoformat(row['start_time'])
            duration = (datetime.now() - start_time).total_seconds()
            updates.append('duration = ?')
            params.append(duration)
        
        params.append(scan_id)
        
        cursor.execute(f'''
            UPDATE scans SET {', '.join(updates)} WHERE id = ?
        ''', params)
        
        conn.commit()
        conn.close()
    
    def add_finding(self, scan_id: int, finding: Dict[str, Any]) -> int:
        """添加发现结果"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings (scan_id, result_type, title, description, 
                                 severity, target, evidence, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            finding.get('result_type', 'unknown'),
            finding.get('title', ''),
            finding.get('description', ''),
            finding.get('severity', 'info'),
            finding.get('target', ''),
            finding.get('evidence', ''),
            json.dumps(finding.get('raw_data', {}))
        ))
        
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return finding_id
    
    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        """获取扫描记录"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return ScanRecord(
                id=row['id'],
                target=row['target'],
                start_time=datetime.fromisoformat(row['start_time']),
                end_time=datetime.fromisoformat(row['end_time']) if row['end_time'] else None,
                duration=row['duration'] or 0,
                status=row['status'],
                modules=row['modules'],
                total_findings=row['total_findings'],
                severity_distribution=row['severity_distribution']
            )
        return None
    
    def get_scans(self, limit: int = 50, offset: int = 0, user_id: int = None) -> List[ScanRecord]:
        """获取扫描记录列表（可按用户过滤）"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('''
                SELECT * FROM scans WHERE user_id = ? ORDER BY start_time DESC LIMIT ? OFFSET ?
            ''', (user_id, limit, offset))
        else:
            cursor.execute('''
                SELECT * FROM scans ORDER BY start_time DESC LIMIT ? OFFSET ?
            ''', (limit, offset))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [ScanRecord(
            id=row['id'],
            target=row['target'],
            start_time=datetime.fromisoformat(row['start_time']),
            end_time=datetime.fromisoformat(row['end_time']) if row['end_time'] else None,
            duration=row['duration'] or 0,
            status=row['status'],
            modules=row['modules'],
            total_findings=row['total_findings'],
            severity_distribution=row['severity_distribution']
        ) for row in rows]
    
    def get_findings(self, scan_id: int) -> List[FindingRecord]:
        """获取扫描的所有发现"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM findings WHERE scan_id = ? ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
                WHEN 'medium' THEN 3 
                WHEN 'low' THEN 4 
                ELSE 5 
            END
        ''', (scan_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [FindingRecord(
            id=row['id'],
            scan_id=row['scan_id'],
            result_type=row['result_type'],
            title=row['title'],
            description=row['description'],
            severity=row['severity'],
            target=row['target'],
            evidence=row['evidence'],
            raw_data=row['raw_data']
        ) for row in rows]
    
    def get_stats(self, user_id: int = None) -> Dict[str, Any]:
        """获取统计信息（可按用户过滤）"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if user_id:
            # 总扫描数（按用户）
            cursor.execute('SELECT COUNT(*) as count FROM scans WHERE user_id = ?', (user_id,))
            total_scans = cursor.fetchone()['count']
            
            # 总发现数（按用户的扫描）
            cursor.execute('''
                SELECT COUNT(*) as count FROM findings
                WHERE scan_id IN (SELECT id FROM scans WHERE user_id = ?)
            ''', (user_id,))
            total_findings = cursor.fetchone()['count']
            
            # 按严重程度统计（按用户的扫描）
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE scan_id IN (SELECT id FROM scans WHERE user_id = ?)
                GROUP BY severity
            ''', (user_id,))
            severity_stats = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # 最近7天扫描数（按用户）
            cursor.execute('''
                SELECT COUNT(*) as count FROM scans
                WHERE user_id = ? AND start_time >= datetime('now', '-7 days')
            ''', (user_id,))
            recent_scans = cursor.fetchone()['count']
        else:
            # 总扫描数
            cursor.execute('SELECT COUNT(*) as count FROM scans')
            total_scans = cursor.fetchone()['count']
            
            # 总发现数
            cursor.execute('SELECT COUNT(*) as count FROM findings')
            total_findings = cursor.fetchone()['count']
            
            # 按严重程度统计
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM findings
                GROUP BY severity
            ''')
            severity_stats = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # 最近7天扫描数
            cursor.execute('''
                SELECT COUNT(*) as count FROM scans
                WHERE start_time >= datetime('now', '-7 days')
            ''')
            recent_scans = cursor.fetchone()['count']
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'severity_distribution': severity_stats,
            'recent_scans_7d': recent_scans
        }
    
    def delete_scan(self, scan_id: int) -> bool:
        """删除扫描记录及其发现"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # 删除相关发现
        cursor.execute('DELETE FROM findings WHERE scan_id = ?', (scan_id,))
        
        # 删除扫描记录
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return deleted
    
    def search_findings(self, query: str, severity: str = None, 
                        limit: int = 100) -> List[FindingRecord]:
        """搜索发现结果"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        sql = '''
            SELECT * FROM findings 
            WHERE (title LIKE ? OR target LIKE ? OR description LIKE ?)
        '''
        params = [f'%{query}%', f'%{query}%', f'%{query}%']
        
        if severity:
            sql += ' AND severity = ?'
            params.append(severity)
        
        sql += ' ORDER BY created_at DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [FindingRecord(
            id=row['id'],
            scan_id=row['scan_id'],
            result_type=row['result_type'],
            title=row['title'],
            description=row['description'],
            severity=row['severity'],
            target=row['target'],
            evidence=row['evidence'],
            raw_data=row['raw_data']
        ) for row in rows]
    
    # ==================== 用户管理 ====================
    
    def create_user(self, username: str, password_hash: str) -> bool:
        """创建用户"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            ''', (username, password_hash))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """获取用户信息"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, password_hash, is_admin, created_at
            FROM users WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row['id'],
                'username': row['username'],
                'password_hash': row['password_hash'],
                'is_admin': bool(row['is_admin']),
                'created_at': row['created_at']
            }
        return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """根据ID获取用户信息"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, is_admin, created_at
            FROM users WHERE id = ?
        ''', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row['id'],
                'username': row['username'],
                'is_admin': bool(row['is_admin']),
                'created_at': row['created_at']
            }
        return None
    
    def user_exists(self, username: str) -> bool:
        """检查用户是否存在"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        result = cursor.fetchone() is not None
        conn.close()
        return result
    
    def get_user_count(self) -> int:
        """获取用户总数"""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM users')
        result = cursor.fetchone()
        conn.close()
        return result['count'] if result else 0


# 全局数据库实例
db = Database()
