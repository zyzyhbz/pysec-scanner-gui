"""
AI批量分析器
支持批量漏洞的高效分析和任务队列管理
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import hashlib

from core.base import ScanResult
from modules.ai.analyzer import AIAnalyzer
from modules.ai.ai_service_adapter import AIAnalysisResult


@dataclass
class AnalysisTask:
    """分析任务"""
    task_id: str
    result: ScanResult
    status: str = "pending"  # pending, processing, completed, failed
    analysis_result: Optional[AIAnalysisResult] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    completed_at: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "status": self.status,
            "title": self.result.title,
            "result_type": self.result.result_type.value,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "error": self.error
        }


class BatchAnalyzer:
    """AI批量分析器（任务9）"""
    
    def __init__(
        self,
        max_concurrent: int = 5,
        ai_analyzer: Optional[AIAnalyzer] = None
    ):
        """
        初始化批量分析器
        
        Args:
            max_concurrent: 最大并发数
            ai_analyzer: AI分析器实例
        """
        self.max_concurrent = max_concurrent
        self.ai_analyzer = ai_analyzer
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._tasks: Dict[str, AnalysisTask] = {}
        self._processing_tasks: set[str] = set()
        self._running = False
        self._worker_tasks: List[asyncio.Task] = []
        self._progress_callbacks: List[Any] = []
    
    async def analyze_batch(
        self,
        results: List[ScanResult],
        on_progress: Optional[callable] = None
    ) -> List[AIAnalysisResult]:
        """
        批量分析漏洞（任务9）
        
        Args:
            results: 扫描结果列表
            on_progress: 进度回调函数
            
        Returns:
            AI分析结果列表（与输入顺序一致）
        """
        # 每次调用前重置内部任务状态，避免上一次分析残留导致任务ID不匹配
        self._tasks.clear()
        self._processing_tasks.clear()
        # 用新的队列替换旧队列，确保没有残留任务
        self._task_queue = asyncio.Queue()

        if on_progress:
            self._progress_callbacks.append(on_progress)
        
        # 创建分析任务
        result_map = {}
        for i, result in enumerate(results):
            task_id = self._generate_task_id(result)
            task = AnalysisTask(task_id=task_id, result=result)
            self._tasks[task_id] = task
            result_map[task_id] = {"result": result, "index": i}
            await self._task_queue.put(task_id)
        
        # 启动worker
        if not self._running:
            self._running = True
            self._worker_tasks = [
                asyncio.create_task(self._worker(f"worker-{i}"))
                for i in range(self.max_concurrent)
            ]
        
        # 等待所有任务完成
        total_tasks = len(results)
        completed_tasks = 0
        
        while completed_tasks < total_tasks:
            await asyncio.sleep(0.1)
            completed_tasks = sum(
                1 for task in self._tasks.values()
                if task.status in ["completed", "failed"]
            )
            
            # 调用进度回调
            if on_progress:
                progress = {
                    "total": total_tasks,
                    "completed": completed_tasks,
                    "pending": total_tasks - completed_tasks,
                    "progress_percent": (completed_tasks / total_tasks) * 100
                }
                for callback in self._progress_callbacks:
                    try:
                        callback(progress)
                    except Exception:
                        pass
        
        # 收集结果
        analysis_results = [None] * len(results)
        for task in self._tasks.values():
            info = result_map[task.task_id]
            analysis_results[info["index"]] = task.analysis_result
        
        # 停止worker
        await self._stop()
        
        # 清理回调
        if on_progress:
            self._progress_callbacks.remove(on_progress)
        
        return analysis_results
    
    async def _worker(self, worker_name: str) -> None:
        """
        Worker协程，从队列中获取任务并执行分析
        
        Args:
            worker_name: Worker名称
        """
        while True:
            try:
                # 获取任务（超时1秒，检查是否停止）
                task_id = await asyncio.wait_for(
                    self._task_queue.get(),
                    timeout=1.0
                )
                
                task = self._tasks.get(task_id)
                if not task:
                    continue
                
                # 标记为处理中
                task.status = "processing"
                self._processing_tasks.add(task_id)
                
                try:
                    # 执行分析
                    if self.ai_analyzer:
                        analysis_result = await self.ai_analyzer.analyze(task.result)
                    else:
                        from modules.ai.ai_service_adapter import AIAnalysisResult
                        analysis_result = AIAnalysisResult()
                    
                    task.analysis_result = analysis_result
                    task.status = "completed"
                    task.completed_at = datetime.now().timestamp()
                    
                except Exception as e:
                    task.status = "failed"
                    task.error = str(e)
                    task.completed_at = datetime.now().timestamp()
                
                finally:
                    self._processing_tasks.discard(task_id)
                    self._task_queue.task_done()
                    
            except asyncio.TimeoutError:
                # 检查是否应该停止
                if not self._running and self._task_queue.empty():
                    break
            except Exception as e:
                # 错误继续处理下一个任务
                continue
    
    async def _stop(self) -> None:
        """停止所有worker"""
        if not self._running:
            return
        
        self._running = False
        
        # 等待队列清空
        await self._task_queue.join()
        
        # 取消worker
        for worker_task in self._worker_tasks:
            worker_task.cancel()
        
        # 等待worker结束
        if self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        
        self._worker_tasks.clear()
    
    def _generate_task_id(self, result: ScanResult) -> str:
        """
        生成任务ID（任务去重）
        
        Args:
            result: 扫描结果
            
        Returns:
            任务ID
        """
        # 使用结果的唯一属性生成ID
        # 兼容 result.result_type 可能是 Enum 或 str 的情况（GUI/外部调用可能传入字符串）
        result_type_value = getattr(result.result_type, "value", result.result_type)
        unique_str = f"{result_type_value}_{result.title}_{result.target}_{hash(str(result.raw_data))}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:16]
    
    def get_pending_count(self) -> int:
        """获取待处理任务数"""
        return self._task_queue.qsize()
    
    def get_processing_count(self) -> int:
        """获取正在处理的任务数"""
        return len(self._processing_tasks)
    
    def get_completed_count(self) -> int:
        """获取已完成任务数"""
        return sum(
            1 for task in self._tasks.values()
            if task.status == "completed"
        )
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        获取任务状态
        
        Args:
            task_id: 任务ID
            
        Returns:
            任务状态字典
        """
        task = self._tasks.get(task_id)
        if task:
            return task.to_dict()
        return None
    
    def get_all_tasks_status(self) -> Dict[str, Any]:
        """
        获取所有任务状态
        
        Returns:
            任务状态汇总
        """
        status_counts = {"pending": 0, "processing": 0, "completed": 0, "failed": 0}
        
        for task in self._tasks.values():
            status_counts[task.status] += 1
        
        return {
            "total_tasks": len(self._tasks),
            "status_counts": status_counts,
            "pending": self.get_pending_count(),
            "processing": self.get_processing_count(),
            "completed": self.get_completed_count(),
            "failed": status_counts["failed"]
        }
    
    async def persist_tasks(self, filepath: str) -> None:
        """
        持久化任务（任务持久化）
        
        Args:
            filepath: 持久化文件路径
        """
        import json
        
        tasks_data = []
        for task in self._tasks.values():
            data = task.to_dict()
            if task.analysis_result:
                data["analysis_result"] = task.analysis_result.to_dict()
            tasks_data.append(data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(tasks_data, f, indent=2, ensure_ascii=False, default=str)
    
    async def load_tasks(self, filepath: str) -> None:
        """
        从文件加载任务（任务持久化）
        
        Args:
            filepath: 持久化文件路径
        """
        import json
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                tasks_data = json.load(f)
            
            for data in tasks_data:
                # 重建任务对象
                task = AnalysisTask(
                    task_id=data["task_id"],
                    result=ScanResult(
                        result_type=data.get("result_type"),
                        title=data.get("title", "")
                    ),
                    status=data.get("status", "pending"),
                    error=data.get("error"),
                    created_at=data.get("created_at"),
                    completed_at=data.get("completed_at")
                )
                
                # 重建分析结果
                if "analysis_result" in data:
                    ar_data = data["analysis_result"]
                    task.analysis_result = AIAnalysisResult(
                        root_cause=ar_data.get("root_cause", ""),
                        impact_scope=ar_data.get("impact_scope", ""),
                        attack_path=ar_data.get("attack_path", ""),
                        cvss_score=ar_data.get("cvss_score", 0.0),
                        cvss_justification=ar_data.get("cvss_justification", ""),
                        additional_insights=ar_data.get("additional_insights")
                    )
                
                self._tasks[task.task_id] = task
        
        except FileNotFoundError:
            pass
        except Exception as e:
            raise Exception(f"加载任务失败: {e}")
