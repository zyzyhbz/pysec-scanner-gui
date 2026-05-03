"""
HTTP证据采集工具
用于在漏洞探测时记录“解释用证据”（请求/响应摘要、耗时、片段等）。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, Optional

import aiohttp


def _truncate(text: str, limit: int = 800) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"...(truncated, total={len(text)})"


def _safe_headers(headers: aiohttp.typedefs.LooseHeaders) -> Dict[str, str]:
    """
    只保留少量对分析有用且低敏感的响应头。
    """
    keep = {"server", "content-type", "content-length", "location", "set-cookie", "x-powered-by"}
    out: Dict[str, str] = {}
    for k, v in dict(headers).items():
        lk = str(k).lower()
        if lk in keep:
            out[str(k)] = str(v)
    return out


async def fetch_evidence(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Any = None,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = False,
    timeout: Optional[aiohttp.ClientTimeout] = None,
    body_limit: int = 1200,
) -> Dict[str, Any]:
    """
    发起一次HTTP请求并返回可用于解释的证据（尽量不包含高敏感信息）。
    """
    start = time.perf_counter()
    try:
        req_kwargs: Dict[str, Any] = {
            "allow_redirects": allow_redirects,
        }
        if timeout is not None:
            req_kwargs["timeout"] = timeout
        if params:
            req_kwargs["params"] = params
        if data is not None:
            req_kwargs["data"] = data
        if headers:
            req_kwargs["headers"] = headers

        async with session.request(method.upper(), url, **req_kwargs) as resp:
            text = await resp.text(errors="ignore")
            elapsed_ms = (time.perf_counter() - start) * 1000
            snippet = _truncate(text, body_limit)
            snippet_hash = hashlib.sha256(snippet.encode("utf-8", errors="ignore")).hexdigest()
            return {
                "url": url,
                "method": method.upper(),
                "status": resp.status,
                "elapsed_ms": round(elapsed_ms, 2),
                "headers": _safe_headers(resp.headers),
                "body_snippet": snippet,
                "body_hash": snippet_hash,
                "body_length": len(text),
            }
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "url": url,
            "method": method.upper(),
            "error": f"{type(e).__name__}: {e}",
            "elapsed_ms": round(elapsed_ms, 2),
        }


def compare_evidence(baseline: Dict[str, Any], exploit: Dict[str, Any]) -> Dict[str, Any]:
    """
    生成 baseline 与 exploit 的差异摘要，便于解释“为什么判定为异常”。
    """
    def _num(x, default=0):
        try:
            return float(x)
        except Exception:
            return default

    b_status = baseline.get("status")
    e_status = exploit.get("status")
    b_len = _num(baseline.get("body_length"))
    e_len = _num(exploit.get("body_length"))
    b_ms = _num(baseline.get("elapsed_ms"))
    e_ms = _num(exploit.get("elapsed_ms"))

    return {
        "status_changed": (b_status is not None and e_status is not None and b_status != e_status),
        "baseline_status": b_status,
        "exploit_status": e_status,
        "length_delta": int(e_len - b_len),
        "baseline_length": int(b_len),
        "exploit_length": int(e_len),
        "elapsed_ms_delta": round(e_ms - b_ms, 2),
        "baseline_elapsed_ms": round(b_ms, 2),
        "exploit_elapsed_ms": round(e_ms, 2),
        "body_hash_changed": (
            bool(baseline.get("body_hash")) and bool(exploit.get("body_hash")) and baseline.get("body_hash") != exploit.get("body_hash")
        ),
        "baseline_body_hash": baseline.get("body_hash"),
        "exploit_body_hash": exploit.get("body_hash"),
        "baseline_error": baseline.get("error"),
        "exploit_error": exploit.get("error"),
    }

