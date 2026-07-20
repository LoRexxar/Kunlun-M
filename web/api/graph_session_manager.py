"""进程级 Graph Session 管理器。

在 gunicorn worker 进程生命周期内缓存 AstGraphSession，
避免每次 API 请求都重新加载全量图。

提供:
    - load: 加载并缓存 session
    - get: 获取已缓存的 session（不加载）
    - release: 释放 session 回收内存
    - session_info: 返回当前状态信息
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

# 进程级单例
_sessions: dict[int, Any] = {}  # scan_id → AstGraphSession
_load_times: dict[int, float] = {}  # scan_id → load timestamp
_last_access: dict[int, float] = {}  # scan_id → last access timestamp
_IDLE_TIMEOUT = 30 * 60  # 30 分钟无操作自动释放


def _require_session():
    """延迟导入避免循环依赖。"""
    from core.graph.session import AstGraphSession
    return AstGraphSession


def load_session(scan_id: int) -> tuple[Any | None, str | None]:
    """加载 scan 对应的 graph session 并缓存。

    Returns (session, error_message)。
    成功时 session 可用，失败时 session=None, error_message 描述原因。
    """
    # 已加载，直接复用
    if scan_id in _sessions and _sessions[scan_id].is_loaded:
        _last_access[scan_id] = time.time()
        return _sessions[scan_id], None

    # 检查 graph 文件是否存在
    from core.graph.workspace import get_scan_dir
    from core.graph.workspace import get_workspace_db
    from core.graph.sqlite_index import ScanRecord

    graph_dir = get_scan_dir(scan_id)
    graph_path = os.path.join(graph_dir, "graph.graphmlz")
    if not os.path.exists(graph_path):
        return None, f"Graph not found for scan {scan_id}"

    workspace_db = get_workspace_db()
    sr = ScanRecord(workspace_db)
    info = sr.get_by_id(scan_id)
    language = info.get("language", "php") if info else "php"

    # 如果当前有其他 session，先释放（内存有限，只保留一个）
    _release_all()

    # 内存预检：确保有足够的可用内存加载图
    # igraph 加载 graphmlz 大约需要文件大小 × 100-150 倍的内存
    # 预留安全余量：至少需要 500MB 可用内存才能尝试加载
    try:
        import psutil
        mem = psutil.virtual_memory()
        available_mb = mem.available // (1024 * 1024)
        if available_mb < 512:
            return None, (
                f"Insufficient memory to load graph (available: {available_mb}MB, "
                f"need at least 512MB). Please try again later or upgrade the server."
            )
        logger.info("Memory check: available=%dMB, total=%dMB", available_mb, mem.total // (1024 * 1024))
    except ImportError:
        logger.warning("psutil not available, skipping memory check")

    try:
        AstGraphSession = _require_session()
        session = AstGraphSession(graph_dir, db_path=workspace_db, language=language)
        session.load()

        _sessions[scan_id] = session
        _load_times[scan_id] = time.time()
        _last_access[scan_id] = time.time()

        node_count = session.graph.vcount()
        edge_count = session.graph.ecount()
        logger.info(
            "Graph session loaded: scan_id=%d, nodes=%d, edges=%d",
            scan_id, node_count, edge_count,
        )
        return session, None
    except Exception as e:
        logger.error("Failed to load graph session for scan %d: %s", scan_id, e)
        return None, str(e)


def get_session(scan_id: int) -> Any | None:
    """获取已缓存的 session，未加载返回 None。"""
    # 检查空闲超时
    if scan_id in _sessions:
        if time.time() - _last_access.get(scan_id, 0) > _IDLE_TIMEOUT:
            logger.info("Session %d idle timeout, auto-releasing", scan_id)
            _release_one(scan_id)
        else:
            _last_access[scan_id] = time.time()
            return _sessions.get(scan_id)
    return None


def release_session(scan_id: int) -> bool:
    """主动释放指定 scan 的 session。"""
    return _release_one(scan_id)


def _release_one(scan_id: int) -> bool:
    """释放单个 session。"""
    if scan_id in _sessions:
        try:
            _sessions[scan_id].close()
        except Exception:
            pass
        del _sessions[scan_id]
        _load_times.pop(scan_id, None)
        _last_access.pop(scan_id, None)
        logger.info("Graph session released: scan_id=%d", scan_id)
        return True
    return False


def _release_all() -> None:
    """释放所有 session。"""
    for sid in list(_sessions.keys()):
        _release_one(sid)


def session_info() -> dict[str, Any]:
    """返回当前所有 session 的状态信息。"""
    # 先清理超时的
    for sid in list(_sessions.keys()):
        if time.time() - _last_access.get(sid, 0) > _IDLE_TIMEOUT:
            _release_one(sid)

    result = {
        "loaded": [],
        "idle_timeout_minutes": _IDLE_TIMEOUT // 60,
    }
    for sid, sess in _sessions.items():
        info = {
            "scan_id": sid,
            "is_loaded": sess.is_loaded,
            "loaded_at": _load_times.get(sid),
            "last_access": _last_access.get(sid),
            "idle_seconds": int(time.time() - _last_access.get(sid, time.time())),
        }
        try:
            if sess.is_loaded:
                info["node_count"] = sess.graph.vcount()
                info["edge_count"] = sess.graph.ecount()
        except Exception:
            info["node_count"] = None
            info["edge_count"] = None
        result["loaded"].append(info)
    return result
