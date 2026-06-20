"""Workspace 管理 — 统一的扫描产出存储。

所有扫描产物都归入 ``BASE_DIR/workspace/``：

    workspace/
        kunlun.db              # 共享 SQLite（ast_node_index + file_hash + scans）
        <scan_id>/             # 例: 42
            graph.graphmlz     # 图持久化
            meta.json          # 元数据
"""

from __future__ import annotations

import os

from Kunlun_M.settings import BASE_DIR

__all__ = [
    "WORKSPACE_ROOT",
    "get_scan_dir",
    "ensure_scan_dir",
    "get_workspace_db",
]


WORKSPACE_ROOT = os.path.join(BASE_DIR, "workspace")


def get_scan_dir(scan_id: int | str) -> str:
    """返回 ``workspace/<scan_id>/`` 目录路径（不创建）。"""
    return os.path.join(WORKSPACE_ROOT, str(scan_id))


def ensure_scan_dir(scan_id: int | str) -> str:
    """确保 ``workspace/<scan_id>/`` 目录存在，返回路径。"""
    path = get_scan_dir(scan_id)
    os.makedirs(path, exist_ok=True)
    return path


def get_workspace_db() -> str:
    """返回 ``workspace/kunlun.db`` 的路径。"""
    return os.path.join(WORKSPACE_ROOT, "kunlun.db")
