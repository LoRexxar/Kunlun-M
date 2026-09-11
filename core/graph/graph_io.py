"""AST Graph I/O — 持久化 igraph 图到 gzip pickle 文件。

通过 meta.json 记录文件元信息（节点数、边数、内容哈希等），
用于完整性校验和缓存过期判断。纯 Python 实现，不依赖 Django。
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime

__all__ = ["AstGraphIO"]


def _iso_now() -> str:
    """返回当前 UTC 时间的 ISO 格式时间戳。"""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _md5_file(path: str) -> str:
    """计算文件二进制内容的 MD5 哈希。"""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _sanitize_graph_attrs(graph: "igraph.Graph") -> None:  # type: ignore[name-defined]
    """清理图节点/边属性中的控制字符，防止 GraphML 写入失败。

    GraphML 格式禁止 XML 1.0 控制字符（0x00-0x1F 除了 0x09/0x0A/0x0D）。
    将非法字符替换为 '�'（U+FFFD REPLACEMENT CHARACTER）。
    """
    import re
    _ctrl_pat = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    for attr_name in graph.vertex_attributes():
        vals = graph.vs[attr_name]
        cleaned = []
        for v in vals:
            if isinstance(v, str) and _ctrl_pat.search(v):
                cleaned.append(_ctrl_pat.sub("\ufffd", v))
            else:
                cleaned.append(v)
        graph.vs[attr_name] = cleaned
    for attr_name in graph.edge_attributes():
        vals = graph.es[attr_name]
        cleaned = []
        for v in vals:
            if isinstance(v, str) and _ctrl_pat.search(v):
                cleaned.append(_ctrl_pat.sub("\ufffd", v))
            else:
                cleaned.append(v)
        graph.es[attr_name] = cleaned


class AstGraphIO:
    """igraph 图的持久化和加载。

    将 igraph.Graph 保存为 gzip 压缩的 pickle（``.pkz``），
    并在 ``meta.json`` 中记录节点/边数量、内容哈希、保存时间等元信息。
    加载时验证 meta.json 中的哈希与文件实际 MD5 是否匹配，
    防止加载损坏的图文件。

    加载时优先使用新格式 ``.pkz``；不存在时回退到旧的 ``.graphmlz``。
    """

    def __init__(self, graph_dir: str):
        """
        Args:
            graph_dir: 存放图文件的目录路径。
        """
        self.graph_dir = graph_dir
        # New format: gzip pickle (.pkz). Falls back to legacy .graphmlz on load.
        self.graph_path = os.path.join(graph_dir, "graph.pkz")
        self.legacy_path = os.path.join(graph_dir, "graph.graphmlz")
        self.meta_path = os.path.join(graph_dir, "meta.json")

    def save(self, graph: "igraph.Graph") -> dict:  # type: ignore[name-defined]
        """保存图到 gzip pickle 文件并更新 meta.json。

        保存流程：
            1. 确保目录存在；
            2. 用 gzip + pickle (HIGHEST_PROTOCOL) 将 graph 写入 ``graph_path``；
            3. 计算文件 MD5 作为 ``content_hash``；
            4. 写入 meta.json（file_path / node_count / edge_count /
               content_hash / save_time / file_size）。

        pickle 能直接序列化任意字符串属性值，无需像 GraphML 那样清理
        XML 控制字符，避免遍历所有顶点/边属性带来的内存峰值。

        Args:
            graph: 待保存的 igraph.Graph 对象。

        Returns:
            写入的 meta 字典。
        """
        import gzip
        import pickle

        os.makedirs(self.graph_dir, exist_ok=True)

        # gzip + pickle: no need for XML control char sanitization
        with gzip.open(self.graph_path, "wb") as f:
            pickle.dump(graph, f, protocol=pickle.HIGHEST_PROTOCOL)

        content_hash = _md5_file(self.graph_path)
        file_size = os.path.getsize(self.graph_path)

        meta = {
            "file_path": self.graph_path,
            "node_count": graph.vcount(),
            "edge_count": graph.ecount(),
            "content_hash": content_hash,
            "save_time": _iso_now(),
            "file_size": file_size,
        }

        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

        return meta

    def load(self) -> "igraph.Graph | None":  # type: ignore[name-defined]
        """从文件加载图。

        加载前会先验证 meta.json 中记录的 ``content_hash`` 与文件实际
        MD5 是否一致。不匹配时打印 warning 并返回 ``None``，避免加载
        损坏或被篡改的图文件。

        优先加载新格式 ``.pkz``；若不存在则回退到旧格式 ``.graphmlz``。

        Returns:
            igraph.Graph 对象；文件不存在、meta 缺失或哈希不匹配时
            返回 ``None``。
        """
        if not self.exists():
            return None

        # Prefer new pickle format; fall back to legacy GraphMLz
        if os.path.isfile(self.graph_path):
            active_path = self.graph_path
            active_loader = self._load_pickle
        elif os.path.isfile(self.legacy_path):
            active_path = self.legacy_path
            active_loader = self._load_graphmlz
        else:
            return None

        meta = self.get_meta()
        if meta is None:
            print(f"[AstGraphIO] warning: meta.json missing, skip loading {active_path}")
            return None

        actual_hash = _md5_file(active_path)
        expected_hash = meta.get("content_hash")
        if not expected_hash or actual_hash != expected_hash:
            print(
                f"[AstGraphIO] warning: content_hash mismatch "
                f"(expected={expected_hash}, actual={actual_hash}), "
                f"file may be corrupted: {active_path}"
            )
            return None

        try:
            import igraph as ig  # noqa: F401
        except ImportError:
            raise ImportError(
                "igraph is required for graph loading. "
                "Install it with: pip install python-igraph"
            )

        return active_loader(active_path)

    @staticmethod
    def _load_graphmlz(path: str) -> "igraph.Graph":
        """加载 GraphMLz 文件，静默 igraph 内部 vertex id 冲突 warning。"""
        import warnings
        import igraph as ig
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Could not add vertex ids")
            return ig.Graph.Read_GraphMLz(path)

    @staticmethod
    def _load_pickle(path: str) -> "igraph.Graph":
        """加载 gzip pickle 格式的图文件。"""
        import gzip
        import pickle
        with gzip.open(path, "rb") as f:
            return pickle.load(f)

    def exists(self) -> bool:
        """判断图文件是否存在（新格式或旧格式）。"""
        return os.path.isfile(self.graph_path) or os.path.isfile(self.legacy_path)

    def delete(self) -> bool:
        """删除图文件和 meta.json。

        Returns:
            是否成功删除（任一文件存在并被删除即返回 ``True``）。
        """
        ok = False
        for path in (self.graph_path, self.legacy_path, self.meta_path):
            if os.path.isfile(path):
                try:
                    os.remove(path)
                    ok = True
                except OSError as e:
                    print(f"[AstGraphIO] warning: failed to remove {path}: {e}")
        return ok

    def file_size(self) -> int:
        """返回图文件大小（字节）。

        优先返回新格式 ``.pkz`` 的大小；不存在时返回旧格式大小。

        Returns:
            文件大小；不存在时返回 0。
        """
        if not self.exists():
            return 0
        if os.path.isfile(self.graph_path):
            return os.path.getsize(self.graph_path)
        return os.path.getsize(self.legacy_path)

    def is_stale(self, file_hash: str) -> bool:
        """判断缓存图是否过期。

        过期判断逻辑：
            1. 图文件不存在 → 返回 ``True``（需要构建）；
            2. 与 meta.json 中记录的 ``content_hash`` 不一致 → 返回 ``True``。

        Args:
            file_hash: 项目的当前文件哈希（任意字符串，只要项目文件有
                变化即不同即可）。

        Returns:
            ``True`` 表示需要重新构建；``False`` 表示缓存有效。
        """
        if not self.exists():
            return True

        meta = self.get_meta()
        if meta is None:
            return True

        return meta.get("content_hash") != file_hash

    def get_meta(self) -> dict | None:
        """读取 meta.json。

        Returns:
            meta 字典；文件不存在或解析失败时返回 ``None``。
        """
        if not os.path.isfile(self.meta_path):
            return None
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[AstGraphIO] warning: failed to read meta.json: {e}")
            return None
