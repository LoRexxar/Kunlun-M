"""AST 节点 SQLite 索引 — 快速定位 5 种高频节点类型。

不使用 Django ORM，直接用 ``sqlite3`` 操作 ``kunlun.db``，避免 Django
models 迁移的复杂性。所有写操作使用事务（``with conn:``）。

两张表：

    ``ast_node_index`` — 仅索引 file / class / function / operator / import
    五种节点，用于跨文件快速查询（类定义、函数定义、调用点等）。

    ``file_hash`` — 记录每个文件的内容哈希（MD5），用于增量更新判断
    （只对变化的文件重新解析）。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

__all__ = ["AstNodeIndex", "FileHash"]


def _iso_now() -> str:
    """返回当前 UTC 时间的 ISO 格式时间戳。"""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# ---------------------------------------------------------------------------
# 建表 SQL
# ---------------------------------------------------------------------------

_AST_NODE_INDEX_DDL = """
CREATE TABLE IF NOT EXISTS ast_node_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    node_label TEXT NOT NULL,
    node_name TEXT,
    lineno INTEGER NOT NULL,
    language TEXT NOT NULL,
    extra TEXT
);
"""

_AST_NODE_INDEX_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_ani_file_label ON ast_node_index(file_path, node_label);",
    "CREATE INDEX IF NOT EXISTS idx_ani_label_name ON ast_node_index(node_label, node_name);",
]

_FILE_HASH_DDL = """
CREATE TABLE IF NOT EXISTS file_hash (
    file_path TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    language TEXT NOT NULL,
    scan_time TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# AstNodeIndex
# ---------------------------------------------------------------------------

class AstNodeIndex:
    """AST 核心节点快速索引 — 仅存储 5 种高频查询的节点类型。

    仅对 ``INDEXED_LABELS`` 中的节点建立索引（file / class / function /
    operator / import），用于跨文件快速定位类定义、函数定义、调用点等。
    其余节点类型（parameter / return / identifier / const / branch /
    annotation / dependency）不入索引表，仍保留在 igraph 图中。
    """

    #: 允许建索引的 5 种节点类型
    INDEXED_LABELS = {"file", "class", "function", "operator", "import"}

    def __init__(self, db_path: str):
        """
        Args:
            db_path: SQLite 数据库文件路径，如 ``db/kunlun.db``。
        """
        self._db_path = db_path

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接，设置 ``row_factory = sqlite3.Row``。"""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_tables(self) -> None:
        """确保索引表存在（``CREATE TABLE IF NOT EXISTS`` + 索引）。"""
        with self._get_conn() as conn:
            conn.execute(_AST_NODE_INDEX_DDL)
            for stmt in _AST_NODE_INDEX_INDEXES:
                conn.execute(stmt)

    def upsert_nodes(self, file_path: str, nodes: list[dict]) -> None:
        """批量写入/更新节点的索引。

        流程：先删除该 ``file_path`` 的所有旧索引记录，再批量插入新节点。
        仅处理 ``INDEXED_LABELS`` 中的节点类型，其余忽略。

        Args:
            file_path: 文件路径。
            nodes: 节点列表，每个节点是 dict，至少包含以下字段：

                - ``label`` (str): 节点类型。
                - ``name`` (str|None): 节点名称。
                - ``lineno`` (int): 行号。
                - ``language`` (str): 语言标识。
                - ``attrs`` (dict|None): 额外属性，将以 JSON 序列化到
                  ``extra`` 列。
        """
        self.ensure_tables()

        rows = []
        for n in nodes:
            label = n.get("label")
            if label not in self.INDEXED_LABELS:
                continue
            attrs = n.get("attrs") or {}
            extra = json.dumps(attrs, ensure_ascii=False) if attrs else None
            rows.append((
                file_path,
                label,
                n.get("name"),
                int(n.get("lineno", 0) or 0),
                n.get("language", ""),
                extra,
            ))

        with self._get_conn() as conn:
            conn.execute(
                "DELETE FROM ast_node_index WHERE file_path = ?",
                (file_path,),
            )
            if rows:
                conn.executemany(
                    """
                    INSERT INTO ast_node_index
                        (file_path, node_label, node_name, lineno, language, extra)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

    def query_by_file(self, file_path: str, node_label: str = None) -> list[dict]:
        """查询某文件的节点索引。

        Args:
            file_path: 文件路径。
            node_label: 可选，按节点类型过滤。

        Returns:
            匹配的节点列表，每个是 dict，包含 ``id`` / ``file_path`` /
            ``node_label`` / ``node_name`` / ``lineno`` / ``language`` /
            ``extra``（自动反序列化为 dict）。
        """
        sql = "SELECT * FROM ast_node_index WHERE file_path = ?"
        params: list = [file_path]
        if node_label is not None:
            sql += " AND node_label = ?"
            params.append(node_label)

        with self._get_conn() as conn:
            cur = conn.execute(sql, params)
            return [_row_to_node_dict(r) for r in cur.fetchall()]

    def query_by_name(self, node_name: str, node_label: str = None) -> list[dict]:
        """全局搜索：某名称的节点在哪些文件中定义。

        Args:
            node_name: 节点名称。
            node_label: 可选，按节点类型过滤。

        Returns:
            匹配的节点列表（字段同 :meth:`query_by_file`）。
        """
        sql = "SELECT * FROM ast_node_index WHERE node_name = ?"
        params: list = [node_name]
        if node_label is not None:
            sql += " AND node_label = ?"
            params.append(node_label)

        with self._get_conn() as conn:
            cur = conn.execute(sql, params)
            return [_row_to_node_dict(r) for r in cur.fetchall()]

    def delete_by_file(self, file_path: str) -> int:
        """删除某文件的所有索引记录。

        Args:
            file_path: 文件路径。

        Returns:
            删除的行数。
        """
        with self._get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM ast_node_index WHERE file_path = ?",
                (file_path,),
            )
            return cur.rowcount

    def clear_all(self) -> None:
        """清空所有索引数据。"""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM ast_node_index")


# ---------------------------------------------------------------------------
# FileHash
# ---------------------------------------------------------------------------

class FileHash:
    """文件内容哈希 — 用于增量更新判断。

    记录每个被解析过的文件的 MD5 哈希。下次扫描时对比当前哈希与数据库
    哈希，仅对变化的文件重新解析和更新索引，避免重复工作。
    """

    def __init__(self, db_path: str):
        """
        Args:
            db_path: SQLite 数据库文件路径，如 ``db/kunlun.db``。
        """
        self._db_path = db_path

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接，设置 ``row_factory = sqlite3.Row``。"""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_tables(self) -> None:
        """确保表存在（``CREATE TABLE IF NOT EXISTS``）。"""
        with self._get_conn() as conn:
            conn.execute(_FILE_HASH_DDL)

    def update_hash(self, file_path: str, content_hash: str, language: str) -> None:
        """更新/插入文件哈希。

        使用 ``INSERT OR REPLACE`` 语义：已存在则覆盖，不存在则插入。
        ``scan_time`` 自动设为当前 ISO 格式时间戳。

        Args:
            file_path: 文件路径（主键）。
            content_hash: 文件内容 MD5 哈希。
            language: 语言标识（php/javascript/java/python/go/c）。
        """
        self.ensure_tables()
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_hash
                    (file_path, content_hash, language, scan_time)
                VALUES (?, ?, ?, ?)
                """,
                (file_path, content_hash, language, _iso_now()),
            )

    def get_hash(self, file_path: str) -> str | None:
        """获取某文件的内容哈希。

        Args:
            file_path: 文件路径。

        Returns:
            content_hash 字符串；不存在返回 ``None``。
        """
        with self._get_conn() as conn:
            cur = conn.execute(
                "SELECT content_hash FROM file_hash WHERE file_path = ?",
                (file_path,),
            )
            row = cur.fetchone()
            return row["content_hash"] if row else None

    def get_all_hashes(self) -> dict[str, str]:
        """获取所有文件哈希。

        Returns:
            ``{file_path: content_hash}`` 字典。
        """
        with self._get_conn() as conn:
            cur = conn.execute("SELECT file_path, content_hash FROM file_hash")
            return {row["file_path"]: row["content_hash"] for row in cur.fetchall()}

    def get_changed_files(self, current_hashes: dict[str, str]) -> list[str]:
        """对比当前文件哈希与数据库中的哈希，返回有变化的文件列表。

        包括两类：
            - 新增文件（数据库中不存在）；
            - 内容变化的文件（哈希不一致）。

        Args:
            current_hashes: ``{file_path: content_hash}``。

        Returns:
            需要重新处理的文件路径列表。
        """
        existing = self.get_all_hashes()
        changed: list[str] = []
        for file_path, content_hash in current_hashes.items():
            db_hash = existing.get(file_path)
            if db_hash is None or db_hash != content_hash:
                changed.append(file_path)
        return changed

    def delete_by_file(self, file_path: str) -> bool:
        """删除某文件的哈希记录。

        Args:
            file_path: 文件路径。

        Returns:
            是否删除成功（即确实删除了一行）。
        """
        with self._get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM file_hash WHERE file_path = ?",
                (file_path,),
            )
            return cur.rowcount > 0

    def clear_all(self) -> None:
        """清空所有哈希数据。"""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM file_hash")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_node_dict(row: sqlite3.Row) -> dict:
    """将 sqlite3.Row 转为 dict，并把 ``extra`` 反序列化。

    Args:
        row: ``ast_node_index`` 表的一行。

    Returns:
        包含全部字段的 dict，``extra`` 自动 ``json.loads`` 为 dict；
        ``extra`` 为空时设为空 dict。
    """
    d = dict(row)
    extra = d.get("extra")
    if extra:
        try:
            d["extra"] = json.loads(extra)
        except (json.JSONDecodeError, TypeError):
            d["extra"] = {}
    else:
        d["extra"] = {}
    return d
