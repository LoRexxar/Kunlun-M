"""AST Graph Pipeline — 将 Pretreatment 的 AST 预处理结果构建为统一 IR 图。

调用时机：在 ``ast_object.pre_ast_all()`` 完成之后。
只处理已有 Normalizer 实现的语言，其余语言静默跳过。

用法::

    from core.pretreatment import ast_object
    from core.graph.graph_pipeline import build_ast_graph

    ast_object.init_pre(target_directory, files)
    ast_object.pre_ast_all(main_language)

    graph = build_ast_graph(ast_object, graph_dir="./graph_cache")
"""

from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

from utils.log import logger

if TYPE_CHECKING:
    from core.pretreatment import Pretreatment

__all__ = ["build_ast_graph"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_file_hash(filepath: str) -> str:
    """计算文件内容的 MD5 哈希。"""
    h = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _try_get_normalizer(language: str):
    """尝试获取语言的 Normalizer 类。

    优先走 registry（``normalizers/__init__.py``），失败则静默返回 None。

    Args:
        language: 语言标识（php / javascript / java / python / go / c）。

    Returns:
        Normalizer **类**（不是实例），或 None。
    """
    try:
        from core.graph.normalizers import get_normalizer
        return get_normalizer(language)
    except (KeyError, ImportError):
        return None


# ---------------------------------------------------------------------------
# build_ast_graph
# ---------------------------------------------------------------------------

def build_ast_graph(
    pretreatment: Pretreatment,
    graph_dir: str | None = None,
    db_path: str | None = None,
):
    """从 Pretreatment 的 ``pre_result`` 构建 AST 图。

    完整流程：

        1. 遍历 ``pretreatment.pre_result``
        2. 对每个文件检查是否有 Normalizer
        3. 有 → 调用 ``Normalizer().normalize(ast_nodes, filepath)``
        4. 通过 ``AstGraphBuilder`` 组装为 igraph Graph
        5. （可选）保存 ``.graphmlz`` + 更新 SQLite 索引

    Args:
        pretreatment: Pretreatment 单例实例（``ast_object``）。
        graph_dir: 图文件输出目录。提供时保存 ``.graphmlz``。
        db_path: SQLite 数据库路径。提供时更新节点索引和文件哈希。

    Returns:
        igraph.Graph 对象。无文件可处理时返回空图。
    """
    try:
        import igraph as ig
    except ImportError:
        logger.warning("[GraphPipeline] igraph not installed, skip graph building")
        return ig.Graph(directed=True)

    from core.graph.graph_builder import AstGraphBuilder

    builder = AstGraphBuilder()

    # 语言 → Normalizer 缓存，避免反复查询 registry
    normalizer_cache: dict[str, object] = {}

    processed = 0
    skipped_no_normalizer = 0
    skipped_empty_ast = 0
    errors = 0

    for filepath, file_data in pretreatment.pre_result.items():
        language = file_data.get("language", "")
        ast_nodes = file_data.get("ast_nodes")

        if not ast_nodes:
            skipped_empty_ast += 1
            continue

        # 获取 Normalizer 类
        norm_cls = normalizer_cache.get(language)
        if norm_cls is None:
            norm_cls = _try_get_normalizer(language)
            normalizer_cache[language] = norm_cls

        if norm_cls is None:
            skipped_no_normalizer += 1
            continue

        try:
            normalizer = norm_cls()
            # PHP Normalizer 接口: normalize(ast_nodes, file_path, source_content=None)
            result = normalizer.normalize(ast_nodes, filepath)
            if result is None:
                skipped_empty_ast += 1
                continue

            file_node, nodes, edges = result
            builder.add_file(file_node, nodes, edges)
            processed += 1

        except Exception as e:
            logger.warning(
                "[GraphPipeline] Failed to normalize %s (%s): %s",
                filepath, language, e,
            )
            errors += 1

    graph = builder.build()

    # ── 数据流分析 ──
    edge_count_before = graph.ecount()
    try:
        from core.graph.dataflow_analyzer import DataFlowAnalyzer

        # TODO: 从处理文件中自动检测语言
        analyzer = DataFlowAnalyzer(graph)
        dfg_added = analyzer.analyze(language="php")
        logger.info(
            "[GraphPipeline] DFG 分析完成: 新增 %d 条 dfg 边（总边数: %d → %d）",
            dfg_added, edge_count_before, graph.ecount(),
        )
    except Exception as e:
        logger.warning("[GraphPipeline] DFG 分析失败，跳过: %s", e)

    logger.info(
        "[GraphPipeline] Build complete: %d processed, "
        "%d no normalizer, %d empty AST, %d errors. "
        "Graph: %d nodes, %d edges",
        processed, skipped_no_normalizer, skipped_empty_ast, errors,
        graph.vcount(), graph.ecount(),
    )

    # ── 可选持久化 ──

    if graph_dir and processed > 0:
        try:
            from core.graph.graph_io import AstGraphIO
            io = AstGraphIO(graph_dir)
            io.save(graph)
            logger.info("[GraphPipeline] Graph saved to %s", io.graph_path)
        except Exception as e:
            logger.warning("[GraphPipeline] Failed to save graph: %s", e)

    if db_path and processed > 0:
        try:
            from core.graph.sqlite_index import AstNodeIndex, FileHash

            node_index = AstNodeIndex(db_path)
            node_index.ensure_tables()

            file_hash = FileHash(db_path)
            file_hash.ensure_tables()

            for filepath, file_data in pretreatment.pre_result.items():
                language = file_data.get("language", "")
                norm_cls = normalizer_cache.get(language)
                if norm_cls is None:
                    continue

                ast_nodes = file_data.get("ast_nodes")
                if not ast_nodes:
                    continue

                try:
                    result = norm_cls().normalize(ast_nodes, filepath)
                    if result is None:
                        continue
                    file_node, nodes, _ = result

                    # 更新文件哈希
                    content_hash = _compute_file_hash(filepath)
                    file_hash.update_hash(filepath, content_hash, language)

                    # 更新节点索引
                    all_index_nodes = [file_node] + nodes
                    node_index.upsert_nodes(filepath, all_index_nodes)

                except Exception:
                    continue

            logger.info("[GraphPipeline] SQLite index updated")

        except Exception as e:
            logger.warning("[GraphPipeline] Failed to update SQLite index: %s", e)

    return graph
