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

__all__ = ["build_ast_graph", "load_cached_graph"]


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
    scan_id: int | str | None = None,
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
            未提供但设置了 ``scan_id`` 时，自动使用 workspace 共享 DB。
        scan_id: 扫描任务 ID。提供时把图保存到 ``workspace/<scan_id>/``
            并在 workspace DB 的 ``scans`` 表中登记。

    Returns:
        igraph.Graph 对象。无文件可处理时返回空图。
    """
    try:
        import igraph as ig
    except ImportError:
        logger.warning("[GraphPipeline] igraph not installed, skip graph building")
        return ig.Graph(directed=True)

    from core.graph.graph_builder import AstGraphBuilder

    # 未指定 db_path 但有 scan_id → 使用 workspace 共享 DB
    if db_path is None and scan_id:
        from core.graph.workspace import get_workspace_db
        db_path = get_workspace_db()

    builder = AstGraphBuilder()

    # 语言 → Normalizer 缓存，避免反复查询 registry
    normalizer_cache: dict[str, object] = {}

    processed_count = 0
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
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    source_content = f.read()
            except Exception:
                source_content = None
            result = normalizer.normalize(ast_nodes, filepath, source_content)
            if result is None:
                skipped_empty_ast += 1
                continue

            file_node, nodes, edges = result
            builder.add_file(file_node, nodes, edges)
            processed_count += 1

        except Exception as e:
            logger.warning(
                "[GraphPipeline] Failed to normalize %s (%s): %s",
                filepath, language, e,
            )
            errors += 1

    graph = builder.build()

    # ── 数据流分析（按语言分别运行） ──
    edge_count_before = graph.ecount()
    try:
        from core.graph.edge_builders import run_all

        detected_languages = [lang for lang, cls in normalizer_cache.items() if cls is not None]
        total_added = 0
        for lang in detected_languages:
            results = run_all(graph, language=lang)
            added = sum(results.values())
            total_added += added
            logger.info(
                "[GraphPipeline] Edge builders (%s): %s（+ %d edges）",
                lang, results, added,
            )
        logger.info(
            "[GraphPipeline] Edge builders 完成: 总边数 %d → %d（+ %d）",
            edge_count_before, graph.ecount(), total_added,
        )
    except Exception as e:
        logger.warning("[GraphPipeline] Edge builders 失败，跳过: %s", e)

    logger.info(
        "[GraphPipeline] Build complete: %d processed, "
        "%d no normalizer, %d empty AST, %d errors. "
        "Graph: %d nodes, %d edges",
        processed_count, skipped_no_normalizer, skipped_empty_ast, errors,
        graph.vcount(), graph.ecount(),
    )

    # ── 可选持久化 ──

    if graph_dir and processed_count > 0:
        try:
            from core.graph.graph_io import AstGraphIO
            io = AstGraphIO(graph_dir)
            io.save(graph)
            logger.info("[GraphPipeline] Graph saved to %s", io.graph_path)
        except Exception as e:
            logger.warning("[GraphPipeline] Failed to save graph: %s", e)

    if db_path and processed_count > 0:
        try:
            from core.graph.sqlite_index import AstNodeIndex, FileHash

            # 确保 workspace 目录存在
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

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
                    file_hash.update_hash(filepath, content_hash, language, scan_id=scan_id or 0)

                    # 更新节点索引
                    all_index_nodes = [file_node] + nodes
                    node_index.upsert_nodes(filepath, all_index_nodes, scan_id=scan_id or 0)

                except Exception:
                    continue

            logger.info("[GraphPipeline] SQLite index updated")

        except Exception as e:
            logger.warning("[GraphPipeline] Failed to update SQLite index: %s", e)

    # 保存图到 workspace/<scan_id>/
    if graph.vcount() > 0 and scan_id:
        try:
            from core.graph.workspace import ensure_scan_dir, get_workspace_db
            from core.graph.graph_io import AstGraphIO
            from core.graph.sqlite_index import ScanRecord
            scan_dir = ensure_scan_dir(scan_id)
            gio = AstGraphIO(scan_dir)
            meta = gio.save(graph)
            sr = ScanRecord(get_workspace_db())
            sr.upsert(
                scan_id=scan_id,
                language=pretreatment.lan[0] if pretreatment.lan else None,
                target=pretreatment.target_directory,
                graph_path=meta["file_path"],
                file_count=processed_count,
                node_count=graph.vcount(),
                edge_count=graph.ecount(),
            )
            logger.info("[GraphPipeline] Graph saved to %s (%d nodes, %d edges)",
                       scan_dir, graph.vcount(), graph.ecount())
        except Exception as e:
            logger.warning("[GraphPipeline] Failed to save graph: %s", e)

    return graph


# ---------------------------------------------------------------------------
# load_cached_graph
# ---------------------------------------------------------------------------

def load_cached_graph(target: str) -> "igraph.Graph | None":
    """尝试从 workspace 中加载同一 target 的缓存图。

    查找逻辑：
      1. 查 workspace kunlun.db 的 scans 表，找 target 匹配的最新记录
      2. 验证 graphmlz 文件存在且 content_hash 一致（AstGraphIO.load 内置校验）
      3. 检查源文件是否有变动（对比 FileHash 表中记录的 MD5 与当前文件 MD5）
      4. 全部通过 → 返回加载的图
      5. 任一不通过 → 返回 None（打印 warning）

    Args:
        target: 扫描目标路径。

    Returns:
        igraph.Graph 对象；无缓存 / 缓存失效 / 文件变动时返回 ``None``。
    """
    try:
        import igraph as ig
    except ImportError:
        return None

    from core.graph.workspace import get_workspace_db
    from core.graph.graph_io import AstGraphIO
    from core.graph.sqlite_index import ScanRecord, FileHash

    db_path = get_workspace_db()
    if not os.path.isfile(db_path):
        logger.debug("[GraphPipeline] No workspace DB, skip cache loading")
        return None

    # 1. 查 scans 表找同 target 的最新记录
    sr = ScanRecord(db_path)
    record = sr.get_by_target(target)
    if not record:
        logger.debug("[GraphPipeline] No cached scan for target: %s", target)
        return None

    graph_path = record.get("graph_path")
    if not graph_path or not os.path.isfile(graph_path):
        logger.warning("[GraphPipeline] Cached graph file missing: %s", graph_path)
        return None

    # 2. 加载图（AstGraphIO.load 会验证 content_hash）
    graph_dir = os.path.dirname(graph_path)
    gio = AstGraphIO(graph_dir)
    graph = gio.load()
    if graph is None:
        logger.warning("[GraphPipeline] Cached graph failed hash validation: %s", graph_path)
        return None

    # 3. 检查源文件是否有变动（仅检查该 scan 关联的文件）
    fh = FileHash(db_path)
    cached_scan_id = record.get("id", 0)
    all_hashes = fh.get_hashes_by_scan_id(cached_scan_id)
    changed_files = []
    for filepath, stored_hash in all_hashes.items():
        if not os.path.isfile(filepath):
            changed_files.append(filepath)
            continue
        current_hash = _compute_file_hash(filepath)
        if current_hash != stored_hash:
            changed_files.append(filepath)

    if changed_files:
        logger.info(
            "[GraphPipeline] Cache invalidated: %d file(s) changed since cached scan %s",
            len(changed_files), record.get("id"),
        )
        for fp in changed_files[:5]:
            logger.debug("  changed: %s", fp)
        if len(changed_files) > 5:
            logger.debug("  ... and %d more", len(changed_files) - 5)
        return None

    logger.info(
        "[GraphPipeline] Loaded cached graph from scan %s: %d nodes, %d edges",
        record.get("id"), graph.vcount(), graph.ecount(),
    )
    return graph
