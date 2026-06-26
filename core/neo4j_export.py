# -*- coding: utf-8 -*-
"""
core.neo4j_export
~~~~~~~~~~~~~~~~~~

将 KunLun-M 的 igraph AST 图导出到 Neo4j 图数据库。

CLI 用法:
    python kunlun.py export-neo4j -p <project_id_or_name> [options]
    python kunlun.py export-neo4j -s <scan_id> [options]

选项:
    --neo4j-uri <uri>       Neo4j 连接 URI (默认: settings.NEO4J_URI)
    --neo4j-user <user>     Neo4j 用户名 (默认: settings.NEO4J_USER)
    --neo4j-password <pwd>  Neo4j 密码 (默认: settings.NEO4J_PASSWORD)
    --clean                 导出前清空 KunlunM 相关节点
    --batch-size <n>        批量写入大小 (默认: 500)

数据映射:
    igraph vertex.label  →  Neo4j :KunlunFile/:KunlunFunction/:KunlunOperator/...
    igraph edge.label    →  Neo4j :CONTAINS/:CALLS/:DATA_FLOW/:AST_CHILD/...
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kunlun")

# ---------------------------------------------------------------------------
# Label / Relationship 映射表
# ---------------------------------------------------------------------------

# igraph vertex.label → Neo4j Label
NODE_LABEL_MAP = {
    "file": "KunlunFile",
    "class": "KunlunClass",
    "function": "KunlunFunction",
    "parameter": "KunlunParameter",
    "return": "KunlunReturn",
    "identifier": "KunlunIdentifier",
    "const": "KunlunConst",
    "operator": "KunlunOperator",
    "branch": "KunlunBranch",
    "import": "KunlunImport",
    "annotation": "KunlunAnnotation",
    "dependency": "KunlunDependency",
}

# igraph edge.label → Neo4j relationship type
EDGE_TYPE_MAP = {
    "own": "CONTAINS",
    "cg": "CALLS",
    "dfg": "DATA_FLOW",
    "ast": "AST_CHILD",
    "use": "USES",
    "frg": "FILE_REF",
    "member": "MEMBER_ACCESS",
    "crg": "CLASS_RELATION",
    "alias": "ALIAS",
}

# 所有 KunlunM Neo4j label（用于 --clean 清空）
ALL_KUNLUN_LABELS = list(NODE_LABEL_MAP.values())

# Vertex 通用属性
NODE_COMMON_ATTRS = {"label", "name", "language", "lineno", "end_lineno", "id"}

# Edge 通用属性
EDGE_COMMON_ATTRS = {"label", "source", "target"}


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _get_neo4j_config(uri=None, user=None, password=None):
    """获取 Neo4j 连接配置，CLI 参数优先于 settings。"""
    from django.conf import settings
    return {
        "uri": uri or getattr(settings, "NEO4J_URI", "bolt://localhost:7687"),
        "user": user or getattr(settings, "NEO4J_USER", "neo4j"),
        "password": password or getattr(settings, "NEO4J_PASSWORD", ""),
    }


def _find_scan_ids_for_project(project_id: int) -> List[int]:
    """查找项目下所有已完成的 scan ID 列表。"""
    from web.index.models import ScanTask
    scan_ids = list(
        ScanTask.objects.filter(
            project_id=project_id, is_finished=1
        ).values_list("id", flat=True)
    )
    # 筛选出有 graph 文件的
    workspace_root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "workspace",
    )
    result = []
    for sid in scan_ids:
        graph_path = os.path.join(workspace_root, str(sid), "graph.graphmlz")
        if os.path.exists(graph_path):
            result.append(sid)
    return result


def _resolve_project(project_ref: str) -> Optional[Dict[str, Any]]:
    """通过 ID 或名称查找项目。返回 dict 或 None。"""
    from web.index.models import Project
    try:
        p = Project.objects.get(id=int(project_ref))
    except (ValueError, Project.DoesNotExist):
        p = Project.objects.filter(project_name=project_ref).first()
    if not p:
        return None
    return {"id": p.id, "name": p.project_name, "hash": p.project_hash}


def _node_properties(v) -> Dict[str, Any]:
    """从 igraph vertex 提取 Neo4j 节点属性。"""
    props = {}
    for attr in v.attributes():
        if attr in NODE_COMMON_ATTRS:
            if attr == "lineno":
                val = v[attr]
                props["lineno"] = int(val) if val not in (None, "", 0, 0.0) else 0
            elif attr == "end_lineno":
                val = v[attr]
                props["end_lineno"] = int(val) if val not in (None, "", 0, 0.0) else 0
            elif attr == "id":
                props["vid"] = v[attr]  # 保留 igraph 内部 ID
            else:
                val = v[attr]
                if val not in (None, ""):
                    props[attr] = val
        else:
            # label-specific 属性
            val = v[attr]
            if val not in (None, ""):
                props[attr] = val
    return props


def _edge_properties(e) -> Dict[str, Any]:
    """从 igraph edge 提取 Neo4j 关系属性。"""
    props = {}
    for attr in e.attributes():
        if attr in EDGE_COMMON_ATTRS:
            continue  # source/target 由关系端点表示
        val = e[attr]
        if val not in (None, ""):
            props[attr] = val
    return props


# ---------------------------------------------------------------------------
# 核心导出逻辑
# ---------------------------------------------------------------------------

def export_to_neo4j(
    scan_ids: List[int],
    uri: str = None,
    user: str = None,
    password: str = None,
    clean: bool = False,
    batch_size: int = 500,
    project_name: str = "",
) -> Dict[str, Any]:
    """将指定 scan 的 igraph 图导出到 Neo4j。

    Args:
        scan_ids: 要导出的 scan ID 列表。
        uri: Neo4j URI（为空则用 settings）。
        user: Neo4j 用户名。
        password: Neo4j 密码。
        clean: 是否清空已有的 KunlunM 节点。
        batch_size: 批量写入大小。
        project_name: 项目名称（用于日志）。

    Returns:
        导出统计 report dict。

    Raises:
        ValueError: 连接失败或无有效图文件。
        ImportError: neo4j 驱动未安装。
    """
    try:
        from neo4j import GraphDatabase
    except ImportError:
        raise ImportError(
            "neo4j driver not installed. Run: pip install neo4j"
        )

    import igraph

    config = _get_neo4j_config(uri, user, password)
    workspace_root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "workspace",
    )

    # 连接 Neo4j
    logger.info("[NEO4J] Connecting to {}@{} ...".format(config["user"], config["uri"]))
    driver = GraphDatabase.driver(
        config["uri"],
        auth=(config["user"], config["password"]),
    )
    # 验证连接
    try:
        with driver.session() as session:
            session.run("RETURN 1")
    except Exception as e:
        driver.close()
        raise ValueError("Neo4j connection failed: {}".format(e))

    total_nodes = 0
    total_edges = 0
    total_scans = 0

    try:
        with driver.session() as session:
            # 1. 清空（可选）
            if clean:
                logger.info("[NEO4J] Cleaning existing KunlunM nodes ...")
                for label in ALL_KUNLUN_LABELS:
                    session.run("MATCH (n:" + label + ") DETACH DELETE n")
                logger.info("[NEO4J] Clean done.")

            # 2. 创建索引/约束
            logger.info("[NEO4J] Creating indexes ...")
            index_statements = [
                "CREATE INDEX kunlun_vid IF NOT EXISTS FOR (n:KunlunFile) ON (n.vid)",
                "CREATE INDEX kunlun_vid_class IF NOT EXISTS FOR (n:KunlunClass) ON (n.vid)",
                "CREATE INDEX kunlun_vid_func IF NOT EXISTS FOR (n:KunlunFunction) ON (n.vid)",
                "CREATE INDEX kunlun_vid_param IF NOT EXISTS FOR (n:KunlunParameter) ON (n.vid)",
                "CREATE INDEX kunlun_vid_ret IF NOT EXISTS FOR (n:KunlunReturn) ON (n.vid)",
                "CREATE INDEX kunlun_vid_ident IF NOT EXISTS FOR (n:KunlunIdentifier) ON (n.vid)",
                "CREATE INDEX kunlun_vid_const IF NOT EXISTS FOR (n:KunlunConst) ON (n.vid)",
                "CREATE INDEX kunlun_vid_op IF NOT EXISTS FOR (n:KunlunOperator) ON (n.vid)",
                "CREATE INDEX kunlun_vid_branch IF NOT EXISTS FOR (n:KunlunBranch) ON (n.vid)",
                "CREATE INDEX kunlun_vid_import IF NOT EXISTS FOR (n:KunlunImport) ON (n.vid)",
                "CREATE INDEX kunlun_vid_annot IF NOT EXISTS FOR (n:KunlunAnnotation) ON (n.vid)",
                "CREATE INDEX kunlun_vid_dep IF NOT EXISTS FOR (n:KunlunDependency) ON (n.vid)",
                "CREATE INDEX kunlun_vid_node IF NOT EXISTS FOR (n:KunlunNode) ON (n.vid)",
                "CREATE INDEX kunlun_file_path IF NOT EXISTS FOR (n:KunlunFile) ON (n.file_path)",
                "CREATE INDEX kunlun_function_fullname IF NOT EXISTS FOR (n:KunlunFunction) ON (n.fullname)",
                "CREATE INDEX kunlun_identifier_name IF NOT EXISTS FOR (n:KunlunIdentifier) ON (n.name)",
                "CREATE INDEX kunlun_scan_id IF NOT EXISTS FOR (n:KunlunFile) ON (n.scan_id)",
            ]
            for stmt in index_statements:
                try:
                    session.run(stmt)
                except Exception:
                    pass  # 索引已存在时忽略

            # 3. 逐 scan 导入
            for scan_id in scan_ids:
                graph_dir = os.path.join(workspace_root, str(scan_id))
                graph_path = os.path.join(graph_dir, "graph.graphmlz")

                if not os.path.exists(graph_path):
                    logger.warning("[NEO4J] scan_id={}: graph file not found, skipping".format(scan_id))
                    continue

                # 加载 igraph 图
                graph = igraph.Graph.Read(graph_path, format="graphmlz")
                vcount = graph.vcount()
                ecount = graph.ecount()
                logger.info(
                    "[NEO4J] scan_id={}: {} nodes, {} edges".format(scan_id, vcount, ecount)
                )

                if vcount == 0:
                    logger.info("[NEO4J] scan_id={}: empty graph, skipping".format(scan_id))
                    continue

                # 批量写入节点
                nodes_batch = []
                for v in graph.vs:
                    ig_label = v["label"] if "label" in v.attributes() else "unknown"
                    neo_label = NODE_LABEL_MAP.get(ig_label, "KunlunNode")
                    props = _node_properties(v)
                    props["scan_id"] = scan_id
                    # vid 作为唯一标识（Neo4j 内部 ID 不可靠）
                    props["vid"] = str(v.index) if hasattr(v, 'index') else v["id"]
                    nodes_batch.append({"label": neo_label, "props": props})

                # 分批写入节点
                for i in range(0, len(nodes_batch), batch_size):
                    batch = nodes_batch[i:i + batch_size]
                    _batch_create_nodes(session, batch)
                    logger.debug("[NEO4J]   Nodes batch {}/{}".format(
                        i // batch_size + 1,
                        (len(nodes_batch) + batch_size - 1) // batch_size,
                    ))

                # 批量写入关系
                edges_batch = []
                for e in graph.es:
                    ig_label = e["label"] if "label" in e.attributes() else "unknown"
                    neo_type = EDGE_TYPE_MAP.get(ig_label, "RELATED_TO")
                    props = _edge_properties(e)
                    src_vid = str(e.source)
                    tgt_vid = str(e.target)
                    edges_batch.append({
                        "type": neo_type,
                        "src_vid": src_vid,
                        "tgt_vid": tgt_vid,
                        "props": props,
                    })

                # 分批写入关系
                for i in range(0, len(edges_batch), batch_size):
                    batch = edges_batch[i:i + batch_size]
                    _batch_create_edges(session, batch)
                    logger.debug("[NEO4J]   Edges batch {}/{}".format(
                        i // batch_size + 1,
                        (len(edges_batch) + batch_size - 1) // batch_size,
                    ))

                total_nodes += vcount
                total_edges += ecount
                total_scans += 1
                logger.info("[NEO4J] scan_id={}: done ({} nodes, {} edges)".format(
                    scan_id, vcount, ecount))

    finally:
        driver.close()

    report = {
        "project_name": project_name,
        "scans_exported": total_scans,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "scan_ids": scan_ids,
    }
    logger.info("[NEO4J] Export complete: {} scans, {} nodes, {} edges".format(
        total_scans, total_nodes, total_edges))
    return report


def _batch_create_nodes(session, batch: List[Dict]):
    """批量创建 Neo4j 节点（UNWIND + CREATE）。

    返回 vid → Neo4j internal id 的映射。
    """
    # 按 label 分组
    by_label: Dict[str, List[Dict]] = {}
    for item in batch:
        label = item["label"]
        props = item["props"]
        by_label.setdefault(label, []).append(props)

    for label, items in by_label.items():
        # 构建 UNWIND 参数
        # 每个节点的属性列表需要展开为 $props[i].key 的形式
        # 使用 APOC 或直接展开属性 keys
        prop_keys = list(items[0].keys()) if items else []
        # 构建动态 Cypher: UNWIND $rows AS row CREATE (n:Label) SET n = row
        session.run(
            "UNWIND $rows AS row CREATE (n:" + label + ") SET n = row",
            rows=items,
        )


def _batch_create_edges(session, batch: List[Dict]):
    """批量创建 Neo4j 关系。

    使用 vid 索引匹配节点。先收集所有涉及的 vid，批量查 id()，
    然后用 id() 直接关联，避免逐条 MATCH。
    """
    if not batch:
        return

    # 1. 收集所有唯一 vid
    all_vids = set()
    for item in batch:
        all_vids.add(item["src_vid"])
        all_vids.add(item["tgt_vid"])

    # 2. 批量查 vid → id() 映射
    vid_to_id = {}
    vid_list = list(all_vids)
    # 分批查，每批 1000
    chunk = 1000
    for i in range(0, len(vid_list), chunk):
        subset = vid_list[i:i + chunk]
        result = session.run(
            "UNWIND $vids AS v MATCH (n) WHERE n.vid = v RETURN n.vid AS vid, id(n) AS nid",
            vids=subset,
        )
        for r in result:
            vid_to_id[str(r["vid"])] = r["nid"]

    # 3. 按 type 分组，构建关系
    by_type: Dict[str, List[tuple]] = {}  # type → [(src_nid, tgt_nid, props)]
    for item in batch:
        rel_type = item["type"]
        src_nid = vid_to_id.get(item["src_vid"])
        tgt_nid = vid_to_id.get(item["tgt_vid"])
        if src_nid is None or tgt_nid is None:
            continue  # 跳过无法匹配的
        by_type.setdefault(rel_type, []).append((src_nid, tgt_nid, item["props"]))

    for rel_type, items in by_type.items():
        # 收集所有属性 key
        all_keys = set()
        for _, _, props in items:
            all_keys.update(props.keys())

        # 构建行数据
        rows = []
        for src_nid, tgt_nid, props in items:
            row = {"src": src_nid, "tgt": tgt_nid}
            for key in sorted(all_keys):
                safe_key = key.replace(" ", "_")
                row[safe_key] = props.get(key)
            rows.append(row)

        if not all_keys:
            cypher = (
                "UNWIND $rows AS row "
                "MATCH (a) WHERE id(a) = row.src "
                "MATCH (b) WHERE id(b) = row.tgt "
                "CREATE (a)-[r:" + rel_type + "]->(b)"
            )
        else:
            set_clauses = []
            for key in sorted(all_keys):
                safe_key = key.replace(" ", "_")
                set_clauses.append("r." + safe_key + " = row." + safe_key)
            cypher = (
                "UNWIND $rows AS row "
                "MATCH (a) WHERE id(a) = row.src "
                "MATCH (b) WHERE id(b) = row.tgt "
                "CREATE (a)-[r:" + rel_type + "]->(b) "
                "SET " + ", ".join(set_clauses)
            )

        # 分批写入
        for i in range(0, len(rows), 500):
            session.run(cypher, rows=rows[i:i + 500])


# ---------------------------------------------------------------------------
# 公开入口
# ---------------------------------------------------------------------------

def export_project_to_neo4j(
    project_ref: str,
    uri: str = None,
    user: str = None,
    password: str = None,
    clean: bool = False,
    batch_size: int = 500,
) -> Dict[str, Any]:
    """导出一个项目的所有扫描图到 Neo4j。

    Args:
        project_ref: 项目 ID 或名称。
        其余参数同 export_to_neo4j。
    """
    proj = _resolve_project(project_ref)
    if not proj:
        raise ValueError("Project '{}' not found".format(project_ref))

    scan_ids = _find_scan_ids_for_project(proj["id"])
    if not scan_ids:
        raise ValueError(
            "No completed scans with graph files for project '{}' (id={})".format(
                proj["name"], proj["id"]
            )
        )

    logger.info(
        "[NEO4J] Exporting project '{}' (id={}), {} scans: {}".format(
            proj["name"], proj["id"], len(scan_ids), scan_ids
        )
    )
    return export_to_neo4j(
        scan_ids=scan_ids,
        uri=uri,
        user=user,
        password=password,
        clean=clean,
        batch_size=batch_size,
        project_name=proj["name"],
    )


def export_scan_to_neo4j(
    scan_id: int,
    uri: str = None,
    user: str = None,
    password: str = None,
    clean: bool = False,
    batch_size: int = 500,
) -> Dict[str, Any]:
    """导出单个 scan 的图到 Neo4j。"""
    return export_to_neo4j(
        scan_ids=[scan_id],
        uri=uri,
        user=user,
        password=password,
        clean=clean,
        batch_size=batch_size,
        project_name="",
    )


def list_projects_with_graphs() -> List[tuple]:
    """列出所有有图文件的项目（用于 console 模式提示）。"""
    from web.index.models import Project, ScanTask

    workspace_root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "workspace",
    )

    result = []
    for p in Project.objects.all():
        scan_ids = _find_scan_ids_for_project(p.id)
        if scan_ids:
            result.append((p.id, p.project_name, len(scan_ids)))
    return result


