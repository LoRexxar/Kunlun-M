# -*- coding: utf-8 -*-
"""
core.import_export
~~~~~~~~~~~~~~~~~~

项目级导入导出功能。以 Project 为主体，打包数据库记录 + workspace 图文件，
生成可移植的 tar.gz 归档，支持跨 KunLun-M 实例迁移。

CLI 用法:
    python kunlun.py export-project -p <project_id_or_name>
    python kunlun.py import-project -f <archive_path> [--force]

Console 用法:
    KunLun-M> export <project_id_or_name>
    KunLun-M> import <archive_path>
"""

import json
import os
import shutil
import tarfile
import tempfile
import uuid
from datetime import datetime

from django.db import connection, transaction
from django.db.models.fields import DateTimeField

from utils.log import logger

from web.index.models import (
    Project, ProjectVendors, ScanTask, ScanResultTask, NewEvilFunc,
)
from core.graph.workspace import WORKSPACE_ROOT


EXPORT_VERSION = "1.0"


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _model_to_dict(instance):
    """将 Django model 实例序列化为 dict，处理 datetime/None 等特殊类型。"""
    d = {}
    for f in instance._meta.fields:
        val = getattr(instance, f.attname, None)
        if val is None and not f.null:
            # 非 null 字段但值为 None（不应发生），跳过
            d[f.attname] = f.get_default()
        elif isinstance(f, DateTimeField) and val is not None:
            d[f.attname] = val.isoformat()
        else:
            d[f.attname] = val
    return d


def _dict_to_model_fields(data):
    """将序列化后的 dict 转换回 model 字段值（datetime 字符串 → datetime 对象）。"""
    result = {}
    for k, v in data.items():
        if isinstance(v, str) and v and k not in ('task_name', 'target_path',
                'parameter_config', 'error_message', 'source_type', 'source_archive',
                'source_dir', 'options_json', 'visit_token', 'cvi_id', 'language',
                'vulfile_path', 'source_code', 'result_type', 'vul_hash',
                'func_name', 'origin_func_name', 'func_hash', 'name', 'version',
                'project_origin', 'project_name', 'project_des', 'project_hash',
                'hash', 'source', 'ext'):
            # 尝试解析为 datetime
            try:
                result[k] = datetime.fromisoformat(v)
            except (ValueError, TypeError):
                result[k] = v
        else:
            result[k] = v
    return result


def _resolve_project(project_id_or_name):
    """解析 project_id（数字）或 project_name 为 Project 对象。不存在则抛 ValueError。"""
    try:
        pid = int(project_id_or_name)
        project = Project.objects.filter(id=pid).first()
    except (ValueError, TypeError):
        project = Project.objects.filter(project_name=project_id_or_name).first()
        pid = project.id if project else None

    if not project:
        raise ValueError("Project '{}' not found".format(project_id_or_name))
    return project


def _resultflow_table_name(project_id):
    """计算 ResultFlow 动态表名。"""
    return "ResultFlow_1{:08d}".format(project_id)


def _get_resultflow_rows(table_name):
    """用 raw SQL 读取 ResultFlow 表的全部数据。返回 (columns, rows) 或 None。"""
    import sqlite3
    db_path = connection.settings_dict['NAME']
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        )
        if not cur.fetchone():
            return None
        cur.execute("SELECT * FROM [{}]".format(table_name))
        columns = [desc[0] for desc in cur.description]
        rows = [tuple(r) for r in cur.fetchall()]
        return columns, rows
    finally:
        conn.close()


def _create_resultflow_table(table_name):
    """用 raw SQL 创建 ResultFlow 表（如果不存在）。"""
    import sqlite3
    db_path = connection.settings_dict['NAME']
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS [{}] (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vul_id INTEGER NOT NULL,
                node_type varchar(50) NOT NULL,
                node_content varchar(500) NOT NULL,
                node_path varchar(300) NOT NULL,
                node_source TEXT,
                node_lineno varchar(20),
                node_vid INTEGER
            )
        """.format(table_name))
        try:
            cur.execute("ALTER TABLE [{}] ADD COLUMN node_source TEXT".format(table_name))
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE [{}] ADD COLUMN node_vid INTEGER".format(table_name))
        except Exception:
            pass
        conn.commit()
    finally:
        conn.close()


def list_projects():
    """列出所有项目，返回 [(id, project_name), ...] 列表。"""
    return list(Project.objects.values_list('id', 'project_name').order_by('-id'))


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------

def export_project(project_id_or_name, output_dir=None):
    """
    导出项目为 tar.gz 归档文件。

    :param project_id_or_name: 项目 ID（数字）或项目名称
    :param output_dir: 输出目录，默认 BASE_DIR
    :return: 输出文件的绝对路径
    :raises: ValueError 项目不存在
    """
    project = _resolve_project(project_id_or_name)
    pid = project.id

    logger.info("[EXPORT] Exporting project '{}' (id={}) ...".format(project.project_name, pid))

    # 1. 查询关联数据
    scantasks = list(ScanTask.objects.filter(project_id=pid))
    scan_ids = [st.id for st in scantasks]

    results = list(ScanResultTask.objects.filter(scan_project_id=pid))
    newevilfuncs = list(NewEvilFunc.objects.filter(project_id=pid))
    vendors = list(ProjectVendors.objects.filter(project_id=pid))

    # 2. ResultFlow
    rf_table_name = _resultflow_table_name(pid)
    rf_data = _get_resultflow_rows(rf_table_name)

    # 3. Workspace 图文件
    graph_dirs = []
    for sid in scan_ids:
        ws_dir = os.path.join(WORKSPACE_ROOT, str(sid))
        if os.path.isdir(ws_dir):
            files = os.listdir(ws_dir)
            if files:
                graph_dirs.append((str(sid), ws_dir, files))

    # 4. 构造 manifest
    now = datetime.utcnow()
    manifest = {
        "version": EXPORT_VERSION,
        "exported_at": now.isoformat(),
        "project_id": pid,
        "project_name": project.project_name,
        "project_hash": project.project_hash,
        "project_des": project.project_des or "",
        "project_origin": project.project_origin or "",
        "scan_ids": scan_ids,
        "scan_count": len(scantasks),
        "result_count": len(results),
        "newevilfunc_count": len(newevilfuncs),
        "vendor_count": len(vendors),
        "resultflow_table": rf_table_name if rf_data else "",
        "resultflow_rows": len(rf_data[1]) if rf_data else 0,
        "graph_files": len(graph_dirs),
    }

    logger.info("[EXPORT]   scans={}, results={}, newevilfuncs={}, vendors={}, "
                "resultflow={}, graphs={}".format(
                    manifest["scan_count"], manifest["result_count"],
                    manifest["newevilfunc_count"], manifest["vendor_count"],
                    manifest["resultflow_rows"], manifest["graph_files"]))

    # 5. 序列化 DB 数据
    db_data = {
        "project.json": [_model_to_dict(project)],
        "scantasks.json": [_model_to_dict(st) for st in scantasks],
        "results.json": [_model_to_dict(r) for r in results],
        "newevilfuncs.json": [_model_to_dict(n) for n in newevilfuncs],
        "vendors.json": [_model_to_dict(v) for v in vendors],
    }

    if rf_data:
        columns, rows = rf_data
        db_data["resultflow.json"] = {
            "table_name": rf_table_name,
            "columns": columns,
            "rows": rows,
        }

    # 6. 打包
    if output_dir is None:
        from Kunlun_M.settings import BASE_DIR
        output_dir = BASE_DIR

    ts = now.strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in project.project_name)
    archive_name = "kunlun-export-{}-{}.tar.gz".format(safe_name, ts)
    archive_path = os.path.join(output_dir, archive_name)

    logger.info("[EXPORT]   Packing to {} ...".format(archive_path))

    with tarfile.open(archive_path, mode="w:gz") as tar:
        # manifest
        _add_to_tar(tar, manifest, "manifest.json")

        # db/
        for fname, data in db_data.items():
            _add_to_tar(tar, data, "db/" + fname)

        # workspace/
        for sid, ws_dir, files in graph_dirs:
            for f in files:
                fpath = os.path.join(ws_dir, f)
                if os.path.isfile(fpath):
                    tar.add(fpath, arcname="workspace/{}/{}".format(sid, f))

    size_mb = os.path.getsize(archive_path) / 1024.0 / 1024.0
    logger.info("[EXPORT] Done. Archive: {} ({:.2f} MB)".format(archive_path, size_mb))
    return os.path.abspath(archive_path)


def _add_to_tar(tar, data, arcname):
    """将 Python 对象序列化为 JSON 并添加到 tar 包中。"""
    import io
    content = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
    info = tarfile.TarInfo(name=arcname)
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))


# ---------------------------------------------------------------------------
# 导入
# ---------------------------------------------------------------------------

def import_project(archive_path, force=False):
    """
    从 tar.gz 归档导入项目到当前 KunLun-M 实例。

    :param archive_path: 归档文件路径
    :param force: 是否覆盖同名 project（基于 project_hash）
    :return: 导入报告 dict
    :raises: ValueError 归档不存在或格式错误
    """
    if not os.path.isfile(archive_path):
        raise ValueError("Archive not found: {}".format(archive_path))

    logger.info("[IMPORT] Importing from {} ...".format(archive_path))

    # 1. 解压到临时目录
    tmpdir = tempfile.mkdtemp(prefix="kunlun-import-")
    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            tar.extractall(tmpdir)

        # 2. 读取 manifest
        manifest_path = os.path.join(tmpdir, "manifest.json")
        if not os.path.isfile(manifest_path):
            raise ValueError("Invalid archive: manifest.json not found")

        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        if manifest.get("version") != EXPORT_VERSION:
            logger.warning("[IMPORT] Archive version {} != current {}".
                           format(manifest.get("version"), EXPORT_VERSION))

        old_project_id = manifest["project_id"]
        old_project_name = manifest["project_name"]
        old_project_hash = manifest["project_hash"]

        # 3. 加载 DB 数据
        def _load_json(name):
            p = os.path.join(tmpdir, "db", name)
            if not os.path.isfile(p):
                return None
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)

        project_data = _load_json("project.json")
        scantasks_data = _load_json("scantasks.json") or []
        results_data = _load_json("results.json") or []
        newevilfuncs_data = _load_json("newevilfuncs.json") or []
        vendors_data = _load_json("vendors.json") or []
        resultflow_data = _load_json("resultflow.json")

        if not project_data or not scantasks_data:
            raise ValueError("Invalid archive: missing project or scantasks data")

        project_record = project_data[0] if isinstance(project_data, list) else project_data

        # 4. 处理 Project
        existing = Project.objects.filter(project_hash=old_project_hash).first()
        if existing:
            if not force:
                raise ValueError(
                    "Project '{}' (hash={}) already exists (id={}). "
                    "Use --force to overwrite.".format(
                        existing.project_name, old_project_hash, existing.id))
            # 复用已有 project
            new_project_id = existing.id
            existing.project_des = project_record.get("project_des", "") or existing.project_des
            existing.project_origin = project_record.get("project_origin", "") or existing.project_origin
            existing.save()
            logger.info("[IMPORT]   Reusing existing project id={} '{}'".format(
                new_project_id, existing.project_name))
        else:
            new_project = Project(
                project_name=old_project_name,
                project_des=project_record.get("project_des", ""),
                project_origin=project_record.get("project_origin", ""),
                project_hash=old_project_hash,
            )
            new_project.save()
            new_project_id = new_project.id
            logger.info("[IMPORT]   Created new project id={} '{}'".format(
                new_project_id, old_project_name))

        # 5. 事务：导入所有数据
        with transaction.atomic():
            scan_id_map = {}   # old_scan_id → new_scan_id
            result_id_map = {} # old_result_id → new_result_id

            # 5a. 导入 scantasks
            for st_data in scantasks_data:
                fields = _dict_to_model_fields(st_data)
                old_sid = fields.pop('id', None)
                # 设置新的 project_id，生成新的 visit_token
                fields['project_id'] = new_project_id
                fields['visit_token'] = str(uuid.uuid4())
                # 移除 id（自增），保留其他字段
                new_st = ScanTask.objects.create(**fields)
                if old_sid is not None:
                    scan_id_map[int(old_sid)] = new_st.id

            logger.info("[IMPORT]   Imported {} scan tasks".format(len(scantasks_data)))

            # 5b. 导入 results
            for r_data in results_data:
                fields = _dict_to_model_fields(r_data)
                old_rid = fields.pop('id', None)
                old_scan_id = fields.pop('scan_task_id', None)
                # 映射到新的 ID
                fields['scan_project_id'] = new_project_id
                fields['scan_task_id'] = scan_id_map.get(int(old_scan_id) if old_scan_id else 0, 0)
                # 移除 vul_hash，让 save() 重新计算
                # 但 ScanResultTask.save() 会查重 — 用 create 跳过自定义 save
                new_r = ScanResultTask(
                    scan_project_id=fields['scan_project_id'],
                    scan_task_id=fields['scan_task_id'],
                    cvi_id=fields.get('cvi_id', ''),
                    language=fields.get('language', ''),
                    vulfile_path=fields.get('vulfile_path', ''),
                    source_code=fields.get('source_code', ''),
                    result_type=fields.get('result_type', ''),
                    is_unconfirm=fields.get('is_unconfirm', False),
                    is_active=fields.get('is_active', True),
                )
                new_r.save()
                if old_rid is not None:
                    result_id_map[int(old_rid)] = new_r.id

            logger.info("[IMPORT]   Imported {} results".format(len(results_data)))

            # 5c. 导入 newevilfuncs
            for nef_data in newevilfuncs_data:
                fields = _dict_to_model_fields(nef_data)
                old_nid = fields.pop('id', None)
                old_scan_id = fields.pop('scan_task_id', None)
                fields['project_id'] = new_project_id
                fields['scan_task_id'] = scan_id_map.get(int(old_scan_id) if old_scan_id else 0, 0)
                fields['func_hash'] = ''  # 让 save() 重新计算
                try:
                    NewEvilFunc.objects.create(**fields)
                except Exception as e:
                    logger.debug("[IMPORT] Skip newevilfunc: {}".format(e))

            logger.info("[IMPORT]   Imported {} newevilfuncs".format(len(newevilfuncs_data)))

            # 5d. 导入 vendors
            for v_data in vendors_data:
                fields = _dict_to_model_fields(v_data)
                old_vid = fields.pop('id', None)
                fields['project_id'] = new_project_id
                fields['hash'] = ''  # 让 save() 重新计算
                try:
                    ProjectVendors.objects.create(**fields)
                except Exception as e:
                    logger.debug("[IMPORT] Skip vendor: {}".format(e))

            logger.info("[IMPORT]   Imported {} vendors".format(len(vendors_data)))

        # 事务结束，以下 ResultFlow 和 workspace 操作不在 Django 事务中

        # 5e. 导入 ResultFlow
        rf_rows_imported = 0
        if resultflow_data:
            rf_table = resultflow_data.get("table_name", "")
            rf_columns = resultflow_data.get("columns", [])
            rf_rows = resultflow_data.get("rows", [])

            # 计算新表名（基于新 project_id）
            new_rf_table = _resultflow_table_name(new_project_id)

            import sqlite3
            db_path = connection.settings_dict['NAME']
            rf_conn = sqlite3.connect(db_path)
            rf_cur = rf_conn.cursor()

            try:
                # 检查表是否存在
                rf_cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (new_rf_table,)
                )
                table_exists = rf_cur.fetchone() is not None

                if table_exists:
                    rf_cur.execute("SELECT COUNT(*) FROM [{}]".format(new_rf_table))
                    existing_rows = rf_cur.fetchone()[0]
                    if existing_rows > 0:
                        if force:
                            logger.info("[IMPORT]   Clearing existing ResultFlow table ({})".format(new_rf_table))
                            rf_cur.execute("DELETE FROM [{}]".format(new_rf_table))
                        else:
                            logger.info("[IMPORT]   ResultFlow table {} has {} rows, appending new data".format(
                                new_rf_table, existing_rows))
                else:
                    rf_conn.close()
                    _create_resultflow_table(new_rf_table)
                    rf_conn = sqlite3.connect(db_path)
                    rf_cur = rf_conn.cursor()

                # 找到 vul_id 列索引
                vul_id_idx = rf_columns.index('vul_id') if 'vul_id' in rf_columns else 1

                for row in rf_rows:
                    old_vul_id = row[vul_id_idx]
                    new_vul_id = result_id_map.get(int(old_vul_id)) if old_vul_id else None
                    if not new_vul_id:
                        continue  # 跳过无法映射的行
                    # 构建 INSERT（跳过 id 列）
                    col_names = [c for c in rf_columns if c != 'id']
                    col_placeholders = []
                    col_values = []
                    for c in col_names:
                        idx = rf_columns.index(c)
                        val = row[idx]
                        if c == 'vul_id':
                            val = new_vul_id
                        col_placeholders.append("?")
                        col_values.append(val)
                    sql = "INSERT INTO [{}] ({}) VALUES ({})".format(
                        new_rf_table, ", ".join(col_names), ", ".join(col_placeholders))
                    rf_cur.execute(sql, col_values)
                    rf_rows_imported += 1

                rf_conn.commit()
                logger.info("[IMPORT]   Imported {} ResultFlow rows into {}".format(
                    rf_rows_imported, new_rf_table))
            finally:
                rf_conn.close()

        # 5f. 复制 workspace 图文件
        graphs_copied = 0
        for old_sid in scan_id_map:
            new_sid = scan_id_map[old_sid]
            src_dir = os.path.join(tmpdir, "workspace", str(old_sid))
            dst_dir = os.path.join(WORKSPACE_ROOT, str(new_sid))
            if os.path.isdir(src_dir):
                os.makedirs(dst_dir, exist_ok=True)
                for f in os.listdir(src_dir):
                    src_f = os.path.join(src_dir, f)
                    dst_f = os.path.join(dst_dir, f)
                    if not os.path.exists(dst_f):
                        shutil.copy2(src_f, dst_f)
                        graphs_copied += 1
                        logger.debug("[IMPORT]   workspace/{}/{} -> workspace/{}/{}".format(
                            old_sid, f, new_sid, f))

        logger.info("[IMPORT]   Copied {} workspace files".format(graphs_copied))

    finally:
        # 清理临时目录
        shutil.rmtree(tmpdir, ignore_errors=True)

    report = {
        "project_name": old_project_name,
        "old_project_id": old_project_id,
        "new_project_id": new_project_id,
        "scans_imported": len(scantasks_data),
        "results_imported": len(results_data),
        "newevilfuncs_imported": len(newevilfuncs_data),
        "vendors_imported": len(vendors_data),
        "resultflow_rows_imported": rf_rows_imported if 'rf_rows_imported' in dir() else 0,
        "graph_files_copied": graphs_copied if 'graphs_copied' in dir() else 0,
    }

    logger.info("[IMPORT] Done. Summary: {}".format(
        json.dumps(report, ensure_ascii=False)))
    return report
