"""
迁移 ResultFlow_* 动态表数据到 TaintChain 固定表。

用法:
    python -c "import os; os.environ['DJANGO_SETTINGS_MODULE']='Kunlun_M.settings'; from core.migrate_chains import migrate_resultflow_to_taintchain; migrate_resultflow_to_taintchain()"
    # 或在 Django shell 中:
    >>> from core.migrate_chains import migrate_resultflow_to_taintchain
    >>> migrate_resultflow_to_taintchain()
"""

import os
import sqlite3
import logging

logger = logging.getLogger(__name__)


def migrate_resultflow_to_taintchain(dry_run=False):
    """将所有 ResultFlow_* 动态表数据迁移到 TaintChain 表。

    Args:
        dry_run: 如果为 True，只统计不实际写入
    """
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
    django.setup()

    from django.conf import settings
    from web.index.models import TaintChain, ScanResultTask

    db_path = settings.DATABASES['default']['NAME']
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # 查找所有 ResultFlow 动态表
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ResultFlow_%'"
    )
    rf_tables = [r[0] for r in cur.fetchall()]

    if not rf_tables:
        print("No ResultFlow tables found. Nothing to migrate.")
        conn.close()
        return

    print("Found {} ResultFlow tables to migrate.".format(len(rf_tables)))

    total_rows = 0
    total_migrated = 0
    total_skipped = 0

    for table_name in rf_tables:
        # 检查表中是否有数据
        cur.execute("SELECT COUNT(*) FROM [{}]".format(table_name))
        count = cur.fetchone()[0]
        if count == 0:
            print("  [SKIP] {} (empty)".format(table_name))
            continue

        total_rows += count
        print("  [MIGRATE] {} ({} rows)".format(table_name, count))

        # 读取表结构，确定有哪些字段
        cur.execute("PRAGMA table_info([{}])".format(table_name))
        columns = [col[1] for col in cur.fetchall()]

        has_vid = 'node_vid' in columns

        # 读取所有数据，按 id 排序
        col_select = 'vul_id, node_type, node_content, node_path, node_lineno, node_source'
        if has_vid:
            col_select += ', node_vid'
        cur.execute("SELECT {} FROM [{}] ORDER BY id".format(col_select, table_name))
        rows = cur.fetchall()

        # 按 vul_id 分组，分配 chain_index 和 step_order
        step_counter = {}  # vul_id -> step

        if not dry_run:
            for row in rows:
                vul_id = row[0]
                node_type = row[1]
                node_content = row[2]
                node_path = row[3]
                node_lineno = row[4]
                node_source = row[5]
                node_vid = row[6] if has_vid and len(row) > 6 else None

                # 推断 scan_task: 从 ScanResultTask.scan_task_id 获取
                try:
                    srt = ScanResultTask.objects.filter(id=vul_id).first()
                    if not srt:
                        total_skipped += 1
                        continue
                    scan_task_id = srt.scan_task_id
                except Exception:
                    total_skipped += 1
                    continue

                # 获取 step_order
                key = vul_id
                step = step_counter.get(key, 0)

                # 处理 lineno (可能是字符串化的 float)
                try:
                    lineno = int(float(node_lineno)) if node_lineno else 0
                except (ValueError, TypeError):
                    lineno = 0

                # 处理 vid
                try:
                    vid = int(float(node_vid)) if node_vid is not None else None
                except (ValueError, TypeError):
                    vid = None

                TaintChain(
                    scan_task=scan_task_id,
                    vul_result=vul_id,
                    chain_index=0,
                    step_order=step,
                    node_label=node_type or '',
                    node_name=node_content or '',
                    file_path=node_path or '',
                    lineno=lineno,
                    vid=vid,
                    source_code=node_source or '',
                ).save()

                step_counter[key] = step + 1
                total_migrated += 1

    conn.close()

    print()
    print("=" * 50)
    print("  Migration Summary")
    print("=" * 50)
    print("  Tables scanned:      {}".format(len(rf_tables)))
    print("  Total rows found:    {}".format(total_rows))
    if not dry_run:
        print("  Rows migrated:      {}".format(total_migrated))
        print("  Rows skipped:       {}".format(total_skipped))
        print("  TaintChain total:   {}".format(TaintChain.objects.count()))
    else:
        print("  (DRY RUN - no data written)")
    print()
