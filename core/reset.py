"""
数据库重置模块 — 清除扫描数据和 workspace，保留规则/tamper/用户/账号。

用法:
    python kunlun.py reset              # 必须输入 yes 确认
    python kunlun.py reset --keep-workspace  # 保留 workspace 目录
"""
import os
import shutil
import sqlite3
import logging

logger = logging.getLogger(__name__)

# ANSI 红色
_RED = '\033[91m'
_RESET = '\033[0m'
_BOLD = '\033[1m'


def _red(text):
    return _RED + text + _RESET


def _bold_red(text):
    return _BOLD + _RED + text + _RESET


def reset_database(keep_workspace=False):
    """重置数据库：清除扫描数据 + ResultFlow 动态表 + workspace，重新 migrate + 加载规则。"""
    from django.conf import settings

    db_path = settings.DATABASES['default']['NAME']

    # 先统计当前数据量，给用户明确的提示
    from web.index.models import (
        ScanResultTask, ScanTask, ProjectVendors,
        NewEvilFunc, Project, VendorVulns, TaintChain,
    )
    from django.contrib.sessions.models import Session

    n_project = Project.objects.count()
    n_scan = ScanTask.objects.count()
    n_result = ScanResultTask.objects.count()
    n_vendor = ProjectVendors.objects.count()
    n_evilfunc = NewEvilFunc.objects.count()
    n_taint_chain = TaintChain.objects.count()
    n_session = Session.objects.count()

    # ResultFlow 动态表
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ResultFlow_%'"
    )
    n_rf = len(cur.fetchall())
    conn.close()

    # workspace
    workspace_root = os.path.join(settings.BASE_DIR, 'workspace')
    n_workspace = len(os.listdir(workspace_root)) if os.path.isdir(workspace_root) else 0

    print()
    print("=" * 50)
    print("  KunLun-M Database Reset")
    print("=" * 50)
    print()
    print("  " + _bold_red("WARNING: This will permanently DELETE:"))
    print()
    print("  Scan Data:")
    print("    - Projects:              {:>6}".format(n_project))
    print("    - Scan Tasks:            {:>6}".format(n_scan))
    print("    - Scan Results:          {:>6}".format(n_result))
    print("    - Evil Functions:        {:>6}".format(n_evilfunc))
    print("    - Vendor Dependencies:   {:>6}".format(n_vendor))
    print("    - Taint Chains:          {:>6}".format(n_taint_chain))
    print("  ResultFlow Tables:")
    print("    - Dynamic Tables:       {:>6}".format(n_rf))
    print("  Sessions:")
    print("    - Active Sessions:      {:>6}".format(n_session))
    if not keep_workspace and n_workspace > 0:
        print("  Workspace (Graph Cache):")
        print("    - Cached Entries:      {:>6}".format(n_workspace))
    elif keep_workspace and n_workspace > 0:
        print("  Workspace:                   (kept)")
    print()
    print("  KEEP:")
    print("    - Rules (index_rules)")
    print("    - Tampers (framework_tamper)")
    print("    - User accounts (auth_user)")
    print("    - API tokens (web_apitoken)")
    print()
    print("=" * 50)
    print()

    confirm = input("  Type " + _bold_red("yes") + " to confirm reset: ").strip().lower()
    if confirm != 'yes':
        print("  Reset cancelled.")
        return

    print()
    logger.info("[RESET] Starting database reset...")

    # 1. 通过 Django ORM 清空业务表
    logger.info("[RESET] Clearing business tables...")
    from django.core.management import call_command

    for model in [ScanResultTask, ScanTask, ProjectVendors, NewEvilFunc, VendorVulns, TaintChain, Project]:
        cnt = model.objects.count()
        model.objects.all().delete()
        logger.info("[RESET]   Deleted {} rows from {}".format(cnt, model._meta.db_table))

    # 清空 sessions
    session_cnt = Session.objects.count()
    Session.objects.all().delete()
    logger.info("[RESET]   Deleted {} rows from django_session".format(session_cnt))

    # 2. 删除 ResultFlow 动态表
    logger.info("[RESET] Dropping ResultFlow tables...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ResultFlow_%'"
    )
    rf_tables = [r[0] for r in cur.fetchall()]
    for t in rf_tables:
        cur.execute('DROP TABLE IF EXISTS [{}]'.format(t))
        conn.commit()
    conn.close()
    logger.info("[RESET]   Dropped {} ResultFlow tables".format(len(rf_tables)))

    # 3. 清理 workspace
    if not keep_workspace:
        if os.path.isdir(workspace_root):
            items = os.listdir(workspace_root)
            if items:
                for item in items:
                    item_path = os.path.join(workspace_root, item)
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
                logger.info("[RESET]   Cleared workspace ({} entries)".format(len(items)))
            else:
                logger.info("[RESET]   Workspace already empty")
        else:
            logger.info("[RESET]   No workspace directory found")

    # 4. 重新 migrate
    logger.info("[RESET] Running makemigrations...")
    try:
        call_command('makemigrations', verbosity=0)
    except Exception as e:
        logger.warning("[RESET] makemigrations: {}".format(e))

    logger.info("[RESET] Running migrate...")
    call_command('migrate', verbosity=0)

    # 5. 重新加载规则和 tamper
    logger.info("[RESET] Reloading rules and tampers...")
    from core.rule import RuleCheck, TamperCheck
    try:
        RuleCheck().load()
        logger.info("[RESET]   Rules loaded")
    except Exception as e:
        logger.warning("[RESET]   Rule load error: {}".format(e))
    try:
        TamperCheck().load()
        logger.info("[RESET]   Tampers loaded")
    except Exception as e:
        logger.warning("[RESET]   Tamper load error: {}".format(e))

    # 6. 验证
    logger.info("[RESET] Verifying...")
    print()
    print("  " + _red("Reset complete."))
    print("  Projects: {} | Scan Tasks: {} | Results: {}".format(
        Project.objects.count(), ScanTask.objects.count(), ScanResultTask.objects.count()))
    print()
