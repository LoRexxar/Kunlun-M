"""
数据库重置模块 — 清除扫描数据和 workspace，保留规则/tamper/用户。

用法:
    python kunlun.py reset              # 交互确认
    python kunlun.py reset -y            # 跳过确认
    python kunlun.py reset --keep-workspace  # 保留 workspace 目录
"""
import os
import shutil
import sqlite3
import logging

logger = logging.getLogger(__name__)

# 需要清空的业务表（按外键依赖顺序）
_BUSINESS_TABLES = [
    'index_scanresulttask',
    'index_scantask',
    'index_projectvendors',
    'index_newevilfunc',
    'index_project',
    'index_vendorvulns',
    'django_session',
]

# 需要保留的表（不清理）
_KEEP_TABLES = {
    'auth_group', 'auth_group_permissions', 'auth_permission',
    'auth_user', 'auth_user_groups', 'auth_user_user_permissions',
    'django_content_type', 'django_migrations',
    'framework_tamper',
    'index_rules',
    'web_apitoken',
    'sqlite_sequence',
}


def reset_database(skip_confirm=False, keep_workspace=False):
    """重置数据库：清除扫描数据 + ResultFlow 动态表 + workspace，重新 migrate + 加载规则。"""
    from django.conf import settings

    db_path = settings.DATABASES['default']['NAME']

    if not skip_confirm:
        print("=" * 50)
        print("  KunLun-M Database Reset")
        print("=" * 50)
        print("  This will DELETE:")
        print("    - All scan tasks, results, projects")
        print("    - All vendor/vulnerability data")
        print("    - All ResultFlow tables")
        print("    - All sessions")
        if not keep_workspace:
            print("    - All workspace (graph cache) files")
        print()
        print("  This will KEEP:")
        print("    - Rules (index_rules)")
        print("    - Tampers (framework_tamper)")
        print("    - Users & API tokens")
        print("=" * 50)

        confirm = input("  Are you sure? (yes/no): ").strip().lower()
        if confirm != 'yes':
            logger.info("Reset cancelled.")
            return

    logger.info("[RESET] Starting database reset...")

    # 1. 通过 Django ORM 清空业务表
    logger.info("[RESET] Clearing business tables...")
    from django.core.management import call_command
    from web.index.models import (
        ScanResultTask, ScanTask, ProjectVendors,
        NewEvilFunc, Project, VendorVulns,
    )

    counts = {}
    for model in [ScanResultTask, ScanTask, ProjectVendors, NewEvilFunc, VendorVulns, Project]:
        cnt = model.objects.count()
        model.objects.all().delete()
        counts[model._meta.db_table] = cnt
        logger.info("[RESET]   Deleted {} rows from {}".format(cnt, model._meta.db_table))

    # 清空 sessions
    from django.contrib.sessions.models import Session
    session_cnt = Session.objects.count()
    Session.objects.all().delete()
    counts['django_session'] = session_cnt
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
        logger.info("[RESET]   Dropped table {}".format(t))
    conn.close()
    logger.info("[RESET]   Dropped {} ResultFlow tables".format(len(rf_tables)))

    # 3. 清理 workspace
    if not keep_workspace:
        workspace_root = os.path.join(settings.BASE_DIR, 'workspace')
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

    # 6. 统计
    logger.info("[RESET] Verifying...")
    remain = {}
    from web.index.models import Project, ScanTask, ScanResultTask
    remain['projects'] = Project.objects.count()
    remain['scan_tasks'] = ScanTask.objects.count()
    remain['scan_results'] = ScanResultTask.objects.count()

    logger.info("[RESET] Reset complete!")
    print()
    print("  Database reset done.")
    print("  Remaining: {} projects, {} scan tasks, {} results".format(
        remain['projects'], remain['scan_tasks'], remain['scan_results']))
    print()
