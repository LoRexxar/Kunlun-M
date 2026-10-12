# -*- coding: utf-8 -*-
"""
把 AI 自动分诊跑满存量数据：对全部项目的未分析漏洞做批量分析。
分批提交到 AiTriageQueue 语义之外直接执行（管理命令式脚本，幂等——已分析的跳过）。

用法:
  PYTHONPATH=. DJANGO_SETTINGS_MODULE=Kunlun_M.settings python3 web/management_backfill_triage.py [CAP_TOTAL]
"""
import os
import sys

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Kunlun_M.settings")
django.setup()

from web.index.models import Project, ScanResultTask
from web.ai_pipeline import _triage_project_inner
from web.utils_ai import ai_configured


def main():
    if not ai_configured():
        print("AI_NOT_CONFIGURED")
        return
    cap_total = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    done = 0
    pids = list(Project.objects.values_list("id", flat=True).order_by("-id"))
    for pid in pids:
        if done >= cap_total:
            break
        pending = ScanResultTask.objects.filter(
            scan_project_id=pid, is_active=1, ai_verdict="").count()
        if not pending:
            continue
        n = _triage_project_inner(pid, cap=min(30, cap_total - done))
        done += n
        print("project %s: +%d" % (pid, n), flush=True)
    print("BACKFILL_DONE total=%d" % done)


if __name__ == "__main__":
    main()
