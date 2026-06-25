import json
import os
import sys
import subprocess

from django.utils import timezone

from Kunlun_M import settings
from web.index.models import ScanTask
from web.index.cleanup import cleanup_packages


def try_dispatch():
    try:
        cleanup_packages()
    except Exception:
        pass
    max_concurrency = int(getattr(settings, "WEB_SCAN_MAX_CONCURRENCY", 1) or 1)
    running = ScanTask.objects.filter(is_finished=2).count()
    slots = max_concurrency - running
    if slots <= 0:
        return 0

    started = 0
    for _ in range(slots):
        task = ScanTask.objects.filter(is_finished=3).order_by("id").first()
        if not task:
            break
        if not task.target_path:
            task.is_finished = 0
            task.finished_at = timezone.now()
            task.exit_code = -1
            task.error_message = "Empty target_path."
            task.save()
            continue

        claimed = ScanTask.objects.filter(id=task.id, is_finished=3).update(is_finished=2, started_at=timezone.now(), exit_code=None, error_message=None)
        if not claimed:
            continue

        try:
            cmd = _build_scan_cmd(task)
            proc = subprocess.Popen(
                cmd,
                cwd=getattr(settings, "PROJECT_DIRECTORY", None) or os.getcwd(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ScanTask.objects.filter(id=task.id).update(pid=proc.pid)
            started += 1
        except Exception as e:
            ScanTask.objects.filter(id=task.id).update(is_finished=0, finished_at=timezone.now(), exit_code=-1, error_message=str(e)[:2000])

    return started


def _build_scan_cmd(task):
    cmd = [sys.executable, settings.KUNLUN_MAIN, "scan", "--task-id", str(task.id), "-t", task.target_path, "-y"]

    opts = {}
    try:
        opts = json.loads(task.options_json) if task.options_json else {}
    except Exception:
        opts = {}

    language = (opts.get("language", "") or "").strip()
    if language:
        cmd += ["-lan", language]

    special_rules = (opts.get("special_rules", "") or "").strip()
    if special_rules:
        cmd += ["-r", special_rules]

    tamper_name = (opts.get("tamper_name", "") or "").strip()
    if tamper_name:
        cmd += ["-tp", tamper_name]

    black_path = (opts.get("black_path", "") or "").strip()
    if black_path:
        cmd += ["-b", black_path]

    if int(opts.get("unconfirm", 0) or 0) == 1:
        cmd += ["-uc"]

    if int(opts.get("unprecom", 0) or 0) == 1:
        cmd += ["-upc"]

    if int(opts.get("without_vendor", 0) or 0) == 1:
        cmd += ["--without-vendor"]

    if int(opts.get("no_cache", 0) or 0) == 1:
        cmd += ["--no-cache"]

    return cmd
