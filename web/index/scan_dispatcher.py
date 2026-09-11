import json
import os
import sys
import subprocess

from django.utils import timezone

from Kunlun_M import settings
from web.index.models import ScanTask
from web.index.cleanup import cleanup_packages


def _reap_dead_processes():
    """回收已死进程：将 is_finished=2 但 PID 不存在的任务重置为 pending。"""
    for task in ScanTask.objects.filter(is_finished=2).select_related(None).only('id', 'pid'):
        pid = task.pid
        if pid and os.path.exists(f'/proc/{pid}'):
            continue
        # 进程不存在，尝试 wait 回收
        if pid:
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                pass
        task.is_finished = 0
        task.finished_at = timezone.now()
        task.exit_code = -1
        task.error_message = "Scan process exited unexpectedly (no exit code captured)."
        task.pid = None
        task.save(update_fields=['is_finished', 'finished_at', 'exit_code', 'error_message', 'pid'])


def _check_target_too_large(target_path):
    """检查目标目录是否过大，返回错误信息或 None。"""
    max_files = int(getattr(settings, "WEB_SCAN_MAX_FILES", 15000) or 15000)
    max_size_mb = int(getattr(settings, "WEB_SCAN_MAX_SIZE_MB", 100) or 100)

    total_size = 0
    file_count = 0
    try:
        for dirpath, dirnames, filenames in os.walk(target_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
                    file_count += 1
            # 提前退出：已超限就不再遍历
            if file_count > max_files:
                break
    except Exception:
        return None

    if file_count > max_files:
        return f"Target too large: {file_count} files (limit {max_files}). Skipped to avoid OOM."
    size_mb = total_size / 1024 / 1024
    if size_mb > max_size_mb:
        return f"Target too large: {size_mb:.1f}MB (limit {max_size_mb}MB). Skipped to avoid OOM."
    return None


def try_dispatch():
    try:
        cleanup_packages()
    except Exception:
        pass

    # 回收已死进程：is_finished=2 但 PID 不存在
    _reap_dead_processes()

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

        # 跳过过大的项目，避免 OOM
        skip_reason = _check_target_too_large(task.target_path)
        if skip_reason:
            ScanTask.objects.filter(id=task.id).update(
                is_finished=0, finished_at=timezone.now(), exit_code=-1,
                error_message=skip_reason
            )
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
