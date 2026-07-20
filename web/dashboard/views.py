#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/23 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.conf import settings
import os
from web.index.models import ScanTask, Project
from web.index.models import get_and_check_scantask_project_id

from utils.utils import del_sensitive_for_config
from web.index.scan_dispatcher import try_dispatch

from Kunlun_M.settings import API_TOKEN
from utils.path_safety import safe_join, is_path_under


@login_required
def index(req):

    tasks = ScanTask.objects.all().order_by("-id")[:100]
    for task in tasks:
        task.is_finished = int(task.is_finished)
        task.parameter_config = del_sensitive_for_config(task.parameter_config)

        project_id = get_and_check_scantask_project_id(task.id)
        project = Project.objects.filter(id=project_id).first()

        task.project_name = project.project_name if project else '-'

    # 摘要统计
    status_count = {'success': 0, 'running': 0, 'failed': 0, 'other': 0}
    for task in tasks:
        if task.is_finished == 1:
            status_count['success'] += 1
        elif task.is_finished == 2:
            status_count['running'] += 1
        elif task.is_finished in (-1, 0):
            status_count['failed'] += 1
        else:
            status_count['other'] += 1

    first_task = tasks[0] if tasks else None

    data = {
        'tasks': tasks,
        'status_count': status_count,
        'last_task': first_task,
    }

    return render(req, 'dashboard/index.html', data)


@login_required
def docs(req):
    default_path = req.GET.get("path") or "README.md"
    return render(req, 'dashboard/docs.html', {"default_doc_path": default_path})


def _docs_root():
    return os.path.join(settings.BASE_DIR, "docs")


def _normalize_doc_path(p):
    if not p:
        return None
    p = str(p).strip().replace("\\", "/")
    if not p or p.startswith("/"):
        return None
    if "://" in p:
        return None
    p = os.path.normpath(p).replace("\\", "/")
    if p == "." or p.startswith("../") or p == "..":
        return None
    if not p.lower().endswith(".md"):
        return None
    return p


def _safe_doc_abspath(rel_path):
    rel_path = _normalize_doc_path(rel_path)
    if not rel_path:
        return None, None
    root = _docs_root()
    return rel_path, safe_join(root, rel_path)


@login_required
def docs_api_list(req):
    root = _docs_root()
    if not os.path.isdir(root):
        return JsonResponse({"status": "ok", "files": []})

    files = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d and not d.startswith(".")]
        for fn in filenames:
            if not fn or fn.startswith("."):
                continue
            if not fn.lower().endswith(".md"):
                continue
            abs_path = os.path.join(dirpath, fn)
            rel = os.path.relpath(abs_path, root).replace("\\", "/")
            rel = _normalize_doc_path(rel)
            if not rel:
                continue
            files.append({"path": rel, "name": fn})
            count += 1
            if count >= 200:
                break
        if count >= 200:
            break

    files.sort(key=lambda x: x["path"].lower())
    return JsonResponse({"status": "ok", "files": files})


@login_required
def docs_api_file(req):
    rel, abs_path = _safe_doc_abspath(req.GET.get("path"))
    if not abs_path or not os.path.isfile(abs_path):
        return JsonResponse({"status": "error", "message": "not found"}, status=404)

    try:
        size = os.path.getsize(abs_path)
    except OSError:
        return JsonResponse({"status": "error", "message": "not found"}, status=404)

    if size > 512 * 1024:
        return JsonResponse({"status": "error", "message": "file too large"}, status=413)

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return JsonResponse({"status": "error", "message": "not found"}, status=404)

    return JsonResponse({"status": "ok", "path": rel, "content": content})


@login_required
def docs_raw(req):
    rel, abs_path = _safe_doc_abspath(req.GET.get("path"))
    if not abs_path or not os.path.isfile(abs_path):
        return HttpResponse("not found", status=404, content_type="text/plain; charset=utf-8")

    try:
        size = os.path.getsize(abs_path)
    except OSError:
        return HttpResponse("not found", status=404, content_type="text/plain; charset=utf-8")

    if size > 512 * 1024:
        return HttpResponse("file too large", status=413, content_type="text/plain; charset=utf-8")

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return HttpResponse("not found", status=404, content_type="text/plain; charset=utf-8")

    resp = HttpResponse(content, content_type="text/markdown; charset=utf-8")
    resp["Content-Disposition"] = f'inline; filename="{os.path.basename(rel)}"'
    return resp


@login_required
def userinfo(req):
    from web.index.models import ApiToken

    tokens = ApiToken.objects.filter(user=req.user, is_active=True).order_by('-created_at')

    data = {
        "tokens": tokens,
        "is_admin": req.user.is_staff,
    }

    return render(req, 'dashboard/userinfo.html', data)


@login_required
def userinfo_token_create(req):
    import uuid
    from web.index.models import ApiToken

    name = (req.POST.get('name', '') or '').strip()
    token = uuid.uuid4().hex + uuid.uuid4().hex  # 64 字符

    ApiToken.objects.create(
        user=req.user,
        name=name,
        token=token,
    )
    return redirect('dashboard:userinfo')


@login_required
def userinfo_token_delete(req, token_id):
    from web.index.models import ApiToken

    ApiToken.objects.filter(id=token_id, user=req.user).update(is_active=False)
    return redirect('dashboard:userinfo')


@login_required
def code_view(req, task_id):
    """查看任务关联的源代码文件"""
    from web.index.models import ScanTask
    from utils.path_safety import safe_join, is_path_under

    task = ScanTask.objects.filter(id=task_id).first()
    if not task:
        return redirect('dashboard:tasks_list')

    scan_dir = task.source_dir or task.target_path or ''

    if not scan_dir or not os.path.isdir(scan_dir):
        return render(req, 'dashboard/tasks/code_view.html', {
            "task": task, "tree": [], "file_content": None,
            "rel_path": "", "highlight_line": None, "error": "源码目录不存在",
        })

    req_file = req.GET.get('file', '')
    req_lineno = req.GET.get('lineno', '')

    # 默认展示目录树或指定文件
    file_content = None
    rel_path = ''
    highlight_line = None
    error = None

    if req_file:
        rel_path = req_file
        # 安全校验：safe_join 解析 symlink + 规范化路径
        abs_path = safe_join(scan_dir, req_file)
        if abs_path is None or not is_path_under(abs_path, scan_dir):
            error = "Invalid file path"
        elif not os.path.isfile(abs_path):
            error = "File not found"
        else:
            try:
                with open(abs_path, 'r', encoding='utf-8', errors='replace') as f:
                    file_content = f.readlines()
            except Exception as e:
                error = str(e)
            if req_lineno:
                try:
                    highlight_line = int(req_lineno)
                except ValueError:
                    pass

    # 构建目录树（最多 3 层）
    tree = _build_file_tree(scan_dir, max_depth=3)

    data = {
        "task": task,
        "tree": tree,
        "file_content": file_content,
        "rel_path": rel_path,
        "highlight_line": highlight_line,
        "error": error,
    }
    return render(req, 'dashboard/tasks/code_view.html', data)


def _build_file_tree(root, max_depth=3, current_depth=0):
    """构建目录树供前端展示"""
    if not os.path.isdir(root) or current_depth >= max_depth:
        return []
    result = []
    try:
        entries = sorted(os.listdir(root))
    except PermissionError:
        return result
    for name in entries:
        if name.startswith('.') or name == '__pycache__':
            continue
        full = os.path.join(root, name)
        is_dir = os.path.isdir(full)
        result.append({
            'name': name,
            'path': os.path.relpath(full, root),
            'is_dir': is_dir,
            'children': _build_file_tree(full, max_depth, current_depth + 1) if is_dir else [],
        })
    return result


@login_required
def overview(req):
    try_dispatch()
    tasks = ScanTask.objects.all().order_by("-id")[:200]

    status_count = {
        "success": 0,
        "running": 0,
        "error": 0,
        "other": 0,
    }

    latest_task = None
    latest_scan_time = None

    for task in tasks:
        task_status = int(task.is_finished)
        if task_status == 1:
            status_count["success"] += 1
        elif task_status == 2:
            status_count["running"] += 1
        elif task_status in [0, -1]:
            status_count["error"] += 1
        else:
            status_count["other"] += 1

        if latest_scan_time is None and task.last_scan_time:
            latest_scan_time = timezone.localtime(
                task.last_scan_time,
                timezone.get_fixed_timezone(8 * 60)
            ).strftime("%Y-%m-%d %H:%M:%S")
            latest_task = {
                "id": task.id,
                "task_name": task.task_name,
                "target_path": task.target_path
            }

    context = {
        "tasks": tasks,
        "status_count": status_count,
        "latest_task": latest_task,
        "latest_scan_time": latest_scan_time,
    }
    return render(req, "dashboard/overview.html", context)


