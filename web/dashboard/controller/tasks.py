#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/3/2 15:15
# @Author  : LoRexxar
# @File    : tasks.py
# @Contact : lorexxar@gmail.com

import ast
import re
import os
import json
import zipfile

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect
from django.utils import timezone

from Kunlun_M.settings import SUPER_ADMIN
from Kunlun_M.const import VENDOR_VUL_LEVEL, VUL_LEVEL
from Kunlun_M import settings

from web.index.controller import login_or_token_required
from utils.utils import del_sensitive_for_config

from web.index.models import ScanTask, VendorVulns, Rules, FrameworkTamper, NewEvilFunc, Project
from web.index.models import get_and_check_scantask_project_id, get_and_check_scanresult, get_and_check_evil_func, check_and_new_project_id


class TaskListView(TemplateView):
    """展示当前用户的任务"""
    template_name = "dashboard/tasks/tasks_list.html"

    def get_context_data(self, **kwargs):
        try:
            from web.index.scan_dispatcher import try_dispatch
            try_dispatch()
        except Exception:
            pass
        context = super(TaskListView, self).get_context_data(**kwargs)
        task_count = ScanTask.objects.all().count()

        if 'p' in self.request.GET:
            page = int(self.request.GET['p'])
        else:
            page = 1

        # check page
        if page*50 > task_count:
            page = 1

        rows = ScanTask.objects.all().order_by('-id')[(page-1)*50: page*50]

        context['tasks'] = rows

        context['page'] = page
        max_page = task_count / 50 if task_count % 50 == 0 else (task_count / 50)+1
        context['max_page'] = max_page
        context['page_range'] = range(int(max_page))[1:]

        for task in context['tasks']:
            task.is_finished = int(task.is_finished)
            task.parameter_config = del_sensitive_for_config(task.parameter_config)

            project_id = get_and_check_scantask_project_id(task.id)
            project = Project.objects.filter(id=project_id).first()

            task.project_name = project.project_name

        return context


class TaskNewView(View):
    def get(self, request):
        max_mb = int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50))
        allowed_paths = getattr(settings, "WEB_SCAN_ALLOWED_PATHS", [])
        path_scan_disabled = not bool(allowed_paths)
        return render(request, "dashboard/tasks/task_upload.html", {
            "error_message": "",
            "max_mb": max_mb,
            "path_scan_disabled": path_scan_disabled,
        })

    def post(self, request):
        if "archive" not in request.FILES:
            max_mb = int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50))
            return render(request, "dashboard/tasks/task_upload.html", {"error_message": "请先选择 zip 文件。", "max_mb": max_mb})

        archive = request.FILES.get("archive", None)
        if not archive:
            max_mb = int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50))
            return render(request, "dashboard/tasks/task_upload.html", {"error_message": "请先选择 zip 文件。", "max_mb": max_mb})

        max_bytes = int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50)) * 1024 * 1024
        if hasattr(archive, "size") and archive.size and int(archive.size) > max_bytes:
            max_mb = int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50))
            return render(request, "dashboard/tasks/task_upload.html", {"error_message": "文件过大，已超过 {}MB。".format(max_mb), "max_mb": max_mb})

        filename = getattr(archive, "name", "") or ""
        if not filename.lower().endswith(".zip"):
            max_mb = int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50))
            return render(request, "dashboard/tasks/task_upload.html", {"error_message": "仅支持 .zip 文件。", "max_mb": max_mb})

        task_name = os.path.splitext(os.path.basename(filename))[0] or "web_upload"

        task = ScanTask(
            task_name=task_name,
            target_path="",
            parameter_config=repr(["web", "upload", filename]),
            is_finished=3,
            source_type="upload",
            options_json=json.dumps({}, ensure_ascii=False),
            created_at=timezone.now(),
            last_scan_time=timezone.now(),
        )
        task.save()

        task_dir = os.path.join(settings.PACKAGE_PATH, str(task.id))
        upload_path = os.path.join(task_dir, "upload.zip")
        extract_root = os.path.join(task_dir, "src")
        try:
            if not os.path.isdir(task_dir):
                os.makedirs(task_dir, exist_ok=True)
            with open(upload_path, "wb") as f:
                for chunk in archive.chunks():
                    f.write(chunk)
            self._safe_extract_zip(upload_path, extract_root)
        except Exception as e:
            task.is_finished = 0
            task.finished_at = timezone.now()
            task.error_message = str(e)[:2000]
            task.exit_code = -1
            task.save()
            return redirect("dashboard:task_detail", task_id=task.id)

        scan_dir = self._pick_scan_root(extract_root)
        task.target_path = scan_dir
        task.source_archive = upload_path
        task.source_dir = scan_dir
        task.save()

        return redirect("dashboard:task_config", task_id=task.id)

    @staticmethod
    def _pick_scan_root(extract_root):
        try:
            children = [p for p in os.listdir(extract_root) if p not in [".", ".."]]
        except Exception:
            return extract_root

        if len(children) != 1:
            return extract_root

        only = os.path.join(extract_root, children[0])
        if os.path.isdir(only):
            return only
        return extract_root

    @staticmethod
    def _safe_extract_zip(zip_path, dest_dir):
        abs_dest = os.path.abspath(dest_dir)
        if not os.path.isdir(abs_dest):
            os.makedirs(abs_dest, exist_ok=True)

        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                name = info.filename
                if not name:
                    continue
                if name.endswith("/") or name.endswith("\\"):
                    continue

                joined = os.path.abspath(os.path.join(abs_dest, name))
                if not (joined == abs_dest or joined.startswith(abs_dest + os.sep)):
                    raise ValueError("Unsafe zip entry.")

                parent = os.path.dirname(joined)
                if not os.path.isdir(parent):
                    os.makedirs(parent, exist_ok=True)

                with zf.open(info) as src, open(joined, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)


class TaskConfigView(View):
    def get(self, request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        if not task:
            return HttpResponseNotFound("Task Not Found.")

        opts = {}
        try:
            opts = json.loads(task.options_json) if task.options_json else {}
        except Exception:
            opts = {}

        options = {
            "language": (opts.get("language", "") or "").strip(),
            "special_rules": (opts.get("special_rules", "") or "").strip(),
            "tamper_name": (opts.get("tamper_name", "") or "").strip(),
            "black_path": (opts.get("black_path", "") or "").strip(),
            "unconfirm": int(opts.get("unconfirm", 0) or 0),
            "unprecom": int(opts.get("unprecom", 0) or 0),
            "without_vendor": int(opts.get("without_vendor", 0) or 0),
        }

        archive_name = os.path.basename(task.source_archive) if task.source_archive else ""
        project = Project.objects.filter(id=task.project_id).first()
        project_des = project.project_des if project and project.project_des else ""
        vendor_globally_off = not bool(getattr(settings, "WITH_VENDOR", False))

        # 获取可用 tamper 列表供下拉选择
        tamper_names = list(FrameworkTamper.objects.values_list('name', flat=True).order_by('name'))

        data = {
            "task": task,
            "options": options,
            "archive_name": archive_name,
            "project_des": project_des,
            "vendor_globally_off": vendor_globally_off,
            "tamper_names": tamper_names,
            "error_message": "",
        }
        return render(request, "dashboard/tasks/task_config.html", data)

    def post(self, request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        if not task:
            return HttpResponseNotFound("Task Not Found.")

        if int(task.is_finished) in [0, 1, 2]:
            return redirect("dashboard:task_detail", task_id=task.id)

        task_name = (request.POST.get("task_name", "") or "").strip()
        if not task_name:
            task_name = task.task_name

        project_des = (request.POST.get("description", "") or "").strip()

        options = {
            "language": (request.POST.get("language", "") or "").strip(),
            "special_rules": (request.POST.get("special_rules", "") or "").strip(),
            "tamper_name": (request.POST.get("tamper_name", "") or "").strip(),
            "black_path": (request.POST.get("black_path", "") or "").strip(),
            "unconfirm": 1 if (request.POST.get("unconfirm", "") or "").strip() else 0,
            "unprecom": 1 if (request.POST.get("unprecom", "") or "").strip() else 0,
            "without_vendor": 1 if (request.POST.get("without_vendor", "") or "").strip() else 0,
        }

        task.task_name = task_name
        task.options_json = json.dumps(options, ensure_ascii=False)
        task.last_scan_time = timezone.now()
        task.is_finished = 3
        task.save()

        origin_label = {"upload": "Upload", "path": "Local"}.get(task.source_type, "Unknown")
        check_and_new_project_id(task.id, task_name, origin_label, project_des=project_des)

        from web.index.scan_dispatcher import try_dispatch
        try_dispatch()

        return redirect("dashboard:task_detail", task_id=task.id)


class TaskDetailView(View):
    """展示当前任务细节"""

    @staticmethod
    @login_or_token_required
    def get(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        visit_token = ""

        if 'token' in request.GET:
            visit_token = request.GET['token']

        project_id = get_and_check_scantask_project_id(task.id)
        project = Project.objects.filter(id=project_id).first()

        taskresults = get_and_check_scanresult(task.id).objects.filter(scan_project_id=project_id, is_active=1).all()
        newevilfuncs = get_and_check_evil_func(task.id)

        # 加载漏洞链数据
        chain_map = {}
        try:
            from web.index.models import get_resultflow_class
            RF = get_resultflow_class(task.id)
            if RF:
                for rf in RF.objects.all().order_by('id'):
                    chain_map.setdefault(rf.vul_id, []).append({
                        'type': rf.node_type,
                        'content': rf.node_content or '',
                        'path': rf.node_path or '',
                        'lineno': str(rf.node_lineno or ''),
                        'source': rf.node_source or '',
                        'vid': rf.node_vid if hasattr(rf, 'node_vid') and rf.node_vid is not None else None,
                    })
        except Exception as e:
            import logging
            logging.getLogger('django').warning('[chain] load chain data failed: %s', e)

        task.is_finished = int(task.is_finished)
        task.parameter_config = del_sensitive_for_config(task.parameter_config)

        # 确定 source_root 用于路径截断
        source_root = task.source_dir or task.target_path or ''

        for taskresult in taskresults:
            taskresult.is_unconfirm = int(taskresult.is_unconfirm)
            taskresult.level = 0
            taskresult.chain_nodes = chain_map.get(taskresult.id, [])
            taskresult.has_chain = len(taskresult.chain_nodes) > 0

            if taskresult.cvi_id == '9999':
                vender_vul_id = taskresult.vulfile_path.split(":")[-1]

                if vender_vul_id:
                    vv = VendorVulns.objects.filter(id=vender_vul_id).first()

                    if vv:
                        taskresult.vulfile_path = "[{}]{}".format(vv.vendor_name, vv.title)
                        taskresult.level = VENDOR_VUL_LEVEL[vv.severity]
                        taskresult.vid = vv.id

                    # 处理多个refer的显示问题
                    references = []
                    if re.search(r'"http[^"]+"', taskresult.source_code, re.I):
                        rs = re.findall(r'"http[^"]+"', taskresult.source_code, re.I)
                        for r in rs:
                            references.append(r.strip('"'))
                    else:
                        references = [taskresult.source_code.strip('"')]

                    taskresult.source_code = references

            else:
                r = Rules.objects.filter(svid=taskresult.cvi_id).first()
                taskresult.level = VUL_LEVEL[r.level]

        # 构建 chain JSON 供前端使用
        chain_json_map = {}
        for tr in taskresults:
            if tr.has_chain:
                chain_json_map[str(tr.id)] = tr.chain_nodes
        import json as _json
        chain_json = _json.dumps(chain_json_map, ensure_ascii=False)

        if not task:
            return HttpResponseNotFound('Task Not Found.')
        else:
            data = {
                'task': task,
                'taskresults': taskresults,
                'newevilfuncs': newevilfuncs,
                'visit_token': visit_token,
                'project': project,
                'source_root': source_root,
                'chain_json': chain_json,
            }
            return render(request, 'dashboard/tasks/task_detail.html', data)


class TaskPathView(View):
    """通过服务器本地路径创建扫描任务"""

    def post(self, request):
        allowed_paths = getattr(settings, "WEB_SCAN_ALLOWED_PATHS", [])
        if not allowed_paths:
            return render(request, "dashboard/tasks/task_upload.html", {
                "error_message": "",
                "max_mb": int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50)),
                "path_scan_disabled": True,
                "path_error": "本地路径扫描未启用。请在 settings.py 中配置 WEB_SCAN_ALLOWED_PATHS。",
            })

        target_path = (request.POST.get("target_path", "") or "").strip()
        if not target_path:
            return render(request, "dashboard/tasks/task_upload.html", {
                "error_message": "",
                "max_mb": int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50)),
                "path_scan_disabled": False,
                "path_error": "请输入项目路径",
                "submitted_path": target_path,
            })

        target_path = os.path.abspath(os.path.expanduser(target_path))

        if not os.path.isdir(target_path):
            return render(request, "dashboard/tasks/task_upload.html", {
                "error_message": "",
                "max_mb": int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50)),
                "path_scan_disabled": False,
                "path_error": "路径不存在或不是目录: {}".format(target_path),
                "submitted_path": request.POST.get("target_path", ""),
            })

        if "*" not in allowed_paths:
            real_path = os.path.realpath(target_path)
            matched = False
            for allowed_dir in allowed_paths:
                real_allowed = os.path.realpath(os.path.abspath(allowed_dir))
                if real_path == real_allowed or real_path.startswith(real_allowed + os.sep):
                    matched = True
                    break
            if not matched:
                return render(request, "dashboard/tasks/task_upload.html", {
                    "error_message": "",
                    "max_mb": int(getattr(settings, "WEB_UPLOAD_MAX_MB", 50)),
                    "path_scan_disabled": False,
                    "path_error": "路径不在允许的扫描范围内。允许的目录: {}".format(", ".join(allowed_paths)),
                    "submitted_path": request.POST.get("target_path", ""),
                })

        task_name = (request.POST.get("task_name", "") or "").strip()
        if not task_name:
            task_name = os.path.basename(target_path.rstrip(os.sep)) or "unnamed"

        task = ScanTask(
            task_name=task_name,
            target_path=target_path,
            parameter_config=repr(["web", "path", target_path]),
            is_finished=3,
            source_type="path",
            options_json=json.dumps({}, ensure_ascii=False),
            created_at=timezone.now(),
            last_scan_time=timezone.now(),
        )
        task.save()

        return redirect("dashboard:task_config", task_id=task.id)
