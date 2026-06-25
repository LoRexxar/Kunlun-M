#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com

import os
import ast
import codecs
import json
import csv
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from web.index.controller import login_or_token_required, api_token_required
from web.index.models import ScanTask, ScanResultTask, Rules, NewEvilFunc, VendorVulns, get_resultflow_class
from web.index.models import get_and_check_scantask_project_id, get_and_check_scanresult
from Kunlun_M.const import VUL_LEVEL, VENDOR_VUL_LEVEL

from Kunlun_M.settings import LOGS_PATH
from utils.path_safety import is_path_under


def _is_path_under_allowed_dir(path, allowed_dir):
    """检查路径是否在允许的目录内，防止路径遍历攻击（已迁移到 utils.path_safety）"""
    return is_path_under(path, allowed_dir)


def index(request):
    return HttpResponse("Nothing here.")

@login_or_token_required
def tasklog(req, task_id):
    task = ScanTask.objects.filter(id=task_id).first()
    visit_token = ""

    if 'token' in req.GET:
        visit_token = req.GET['token']

    # check task是否存在
    if not task:
        return redirect("dashboard:tasks_list")

    project_id = get_and_check_scantask_project_id(task_id)

    srts = list(get_and_check_scanresult(task_id).objects.filter(scan_project_id=project_id, is_active=1))
    nefs = NewEvilFunc.objects.filter(project_id=project_id)

    ResultFlow = get_resultflow_class(task_id)
    rfs = ResultFlow.objects.all() if ResultFlow else []

    task.parameter_config = " ".join(ast.literal_eval(task.parameter_config)).replace('\\', '/')

    # 构建 chain 数据（与 dashboard controller 一致）
    chain_map = {}
    for rf in rfs:
        if rf.node_type == "sca_scan":
            continue
        r = get_and_check_scanresult(task_id).objects.filter(id=rf.vul_id, is_active=1).first()
        if not r:
            continue
        chain_map.setdefault(rf.vul_id, []).append({
            'type': rf.node_type,
            'content': rf.node_content or '',
            'path': rf.node_path or '',
            'lineno': str(rf.node_lineno or ''),
            'source': rf.node_source or '',
            'vid': rf.node_vid if hasattr(rf, 'node_vid') and rf.node_vid is not None else None,
        })

    # 计算 level 和 has_chain
    for taskresult in srts:
        taskresult.is_unconfirm = int(taskresult.is_unconfirm)
        taskresult.level = 'low'
        taskresult.chain_nodes = chain_map.get(taskresult.id, [])
        taskresult.has_chain = len(taskresult.chain_nodes) > 0

        if taskresult.cvi_id == '9999':
            vender_vul_id = taskresult.vulfile_path.split(":")[-1]
            if vender_vul_id:
                vv = VendorVulns.objects.filter(id=vender_vul_id).first()
                if vv:
                    taskresult.level = VENDOR_VUL_LEVEL[vv.severity]
        else:
            r = Rules.objects.filter(svid=taskresult.cvi_id).first()
            if r:
                taskresult.level = VUL_LEVEL[r.level]

    # 构建 chain JSON 供前端使用
    chain_json_map = {}
    for tr in srts:
        if tr.has_chain:
            chain_json_map[str(tr.id)] = tr.chain_nodes
    chain_json = json.dumps(chain_json_map, ensure_ascii=False)

    data = {
        "task": task,
        "taskresults": srts,
        "newevilfuncs": nefs,
        "chain_json": chain_json,
        'visit_token': visit_token
    }
    return render(req, 'backend/tasklog.html', data)


@login_or_token_required
def tasklogtail(req, task_id):
    task = ScanTask.objects.filter(id=task_id).first()
    if not task:
        return JsonResponse({"code": 404, "status": False, "message": "Task not found."})

    offset = 0
    if "offset" in req.GET:
        try:
            offset = int(req.GET["offset"])
        except Exception:
            offset = 0
    if offset < 0:
        offset = 0

    log_path = os.path.join(LOGS_PATH, "ScanTask_{}.log".format(task_id))

    # 验证路径仍在 LOGS_PATH 目录内，防止路径遍历
    if not _is_path_under_allowed_dir(log_path, LOGS_PATH):
        return JsonResponse({"code": 400, "status": False, "message": "Bad request."})

    if not os.path.exists(log_path):
        return JsonResponse({"code": 200, "status": True, "message": {"offset": offset, "data": "", "eof": True}})

    max_bytes = 20000
    with open(log_path, "rb") as f:
        f.seek(offset)
        data = f.read(max_bytes)
        new_offset = f.tell()

    text = ""
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    eof = len(data) < max_bytes
    return JsonResponse({"code": 200, "status": True, "message": {"offset": new_offset, "data": text, "eof": eof}})


@login_or_token_required
def debuglog(req, task_id):

    task = ScanTask.objects.filter(id=task_id).first()
    visit_token = ""

    if 'token' in req.GET:
        visit_token = req.GET['token']

    # check task是否存在
    if not task:
        return redirect("dashboard:tasks_list")

    debuglog_filename = os.path.join(LOGS_PATH, 'ScanTask_{}.log'.format(task_id))

    # 验证路径仍在 LOGS_PATH 目录内，防止路径遍历
    if not _is_path_under_allowed_dir(debuglog_filename, LOGS_PATH):
        return HttpResponse("Ooooops, bad request...", status=400)

    if not os.path.exists(debuglog_filename):
        return HttpResponse("Ooooops, Log file not found...")

    f = codecs.open(debuglog_filename, "r", encoding='utf-8', errors='ignore')
    debuglog_content = f.read()
    f.close()

    data = {
        "task": task,
        "debuglog_content": debuglog_content,
        'visit_token': visit_token
    }
    return render(req, 'backend/debuglog.html', data)


@login_or_token_required
def downloadlog(req, task_id):
    task = ScanTask.objects.filter(id=task_id).first()

    # check task是否存在
    if not task:
        return redirect("dashboard:tasks_list")

    debuglog_filename = os.path.join(LOGS_PATH, 'ScanTask_{}.log'.format(task_id))

    # 验证路径仍在 LOGS_PATH 目录内，防止路径遍历
    if not _is_path_under_allowed_dir(debuglog_filename, LOGS_PATH):
        return HttpResponse("Ooooops, bad request...", status=400)

    if not os.path.exists(debuglog_filename):
        return HttpResponse("Ooooops, Log file not found...")

    f = codecs.open(debuglog_filename, "r", encoding='utf-8', errors='ignore')
    debuglog_content = f.read()
    f.close()

    path_to_file = debuglog_filename
    response = HttpResponse(debuglog_content, content_type='application/force-download')
    response['Content-Disposition'] = 'attachment; filename=ScanTask_%s' % task_id + ".log"
    response['X-Sendfile'] = path_to_file
    return response


@login_or_token_required
def exportresult(req, task_id):
    task = ScanTask.objects.filter(id=task_id).first()
    if not task:
        return HttpResponse("Task not found.", status=404)

    fmt = (req.GET.get("format", "json") or "json").lower()
    project_id = get_and_check_scantask_project_id(task_id)
    rows = list(get_and_check_scanresult(task_id).objects.filter(scan_project_id=project_id, is_active=1).values())

    if fmt == "csv":
        resp = HttpResponse(content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = "attachment; filename=ScanTask_{}_result.csv".format(task_id)
        if not rows:
            return resp

        fieldnames = list(rows[0].keys())
        w = csv.DictWriter(resp, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
        return resp

    if fmt == "html":
        html_parts = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            "<title>ScanTask {} Report</title>".format(task_id),
            "<style>body{font-family:sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}tr:nth-child(even){background:#fafafa}.meta{margin-bottom:20px;color:#666}</style>",
            "</head><body>",
            "<div class='meta'><h2>ScanTask #{} Report</h2>".format(task_id),
            "<p>Task: {} | Target: {} | Total: {}</p>".format(
                getattr(task, 'task_name', task_id), getattr(task, 'target_path', ''), len(rows)),
            "</div>",
            "<table><thead><tr>",
        ]
        if rows:
            for k in rows[0].keys():
                html_parts.append("<th>{}</th>".format(k))
        html_parts.append("</tr></thead><tbody>")
        for r in rows:
            html_parts.append("<tr>")
            for v in r.values():
                html_parts.append("<td>{}</td>".format(str(v) if v is not None else ''))
            html_parts.append("</tr>")
        html_parts.append("</tbody></table></body></html>")

        resp = HttpResponse('\n'.join(html_parts), content_type="text/html; charset=utf-8")
        resp["Content-Disposition"] = "attachment; filename=ScanTask_{}_result.html".format(task_id)
        return resp

    if fmt == "md":
        md_parts = [
            "# ScanTask #{} Report".format(task_id),
            "",
            "- **Task**: {}".format(getattr(task, 'task_name', task_id)),
            "- **Target**: {}".format(getattr(task, 'target_path', '')),
            "- **Total**: {}".format(len(rows)),
            "",
        ]
        if rows:
            headers = list(rows[0].keys())
            md_parts.append("| " + " | ".join(headers) + " |")
            md_parts.append("| " + " | ".join(["---"] * len(headers)) + " |")
            for r in rows:
                md_parts.append("| " + " | ".join(str(v) if v is not None else '' for v in r.values()) + " |")
        md_parts.append("")

        resp = HttpResponse('\n'.join(md_parts), content_type="text/markdown; charset=utf-8")
        resp["Content-Disposition"] = "attachment; filename=ScanTask_{}_result.md".format(task_id)
        return resp

    resp = JsonResponse({"code": 200, "status": True, "message": rows})
    resp["Content-Disposition"] = "attachment; filename=ScanTask_{}_result.json".format(task_id)
    return resp


# 使用 @csrf_exempt 是因为此接口通过 API Token 认证而非浏览器 Session，
# API 客户端无法提供 CSRF Token，因此通过 @api_token_required 进行鉴权保护
@csrf_exempt
@api_token_required
def uploadlog(req):
    if "file" not in req.FILES:
        return HttpResponse("Ooooops, bad request...")

    logfile = req.FILES.get("file", None)

    # 仅取文件名，防止通过路径组件进行路径遍历
    logfile_name = os.path.basename(logfile.name)

    logfile_path = os.path.join(LOGS_PATH, logfile_name)

    # 验证目标路径仍在 LOGS_PATH 目录内
    if not _is_path_under_allowed_dir(logfile_path, LOGS_PATH):
        return HttpResponse("Ooooops, bad request...", status=400)

    if os.path.exists(logfile_path):
        return HttpResponse("Ooooops, log file {} exist...".format(logfile_name))

    with open(logfile_path, 'wb') as f:
        for chunk in logfile.chunks():
            f.write(chunk)

    return HttpResponse("Success")
