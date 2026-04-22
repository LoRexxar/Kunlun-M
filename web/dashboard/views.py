#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/23 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import JsonResponse
from web.index.models import ScanTask, Project
from web.index.models import get_and_check_scantask_project_id

from utils.utils import del_sensitive_for_config

from Kunlun_M.settings import API_TOKEN


@login_required
def index(req):

    tasks = ScanTask.objects.all().order_by("-id")[:100]
    for task in tasks:
        task.is_finished = int(task.is_finished)
        task.parameter_config = del_sensitive_for_config(task.parameter_config)

        project_id = get_and_check_scantask_project_id(task.id)
        project = Project.objects.filter(id=project_id).first()

        task.project_name = project.project_name

    data = {'tasks': tasks}

    return render(req, 'dashboard/index.html', data)


@login_required
def docs(req):
    return render(req, 'dashboard/docs.html')


@login_required
def userinfo(req):

    data = {
        "apitoken": API_TOKEN
    }

    return render(req, 'dashboard/userinfo.html', data)


@login_required
def overview(req):
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
            latest_scan_time = str(task.last_scan_time)
            latest_task = {
                "id": task.id,
                "task_name": task.task_name,
                "target_path": task.target_path
            }

    return JsonResponse({
        "status": "ok",
        "count": len(tasks),
        "task_status": status_count,
        "latest_scan_time": latest_scan_time,
        "latest_task": latest_task
    })


