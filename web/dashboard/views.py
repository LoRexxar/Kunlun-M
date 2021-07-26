#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/23 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from web.index.models import ScanTask, Project
from web.index.models import get_and_check_scantask_project_id

from utils.utils import del_sensitive_for_config

from Kunlun_M.settings import API_TOKEN


@login_required
def index(req):

    tasks = ScanTask.objects.all().order_by("-id")
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



