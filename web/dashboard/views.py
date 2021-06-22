#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/23 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com


import ast

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from web.index.models import ScanTask


@login_required
def index(req):

    tasks = ScanTask.objects.all().order_by("-id")
    for task in tasks:
        task.is_finished = int(task.is_finished)
        task.parameter_config = " ".join(ast.literal_eval(task.parameter_config)).replace('\\', '/')

    data = {'tasks': tasks}

    return render(req, 'dashboard/index.html', data)


@login_required
def docs(req):
    return render(req, 'dashboard/docs.html')


@login_required
def userinfo(req):
    return render(req, 'dashboard/userinfo.html')



