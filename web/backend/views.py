#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com

import os
import codecs
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, HttpResponse

from web.index.controller import login_or_token_required
from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc, get_resultflow_class
from utils.utils import show_context

from Kunlun_M.settings import LOGS_PATH


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

    # check task 的状态，只有完成才能继续
    if not task.is_finished:
        return HttpResponse("Ooooops, Maybe this task still in progress or has error, you can't view the log...")

    srts = ScanResultTask.objects.filter(scan_task_id=task_id)
    nefs = NewEvilFunc.objects.filter(scan_task_id=task_id)

    ResultFlow = get_resultflow_class(task_id)
    rfs = ResultFlow.objects.all()

    task.parameter_config = " ".join(eval(task.parameter_config)).replace('\\', '/')
    resultflowdict = {}

    for rf in rfs:
        if rf.vul_id not in resultflowdict:
            resultflowdict[rf.vul_id] = {
                'id': rf.vul_id,
                'flow': [],
            }

        rfdict = {
            'type': rf.node_type,
            'content': rf.node_content,
            'path': rf.node_path,
            'lineno': rf.node_lineno,
            'details': show_context(rf.node_path, rf.node_lineno, is_back=True)
        }

        resultflowdict[rf.vul_id]['flow'].append(rfdict)

    # 扫描结果
    data = {
        "task": task,
        "taskresults": srts,
        "newevilfuncs": nefs,
        "resultflowdict": resultflowdict,
        'visit_token': visit_token
    }
    return render(req, 'backend/tasklog.html', data)


@login_or_token_required
def debuglog(req, task_id):

    task = ScanTask.objects.filter(id=task_id).first()
    visit_token = ""

    if 'token' in req.GET:
        visit_token = req.GET['token']

    # check task是否存在
    if not task:
        return redirect("dashboard:tasks_list")

    # check task 的状态，只有完成才能继续
    if not task.is_finished:
        return HttpResponse("Ooooops, Maybe this task still in progress or has error, you can't view the log...")

    debuglog_filename = os.path.join(LOGS_PATH, 'ScanTask_{}.log'.format(task_id))

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

    # check task 的状态，只有完成才能继续
    if not task.is_finished:
        return HttpResponse("Ooooops, Maybe this task still in progress or has error, you can't view the log...")

    debuglog_filename = os.path.join(LOGS_PATH, 'ScanTask_{}.log'.format(task_id))

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

