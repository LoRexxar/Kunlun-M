#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com

import os
import codecs
import json

from django.core import serializers
from django.shortcuts import render, redirect, HttpResponse
from django.http import HttpResponseRedirect, JsonResponse

from web.index.controller import login_or_token_required, api_token_required
from django.views.generic import TemplateView
from django.views import View

from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc, Project
from web.index.models import get_and_check_scantask_project_id, get_resultflow_class, get_and_check_scanresult
from utils.utils import show_context

from Kunlun_M.settings import LOGS_PATH


def index(request):
    return HttpResponse("Nothing here.")


class TaskListApiView(View):
    """展示当前任务列表"""

    @staticmethod
    @api_token_required
    def get(request):

        scantasks = ScanTask.objects.all().order_by('-id')
        scantaskidlist = []

        for scantask in scantasks:
            scantaskdata = {
                "id": scantask.id,
                "taskname": scantask.task_name,
                "is_finished": scantask.is_finished,
            }

            scantaskidlist.append(scantaskdata)

        scantasklist = {"code": 200, "status": True, "message": scantaskidlist}

        return JsonResponse(scantasklist)


class TaskDetailApiView(View):
    """展示当前任务细节"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).values()

        return JsonResponse({"code": 200, "status": True, "message":  list(scantask)})


class TaskResultDetailApiView(View):
    """展示当前任务结果细节"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        project_id = get_and_check_scantask_project_id(task_id)
        scantaskresults = list(get_and_check_scanresult(task_id).objects.filter(scan_project_id=project_id).values())

        return JsonResponse(
            {"code": 200, "status": True, "message": scantaskresults})


class TaskResultFlowDetailApiView(View):
    """展示当前任务结果流细节"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        ResultFlow = get_resultflow_class(int(task_id))
        rfs = ResultFlow.objects.filter().order_by('vul_id')

        resultflow_list = list(rfs.values())
        return JsonResponse(
            {"code": 200, "status": True, "message": resultflow_list})


class TaskNewEvilFuncApiView(View):
    """展示当前任务生成的新恶意函数"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        project_id = get_and_check_scantask_project_id(task_id)
        nefs = list(NewEvilFunc.objects.filter(project_id=project_id).values())

        return JsonResponse(
            {"code": 200, "status": True, "message": nefs})


class RuleListApiView(View):
    """展示规则列表"""

    @staticmethod
    @api_token_required
    def get(request):
        rules = Rules.objects.filter().values()

        return JsonResponse(
            {"code": 200, "status": True, "message": list(rules)})


class RuleDetailApiView(View):
    """展示当前规则细节"""

    @staticmethod
    @api_token_required
    def get(request, rule_cviid):
        rules = Rules.objects.filter(svid=rule_cviid).values()

        return JsonResponse({"code": 200, "status": True, "message":  list(rules)})
