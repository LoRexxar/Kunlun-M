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
from django.db.models import Count

from web.index.models import ScanTask, VendorVulns, Rules, Tampers, NewEvilFunc, Project, ProjectVendors
from web.index.models import get_and_check_scantask_project_id, get_resultflow_class, get_and_check_scanresult
from core.vendors import get_project_vendor_by_name, get_vendor_vul_by_name

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
        scantaskresults = list(get_and_check_scanresult(task_id).objects.filter(scan_project_id=project_id, is_active=1).values())

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


class TaskVendorsApiView(View):
    """展示当前任务组件"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        project_id = get_and_check_scantask_project_id(task_id)
        pvs = list(ProjectVendors.objects.filter(project_id=project_id).values())

        return JsonResponse(
            {"code": 200, "status": True, "message": pvs})


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


class VendorVulListApiView(View):
    """展示组件漏洞列表"""

    @staticmethod
    @api_token_required
    def get(request):
        vendorvuls = VendorVulns.objects.filter()[:100].values()

        return JsonResponse(
            {"code": 200, "status": True, "message": list(vendorvuls)})

    @staticmethod
    @api_token_required
    def post(request):
        if 'vendor_name' in request.POST:
            vendor_name = request.GET['vendor_name']
            vs = list(get_project_vendor_by_name(vendor_name))
        else:
            vs = []

        return JsonResponse(
            {"code": 200, "status": True, "message": vs})


class VendorVuLDetailApiView(View):
    """展示当前规则细节"""

    @staticmethod
    @api_token_required
    def get(request, vendor_vul_id):

        vendorvuls = VendorVulns.objects.filter(id=vendor_vul_id).values()

        return JsonResponse({"code": 200, "status": True, "message":  list(vendorvuls)})

    @staticmethod
    @api_token_required
    def post(request):
        if 'vendor_name' in request.POST:
            vendor_name = request.GET['vendor_name']
            vs = list(get_vendor_vul_by_name(vendor_name))
        else:
            vs = []

        return JsonResponse(
            {"code": 200, "status": True, "message": vs})


class VendorStatisticsApiView(View):
    """展示组件统计数据Top100"""

    @staticmethod
    @api_token_required
    def get(request):
        limit = 100
        pvs = ProjectVendors.objects.values('name', 'language').annotate(total=Count('id')).order_by('total')
        pvs = pvs[::-1][:limit]

        pv_list = list(pvs)
        id = 1
        for pv in pv_list:
            pv['id'] = id
            id += 1

        return JsonResponse({"code": 200, "status": True, "message":  pv_list})


class VendorVulStatisticsApiView(View):
    """展示组件漏洞统计数据top100"""

    @staticmethod
    @api_token_required
    def get(request):
        limit = 100
        vns = VendorVulns.objects.values('vendor_name').annotate(total=Count('id')).order_by('total')
        vns = vns[::-1][:limit]
        vn_list = list(vns)

        id = 1
        for vn in vn_list:
            vn['id'] = id
            id += 1

            vendor_name = vn['vendor_name']
            vn['id'] = id
            id += 1

            vs = get_project_vendor_by_name(vendor_name)
            vn['vendor_count'] = vs.count()

            vvs = get_vendor_vul_by_name(vendor_name)
            vn['high'] = 0
            vn['medium'] = 0
            vn['low'] = 0

            for vv in vvs:
                if vv.severity > 6:
                    vn['high'] += 1
                elif vv.severity > 2:
                    vn['medium'] += 1
                else:
                    vn['low'] += 1

        return JsonResponse({"code": 200, "status": True, "message":  vn_list})
