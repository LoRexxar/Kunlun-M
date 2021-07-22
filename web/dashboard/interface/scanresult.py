#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: scanresult.py
@time: 2021/7/22 15:52
@desc:

'''

import os
import codecs
import json

from django.core import serializers
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, HttpResponse
from django.http import HttpResponseRedirect, JsonResponse

from django.views.generic import TemplateView
from django.views import View

from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc, Project, ProjectVendors
from web.index.models import get_and_check_scantask_project_id, get_resultflow_class, get_and_check_scanresult
from utils.utils import show_context


class ScanResultDelInterfaceView(View):
    """任务结果删除相关操作"""

    @staticmethod
    @login_required
    def get(request, vul_id):
        srt = ScanResultTask.objects.filter(id=vul_id).first()

        if not srt:
            return JsonResponse({"code": 403, "status": False, "message": "Vul {} not exist.".format(vul_id)})

        srt.is_active = False
        srt.save()

        return JsonResponse(
            {"code": 200, "status": True})
