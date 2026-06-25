#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: scanresult.py
@time: 2021/7/22 15:52
@desc:

'''

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views import View

from web.index.models import ScanResultTask


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
