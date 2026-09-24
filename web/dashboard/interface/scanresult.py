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
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie

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


class ScanResultVerifyView(View):
    """标记扫描结果为确认(TP)或误报(FP)"""

    @staticmethod
    @login_required
    def post(request, vul_id):
        srt = ScanResultTask.objects.filter(id=vul_id, is_active=True).first()
        if not srt:
            return JsonResponse({"code": 404, "status": False, "message": "结果不存在"})

        action = (request.POST.get("action") or "").strip().lower()
        if action not in ("tp", "fp", "unconfirm"):
            return JsonResponse({"code": 400, "status": False, "message": "无效操作，可选: tp, fp, unconfirm"})

        if action == "unconfirm":
            srt.verification_status = ''
            srt.verified_by = ''
            srt.verified_at = None
            srt.verification_notes = ''
            srt.is_unconfirm = True
        else:
            srt.verification_status = action
            srt.verified_by = request.user.username
            srt.verified_at = timezone.now()
            srt.verification_notes = (request.POST.get("notes") or "")[:500]
            srt.is_unconfirm = (action != 'tp')

        srt.save(update_fields=[
            'verification_status', 'verified_by', 'verified_at',
            'verification_notes', 'is_unconfirm'
        ])

        return JsonResponse({"code": 200, "status": True})

class ScanResultBulkVerifyView(View):
    """批量标记扫描结果 (tp/fp/unconfirm/stale)"""

    @staticmethod
    @login_required
    def post(request):
        import json
        from django.db import transaction

        try:
            payload = json.loads(request.body or "{}")
        except ValueError:
            return JsonResponse({"code": 400, "status": False, "message": "invalid json"})

        ids = payload.get("ids") or []
        action = (payload.get("action") or "").strip().lower()
        notes = (payload.get("notes") or "")[:500]

        if not ids:
            return JsonResponse({"code": 400, "status": False, "message": "ids required"})
        if action not in ("tp", "fp", "stale", "unconfirm"):
            return JsonResponse({"code": 400, "status": False, "message": "无效操作"})

        try:
            ids = [int(i) for i in ids]
        except (TypeError, ValueError):
            return JsonResponse({"code": 400, "status": False, "message": "invalid ids"})

        updated = 0
        with transaction.atomic():
            rows = ScanResultTask.objects.filter(id__in=ids, is_active=True)
            for srt in rows:
                if action == "unconfirm":
                    srt.verification_status = ''
                    srt.verified_by = ''
                    srt.verified_at = None
                    srt.verification_notes = ''
                    srt.is_unconfirm = True
                else:
                    srt.verification_status = action
                    srt.verified_by = request.user.username
                    srt.verified_at = timezone.now()
                    srt.verification_notes = notes
                    srt.is_unconfirm = (action != 'tp')
                srt.save(update_fields=[
                    'verification_status', 'verified_by', 'verified_at',
                    'verification_notes', 'is_unconfirm'
                ])
                updated += 1

        return JsonResponse({"code": 200, "status": True, "updated": updated})
