#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2026/07/20
# @File    : views_verify.py
# @Desc    : 验证 API 视图

import json
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone

from web.index.models import ScanResultTask
from web.index.controller import login_or_token_required
from web.index.controller import api_token_required


@method_decorator(csrf_exempt, name='dispatch')
class TaskResultVerifyApiView(View):
    """验证单条扫描结果 (TP/FP/unknown)"""

    @staticmethod
    @api_token_required
    def post(request, result_id):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"code": 400, "error": "Invalid JSON"})

        status = data.get('status')
        notes = data.get('notes', '')
        verified_by = data.get('verified_by', request.user.username if request.user.is_authenticated else 'unknown')

        valid_statuses = ['pending', 'tp', 'fp', 'stale', 'unknown']
        if status not in valid_statuses:
            return JsonResponse({"code": 400, "error": f"Invalid status. Must be one of: {valid_statuses}"})

        try:
            result = ScanResultTask.objects.get(id=result_id)
        except ScanResultTask.DoesNotExist:
            return JsonResponse({"code": 404, "error": "Result not found"})

        result.verification_status = status
        result.verified_by = verified_by
        result.verified_at = timezone.now()
        result.verification_notes = notes
        result.save()

        return JsonResponse({
            "code": 200,
            "message": f"Result {result_id} marked as {status}",
            "data": {
                "id": result.id,
                "status": status,
                "verified_by": verified_by,
                "verified_at": result.verified_at.isoformat() if result.verified_at else None,
            }
        })


@method_decorator(csrf_exempt, name='dispatch')
class TaskVerifyBatchApiView(View):
    """批量验证任务的所有结果"""

    @staticmethod
    @api_token_required
    def post(request, task_id):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"code": 400, "error": "Invalid JSON"})

        status = data.get('status')
        verified_by = data.get('verified_by', request.user.username if request.user.is_authenticated else 'unknown')

        valid_statuses = ['pending', 'tp', 'fp', 'stale', 'unknown']
        if status not in valid_statuses:
            return JsonResponse({"code": 400, "error": f"Invalid status. Must be one of: {valid_statuses}"})

        count = ScanResultTask.objects.filter(scan_task_id=task_id).update(
            verification_status=status,
            verified_by=verified_by,
            verified_at=timezone.now()
        )

        return JsonResponse({
            "code": 200,
            "message": f"Marked {count} results as {status}",
            "data": {"count": count, "status": status}
        })
