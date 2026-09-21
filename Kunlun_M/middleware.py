#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: middleware.py
@time: 2020/12/4 17:02
@desc:

'''

import time

from web.index.models import ScanTask, ScanResultTask, Rules, FrameworkTamper, Project, VendorVulns

# 内存缓存：存储统计查询结果，避免每次请求都查询数据库
_cache = {}
_CACHE_TTL = 30  # 缓存有效期 30 秒


def _get_cached_count(key, query_func):
    """获取缓存计数，过期则重新查询数据库"""
    now = time.time()
    if key in _cache:
        value, expiry = _cache[key]
        if now < expiry:
            return value
    value = query_func()
    _cache[key] = (value, now + _CACHE_TTL)
    return value


class NoCacheHTMLMiddleware:
    """HTML 页面禁止浏览器缓存，避免发版后浏览器渲染旧页面（静态资源仍走 Last-Modified 启发式缓存）"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        content_type = response.get("Content-Type", "")
        if content_type.startswith("text/html"):
            response["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response["Pragma"] = "no-cache"
        return response


class SDataMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if request.user.is_authenticated:
            # 使用缓存查询统计计数，减少数据库访问次数
            request.session["rules_count"] = _get_cached_count(
                "rules_count", lambda: Rules.objects.count())
            request.session["project_count"] = _get_cached_count(
                "project_count", lambda: Project.objects.count())
            request.session["tasks_count"] = _get_cached_count(
                "tasks_count", lambda: ScanTask.objects.count())
            request.session["tasks_finished_count"] = _get_cached_count(
                "tasks_finished_count", lambda: ScanTask.objects.filter(is_finished=1).count())
            request.session["tampers_count"] = _get_cached_count(
                "tampers_count", lambda: FrameworkTamper.objects.all().count())
            request.session["vendor_vuls_count"] = _get_cached_count(
                "vendor_vuls_count", lambda: VendorVulns.objects.count())
            request.session["vul_count"] = _get_cached_count(
                "vul_count", lambda: ScanResultTask.objects.filter(is_active=1).count())

        return response
