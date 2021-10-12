#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: controller.py
@time: 2021/6/16 18:07
@desc:

'''


from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, JsonResponse

from web.index.models import ScanTask

from Kunlun_M.settings import API_TOKEN


def login_or_token_required(function):

    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            return function(request, *args, **kwargs)
        else:
            if "token" in request.GET:
                task_id = kwargs['task_id'] if 'task_id' in kwargs else 0

                task = ScanTask.objects.filter(id=task_id).first()

                if request.GET['token'] == task.visit_token:
                    return function(request, *args, **kwargs)
             
            next = request.get_full_path()
            red = HttpResponseRedirect('/login/?next=' + next)
            return red

    return wrapper


def api_token_required(function):

    def wrapper(request, *args, **kwargs):

        if "apitoken" in request.GET:

            if request.GET['apitoken'] == API_TOKEN:
                return function(request, *args, **kwargs)

        elif "apitoken" in request.POST:

            if request.POST['apitoken'] == API_TOKEN:
                return function(request, *args, **kwargs)

        return JsonResponse({"code": 401, "status": "error", "message": "Auth check error. token required."})

    return wrapper
