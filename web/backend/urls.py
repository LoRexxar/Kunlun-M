#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 14:44
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path

from web.backend import views

from django.views.decorators.csrf import csrf_exempt

app_name = "backend"
urlpatterns = [
    path('', views.index, name='index'),

    # task log
    path("tasklog/<int:task_id>", views.tasklog, name="tasklog"),
    # task debug log
    path("debuglog/<int:task_id>", views.debuglog, name="debuglog"),
    # download debug log
    path("downloadlog/<int:task_id>", views.downloadlog, name="downloadlog"),

    # upload log
    path("uploadlog", csrf_exempt(views.uploadlog), name="uploadlog")
]
