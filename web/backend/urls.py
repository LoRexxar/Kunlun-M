#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 14:44
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path

from web.backend import views

app_name = "backend"
urlpatterns = [
    path('', views.index, name='index'),

    # task debug log
    path("debuglog/<int:task_id>", views.debuglog, name="debuglog"),
    # download debug log
    path("downloadlog/<int:task_id>", views.downloadlog, name="downloadlog"),
    path("export/<int:task_id>", views.exportresult, name="exportresult"),

    # upload log
    path("uploadlog", views.uploadlog, name="uploadlog")
]
