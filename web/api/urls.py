#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 14:44
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path

from web.api import views

app_name = "api"
urlpatterns = [
    path('', views.index, name='index'),

    # task list
    path("task/list", views.TaskListApiView.as_view(), name="task_list"),
    # task details
    path("task/<int:task_id>", views.TaskDetailApiView.as_view(), name="task_detail"),
    # task result details
    path("task/<int:task_id>/result", views.TaskResultDetailApiView.as_view(), name="task_result_detail"),
    # task resultflow details
    path("task/<int:task_id>/resultflow", views.TaskResultFlowDetailApiView.as_view(), name="task_resultflow_detail"),
    # task new evil func
    path("task/<int:task_id>/newevilfunc", views.TaskNewEvilFuncApiView.as_view(), name="task_new_evil_func_detail"),
    # task vendors
    path("task/<int:task_id>/vendors", views.TaskVendorsApiView.as_view(), name="task_vendors"),

    # rule list
    path("rule/list", views.RuleListApiView.as_view(), name="rule_list"),
    # rule details
    path("rule/<int:rule_cviid>", views.RuleDetailApiView.as_view(), name="rule_detail"),

    # vendor vul list
    path("vendorvul/list", views.VendorVulListApiView.as_view(), name="vendor_vul_list"),
    # vendor vul details
    path("vendorvul/<int:vendor_vul_id>", views.VendorVuLDetailApiView.as_view(), name="vendor_vul_detail"),
]
