#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/8 16:29
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path
from django.contrib.auth.decorators import login_required

from web.dashboard import views
from web.dashboard.controller import tasks, rules, tampers, project, vendor
from web.dashboard.interface import scanresult

app_name = "dashboard"
urlpatterns = [
    path('', views.index, name='index'),

    # task
    path('tasks/list', login_required(tasks.TaskListView.as_view()), name='tasks_list'),
    path('tasks/detail/<int:task_id>', tasks.TaskDetailView.as_view(), name="task_detail"),

    # projects
    path('projects/list', login_required(project.ProjectListView.as_view()), name='projects_list'),
    path('projects/detail/<int:project_id>', project.ProjectDetailView.as_view(), name="project_detail"),

    # rule
    path('rules/list', login_required(rules.RuleListView.as_view()), name='rules_list'),
    path('rules/detail/<int:rule_id>', rules.RuleDetailView.as_view(), name="rule_detail"),

    # tamper
    path('tampers/list', login_required(tampers.TamperListView.as_view()), name='tampers_list'),
    path('tampers/detail/<int:tamper_id>', tampers.TamperDetailView.as_view(), name="tamper_detail"),

    # vendor
    path('vendors/search', login_required(vendor.VendorDetailView.as_view()), name='vendor_details'),
    path('vendors/list', login_required(vendor.VendorListView.as_view()), name='vendors_list'),
    path('vendorvulns/<int:vendor_vul_id>', login_required(vendor.VendorVulnDetailView.as_view()), name='vendor_vulns_details'),
    path('vendorvulns/list', login_required(vendor.VendorVulnListView.as_view()), name='vendor_vulns_list'),

    # docs
    path("docs", views.docs, name="docs"),

    # user
    path("userinfo", views.userinfo, name="userinfo"),

    # interface
    # scan result
    path('vuls/<int:vul_id>/del', scanresult.ScanResultDelInterfaceView.as_view(), name="vul_del"),
]
