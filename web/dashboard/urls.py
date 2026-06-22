#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/8 16:29
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path
from django.contrib.auth.decorators import login_required

from web.dashboard import views
from web.dashboard.controller import tasks, rules, tampers, project, vendor, files, graph_analysis
from web.dashboard.interface import scanresult

app_name = "dashboard"
urlpatterns = [
    path('', views.index, name='index'),

    # task
    path('tasks/list', login_required(tasks.TaskListView.as_view()), name='tasks_list'),
    path('tasks/detail/<int:task_id>', tasks.TaskDetailView.as_view(), name="task_detail"),
    path('tasks/new', login_required(tasks.TaskNewView.as_view()), name="task_new"),
    path('tasks/path/', login_required(tasks.TaskPathView.as_view()), name='task_path'),
    path('tasks/config/<int:task_id>', login_required(tasks.TaskConfigView.as_view()), name="task_config"),

    # projects
    path('projects/list', login_required(project.ProjectListView.as_view()), name='projects_list'),
    path('projects/detail/<int:project_id>', project.ProjectDetailView.as_view(), name="project_detail"),
    path('projects/<int:project_id>/files', login_required(files.ProjectFilesView.as_view()), name='project_files'),
    path('projects/<int:project_id>/files/api', files.ProjectFilesApiView.as_view(), name='project_files_api'),
    path('projects/<int:project_id>/files/content', files.ProjectFileContentApiView.as_view(), name='project_files_content'),

    # rule
    path('rules/list', login_required(rules.RuleListView.as_view()), name='rules_list'),
    path('rules/detail/<int:rule_id>', rules.RuleDetailView.as_view(), name="rule_detail"),
    path('rules/source/<int:rule_id>', rules.RuleSourceJsonView.as_view(), name="rule_source"),

    # tamper
    path('tampers/list', login_required(tampers.TamperListView.as_view()), name='tampers_list'),
    path('tampers/detail/<tamper_id>', tampers.TamperDetailView.as_view(), name="tamper_detail"),
    path('tampers/sources', tampers.TamperSourceJsonView.as_view(), name="tamper_sources"),

    # vendor
    path('vendors/search', login_required(vendor.VendorDetailView.as_view()), name='vendor_details'),
    path('vendors/list', login_required(vendor.VendorListView.as_view()), name='vendors_list'),
    path('vendors/statistics', login_required(vendor.VendorStatisticsView.as_view()), name='vendors_statistics'),
    path('vendorvulns/<int:vendor_vul_id>', login_required(vendor.VendorVulnDetailView.as_view()), name='vendor_vulns_details'),
    path('vendorvulns/list', login_required(vendor.VendorVulnListView.as_view()), name='vendor_vulns_list'),
    path('vendorvulns/statistics', login_required(vendor.VendorVulnStatisticsView.as_view()), name='vendors_vulns_statistics'),

    # docs
    path("docs", views.docs, name="docs"),
    path("docs/api/list", views.docs_api_list, name="docs_api_list"),
    path("docs/api/file", views.docs_api_file, name="docs_api_file"),
    path("docs/raw", views.docs_raw, name="docs_raw"),

    # user
    path("userinfo", views.userinfo, name="userinfo"),
    path('user/token/create', views.userinfo_token_create, name='userinfo_token_create'),
    path('user/token/delete/<int:token_id>', views.userinfo_token_delete, name='userinfo_token_delete'),
    path("tasks/<int:task_id>/code", views.code_view, name='task_code_view'),
    path("overview", views.overview, name="overview"),

    # interface
    # scan result
    path('vuls/<int:vul_id>/del', scanresult.ScanResultDelInterfaceView.as_view(), name="vul_del"),

    # graph analysis
    path('graph', login_required(graph_analysis.GraphAnalysisView.as_view()), name='graph_analysis'),
]
