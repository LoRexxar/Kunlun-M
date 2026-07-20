#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 14:44
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path

from web.api import views
from web.api.views_verify import TaskResultVerifyApiView, TaskVerifyBatchApiView

app_name = "api"
urlpatterns = [
    path('', views.index, name='index'),

    # task list
    path("task/list", views.TaskListApiView.as_view(), name="task_list"),
    # task details
    path("task/<int:task_id>", views.TaskDetailApiView.as_view(), name="task_detail"),
    # task result details
    path("task/<int:task_id>/result", views.TaskResultApiView.as_view(), name="task_result_detail"),
    # task taint chain
    path("task/<int:task_id>/taintchain", views.TaskTaintChainApiView.as_view(), name="task_taintchain"),
    # task vendors
    path("task/<int:task_id>/vendors", views.TaskVendorsApiView.as_view(), name="task_vendors"),

    # task result
    path("task/result/<int:result_id>", views.TaskResultDetailApiView.as_view(), name="task_result"),
    path("task/result/<int:result_id>/del", views.TaskResultDetailDelApiView.as_view(), name="task_result_del"),
    # task taint chain detail
    path("task/result/<int:result_id>/taintchain/<int:vul_id>", views.TaskTaintChainDetailApiView.as_view(), name="task_taintchain_detail"),

    # rule list
    path("rule/list", views.RuleListApiView.as_view(), name="rule_list"),
    # rule details
    path("rule/<int:rule_cviid>", views.RuleDetailApiView.as_view(), name="rule_detail"),

    # vendor
    # vendor vul list
    path("vendorvul/list", views.VendorVulListApiView.as_view(), name="vendor_vul_list"),
    # vendor vul details
    path("vendorvul/<int:vendor_vul_id>", views.VendorVuLDetailApiView.as_view(), name="vendor_vul_detail"),
    # vendor vul statistics
    path("vendorvul/statistics", views.VendorVulStatisticsApiView.as_view(), name="vendor_vul_statistics"),

    # vendor statistics
    path("vendor/statistics", views.VendorStatisticsApiView.as_view(), name="vendor_statistics"),

    # task log tail (realtime)
    path("task/<int:task_id>/logtail", views.TaskLogTailApiView.as_view(), name="tasklogtail"),
    # task cancel
    path("task/<int:task_id>/cancel", views.TaskCancelApiView.as_view(), name="taskcancel"),
    # task retry
    path("task/<int:task_id>/retry", views.TaskRetryApiView.as_view(), name="taskretry"),

    # task create (API only, path mode)
    path("task/create", views.TaskCreateApiView.as_view(), name="task_create"),
    # task create with config + auto dispatch
    path("task/create/start", views.TaskCreateWithConfigApiView.as_view(), name="task_create_start"),
    # task status (lightweight)
    path("task/<int:task_id>/status", views.TaskStatusApiView.as_view(), name="task_status"),

    # stats
    path("stats/dashboard", views.StatsApiView.as_view(), name="stats_dashboard"),

    # graph analysis
    path("graph/scans", views.GraphScansApiView.as_view(), name="graph_scans"),
    path("graph/load", views.GraphLoadApiView.as_view(), name="graph_load"),
    path("graph/release", views.GraphReleaseApiView.as_view(), name="graph_release"),
    path("graph/status", views.GraphStatusApiView.as_view(), name="graph_status"),
    path("graph/query", views.GraphQueryApiView.as_view(), name="graph_query"),
    # graph subgraph extraction (for visualization)
    path("graph/subgraph", views.GraphSubgraphApiView.as_view(), name="graph_subgraph"),
    # graph chain subgraph (for taint chain visualization)
    path("graph/chain_subgraph", views.GraphChainSubgraphApiView.as_view(), name="graph_chain_subgraph"),
    # graph node associated vulnerabilities
    path("graph/node_vulns", views.GraphNodeVulnsApiView.as_view(), name="graph_node_vulns"),
    # graph node source code context
    path("graph/node_source", views.GraphNodeSourceApiView.as_view(), name="graph_node_source"),

    # verification
    path("task/result/<int:result_id>/verify", TaskResultVerifyApiView.as_view(), name="task_result_verify"),
    path("task/<int:task_id>/verify/batch", TaskVerifyBatchApiView.as_view(), name="task_verify_batch"),
]
