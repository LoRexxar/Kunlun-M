#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/8 16:29
# @Author  : LoRexxar
# @File    : urls.py
# @Contact : lorexxar@gmail.com

from django.urls import path

from web.dashboard import views
from web.dashboard.controller import tasks, rules, tampers

app_name = "dashboard"
urlpatterns = [
    path('', views.index, name='index'),

    # task
    path('tasks/list', tasks.TaskListView.as_view(), name='tasks_list'),
    path('tasks/detail/<int:task_id>', tasks.TaskDetailView.as_view(), name="task_detail"),

    # rule
    path('rules/list', rules.RuleListView.as_view(), name='rules_list'),
    path('rules/detail/<int:rule_id>', rules.RuleDetailView.as_view(), name="rule_detail"),

    # tamper
    path('tampers/list', tampers.TamperListView.as_view(), name='tampers_list'),
    path('tampers/detail/<int:tamper_id>', tampers.TamperDetailView.as_view(), name="tamper_detail"),

    # docs
    path("docs", views.docs, name="docs"),

    # user
    path("userinfo", views.userinfo, name="userinfo"),
]
