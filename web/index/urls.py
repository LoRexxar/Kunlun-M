#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: urls.py
@time: 2020/12/3 14:45
@desc:

'''

from django.urls import path

from web.index import views


app_name = "index"
urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.signin, name='login'),
    path('logout', views.logout, name='logout'),
    path('register/', views.signup, name='register')
]
