#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/1/29 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com


from django.shortcuts import render, redirect
from django.contrib import auth
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm

from Kunlun_M.settings import TITLE, DESCRIPTION, IS_OPEN_REGISTER

base = {
        "title": TITLE,
        "description": DESCRIPTION
    }


def index(req):
    return render(req, 'index.html', base)


def signup(req):

    if not IS_OPEN_REGISTER:
        return redirect('index:index')

    if req.method == 'POST':
        form = UserCreationForm(req.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            email = form.cleaned_data.get('email')
            user = auth.authenticate(username=username, password=password, email=email)

            if user is not None and user.is_active:
                auth.login(req, user)
                return redirect('index:index')
            else:
                return redirect('index:register')
        else:
            messages.add_message(req, messages.ERROR, form.errors)
            return render(req, 'register.html', base)
    else:
        return render(req, 'register.html', base)


def signin(req):
    if req.method == 'POST':
        username = req.POST['username']
        password = req.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None and user.is_active:
            auth.login(req, user)
            return redirect('index:index')
        else:
            messages.add_message(req, messages.ERROR, "Username or Password is incorrect.")
            return redirect('index:login')
    else:
        return render(req, 'login.html', base)


def logout(req):
    auth.logout(req)
    return redirect('index:index')
