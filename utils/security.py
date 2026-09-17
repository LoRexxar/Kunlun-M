#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""启动期安全配置检查。

从 django.conf.settings 读取配置，适配任意 DJANGO_SETTINGS_MODULE
（Kunlun_M.settings / settings_ci / 用户自定义），由 CLI 与 Web(WSGI)
入口共同调用。配置项缺失时静默跳过——安全警告绝不能阻断启动
(issue #350)。
"""
import warnings


def check_security_settings():
    """生产环境(DEBUG=False)下使用默认 API_TOKEN 时发出警告"""
    try:
        from django.conf import settings
    except Exception:
        return
    api_token = getattr(settings, "API_TOKEN", None)
    debug = getattr(settings, "DEBUG", True)
    if not debug and api_token in (None, "", "secret_api_token"):
        warnings.warn(
            "生产环境(DEBUG=False)下使用了默认 API_TOKEN，请尽快修改 API_TOKEN 配置以避免安全风险。",
            DeprecationWarning,
            stacklevel=2,
        )
