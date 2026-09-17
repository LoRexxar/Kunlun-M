"""
WSGI config for Kunlun_M project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

application = get_wsgi_application()

# 启动期安全配置检查（生产 Web 部署不经过 kunlun.py CLI 入口，在此兜底）
try:
    from utils.security import check_security_settings
    check_security_settings()
except ImportError:
    pass
