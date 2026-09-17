#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

# 安全配置检查：旧版本 settings.py 可能没有该函数（用户保留旧配置文件升级时），
# 缺失时跳过检查而不是让整个工具崩溃 (issue #350)
try:
    from Kunlun_M.settings import check_security_settings
    check_security_settings()
except ImportError:
    pass

from core import main


if __name__ == '__main__':

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(main())

