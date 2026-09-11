# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Echo'
DEPENDENCIES = {'gomod': ['github.com/labstack/echo']}


def detect(project_dir, language='go'):
    """检测是否为 Echo 项目"""
    go_mod = os.path.join(project_dir, 'go.mod')
    if os.path.isfile(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'echo' in content and 'labstack' in content:
                    return True
        except IOError:
            pass
    return False


FILTER_FUNCTIONS = {}

CONTROLLED_SOURCES = [
    'c.QueryParam',
    'c.Param',
    'c.FormValue',
    'c.Request.FormValue',
    'c.QueryString',
    'c.Cookies',
    'c.Cookie',
    'c.RealIP',
    'c.IP',
    'c.Request().Body',
]

EXTRA_SINKS = [
    # XSS sinks: only methods that output text/html
    ("c.HTML(", [8003, 8008]),
    ("c.String(", [8003, 8008]),
    # NOT XSS: structured responses
    ("c.File(", [8006]),
    ("c.Redirect(", [8013]),
    ("c.JSON(", [8008]),
    ("c.JSONPretty(", [8008]),
    ("c.XML(", [8008]),
    ("c.Blob(", [8004, 8006]),
    ("c.Attachment(", [8004, 8006]),
    ("c.Stream(", [8004]),
]