# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Fiber'
DEPENDENCIES = {'gomod': ['github.com/gofiber/fiber']}


def detect(project_dir, language='go'):
    """检测是否为 Fiber 项目"""
    go_mod = os.path.join(project_dir, 'go.mod')
    if os.path.isfile(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'fiber' in content and 'gofiber' in content:
                    return True
        except IOError:
            pass
    return False


FILTER_FUNCTIONS = {}

CONTROLLED_SOURCES = [
    'c.Query',
    'c.Params',
    'c.FormValue',
    'c.Body',
    'c.Get',
    'c.Cookies',
    'c.Path',
    'c.IP',
    'c.IPs',
    'c.Hostname',
    'c.Protocol',
]

EXTRA_SINKS = [
    # XSS sinks: only methods that output text/html to the response
    ("c.HTML(", [8003, 8008]),
    ("c.SendString(", [8003, 8008]),
    # NOT XSS: structured responses (Content-Type is not text/html)
    # c.JSON, c.XML, c.SendStatus do not trigger XSS in browsers
    ("c.SendFile(", [8006]),
    ("c.Redirect(", [8013]),
    ("c.JSON(", [8008]),
    ("c.XML(", [8008]),
    ("c.Download(", [8004, 8006]),
    ("c.Stream(", [8004]),
]