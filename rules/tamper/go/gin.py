# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Gin'
DEPENDENCIES = {'gomod': ['github.com/gin-gonic/gin']}


def detect(project_dir, language='go'):
    """检测是否为 Gin 项目"""
    go_mod = os.path.join(project_dir, 'go.mod')
    if os.path.isfile(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'gin-gonic/gin' in content:
                    return True
        except IOError:
            pass
    return False


FILTER_FUNCTIONS = {}

CONTROLLED_SOURCES = [
    'c.Query',
    'c.Param',
    'c.PostForm',
    'c.GetHeader',
]

EXTRA_SINKS = [
    # XSS sinks: only methods that output text/html to the response
    ("c.HTML(", [8003, 8008]),
    ("c.String(", [8003, 8008]),
    ("c.JSONP(", [8003, 8008]),
    ("c.Writer.Write(", [8003, 8008]),
    # NOT XSS: structured responses (Content-Type is not text/html)
    ("c.File(", [8006]),
    ("c.ServeFile(", [8006]),
    ("c.FileAttachment(", [8006]),
    ("c.Redirect(", [8013]),
    ("c.JSON(", [8008]),
    ("c.XML(", [8008]),
    ("c.YAML(", [8008]),
    ("c.Data(", [8008]),
    ("c.SaveUploadedFile(", [8004, 8006]),
]