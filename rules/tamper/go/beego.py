# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Beego'
DEPENDENCIES = {'gomod': ['github.com/astaxie/beego', 'github.com/beego/beego']}


def detect(project_dir, language='go'):
    """检测是否为 Beego 项目"""
    go_mod = os.path.join(project_dir, 'go.mod')
    if os.path.isfile(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'beego' in content:
                    return True
        except IOError:
            pass
    return False


FILTER_FUNCTIONS = {}

CONTROLLED_SOURCES = [
    'c.GetString',
    'c.GetInt',
    'c.GetStrings',
    'c.Input',
    'c.Ctx.Input.Query',
    'c.Ctx.Input.Param',
    'c.Ctx.Input.Header',
    'c.Ctx.Input.Cookie',
    'c.Ctx.Input.RequestBody',
]

EXTRA_SINKS = [
    ("beego.AppConfig.String(", []),
    # XSS sinks: only text/html output
    ("c.Ctx.Output.Body(", [8003, 8008]),
    ("c.Ctx.WriteString(", [8003, 8008]),
    ("c.ServeJSONP(", [8003, 8008]),
    # NOT XSS: structured responses
    ("c.ServeJSON(", [8008]),
    ("c.ServeXML(", [8008]),
    ("c.ServeFile(", [8006]),
    ("c.Redirect(", [8013]),
]
