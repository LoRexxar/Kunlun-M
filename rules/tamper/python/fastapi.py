# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'FastAPI'
DEPENDENCIES = {'requirements': ['fastapi'], 'pyproject': ['fastapi']}


def detect(project_dir, language='python'):
    """检测是否为 FastAPI 项目"""
    for fname in ['requirements.txt', 'pyproject.toml']:
        dep_path = os.path.join(project_dir, fname)
        if os.path.isfile(dep_path):
            try:
                with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    if 'fastapi' in content:
                        return True
            except IOError:
                pass
    return False


FILTER_FUNCTIONS = {
    # FastAPI HTML 响应（自动转义）
    'HTMLResponse': [7000, 7008],
}

CONTROLLED_SOURCES = [
    'request.cookies',
    'request.query_params',
]

EXTRA_SINKS = [
    ("Jinja2Templates(", [7006]),
    ("TemplateResponse(", [7006]),
    # RedirectResponse is HTTP redirect (CVI-7009), NOT LDAP (7010).
    ("RedirectResponse(", [7009]),
    ("responses.RedirectResponse(", [7009]),
    ("FileResponse(", [7005, 7009]),
    ("StreamingResponse(", [7005]),
]
