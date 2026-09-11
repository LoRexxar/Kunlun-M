# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Flask'
DEPENDENCIES = {'requirements': ['flask'], 'pyproject': ['flask']}


def detect(project_dir, language='python'):
    """检测是否为 Flask 项目"""
    app_py = os.path.join(project_dir, 'app.py')
    if os.path.isfile(app_py):
        with open(app_py, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if 'flask' in content.lower():
                return True
    return False


FILTER_FUNCTIONS = {
    # HTML 转义 / 安全输出（Flask 内置 escape 别名）
    'flask.escape': [7000, 7008],
    # url_for generates safe internal URLs — not a sink at all.
    # Previously misclassified as CVI-7010 (LDAP injection).
    'jsonify': [7000, 7008],
}

EXTRA_SINKS = [
    ("render_template_string(", [7006]),
    ("render_template(", [7006]),
    ("render_template_list(", [7006]),
    # redirect() is HTTP redirect (CVI-7009), NOT LDAP (7010).
    ("redirect(", [7009]),
    ("send_file(", [7005]),
    ("send_from_directory(", [7005, 7009]),
]

CONTROLLED_SOURCES = [
    'flask.request',
    'request.query_string',
    'request.cookies',
    'session',
]
