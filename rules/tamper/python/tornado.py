# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Tornado'
DEPENDENCIES = {'requirements': ['tornado'], 'pyproject': ['tornado']}


def detect(project_dir, language='python'):
    """检测是否为 Tornado 项目"""
    for fname in ['requirements.txt', 'pyproject.toml']:
        dep_path = os.path.join(project_dir, fname)
        if os.path.isfile(dep_path):
            try:
                with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
                    if 'tornado' in f.read().lower():
                        return True
            except IOError:
                pass
    return False


FILTER_FUNCTIONS = {
    # Tornado HTML / URL 转义
    'tornado.escape.xhtml_escape': [7000, 7008],
    'tornado.escape.url_escape': [7004, 7010],
}

CONTROLLED_SOURCES = [
    'self.get_argument',
    'self.get_query_argument',
    'self.get_body_argument',
    'self.request.query_arguments',
    'self.get_cookie',
]

EXTRA_SINKS = [
    ("self.render(", [7006]),
    ("self.render_string(", [7006]),
    ("self.write(", [7008]),
    # self.redirect() is HTTP redirect (CVI-7009), NOT LDAP (7010).
    ("self.redirect(", [7009]),
]
