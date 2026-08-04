# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'ThinkPHP'
DEPENDENCIES = {'composer': ['topthink/framework']}


def detect(project_dir, language='php'):
    """检测是否为 ThinkPHP 项目"""
    return (os.path.isdir(os.path.join(project_dir, 'thinkphp'))
            or os.path.isfile(os.path.join(project_dir, 'tp5.php')))


FILTER_FUNCTIONS = {
    'think\\facade\\Validate': {'safe_for': [1000, 1001, 1004]},
    'Db::where': {'safe_for': [1004]},  # param binding
}

EXTRA_SINKS = [
    ("Db::query(", [1004]),
    ("Db::execute(", [1004]),
    ("Db::name(", [1004]),
    ("Cache::", [1004]),
    # Query Builder — raw SQL injection vectors
    ("->query(", [1004]),
    ("->execute(", [1004]),
    ("->fetchSql(", [1004]),
    # Template engine — XSS
    ("->fetch(", [1000]),
    ("->display(", [1000]),
    # Redirect
    ("redirect(", [1009]),
]

CONTROLLED_SOURCES = [
    'Input', 'request', 'I', 'input',
    '$this->request->param',
    '$this->request->get',
    '$this->request->post',
    '$this->request->header',
    'request()->param',
    'request()->get',
    'request()->post',
]
