# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'phpBB'
DEPENDENCIES = {'composer': ['phpbb/phpbb']}


def detect(project_dir, language='php'):
    """检测是否为 phpBB 项目"""
    return os.path.isdir(os.path.join(project_dir, 'phpbb'))


FILTER_FUNCTIONS = {
    '$request->variable': {'safe_for': [1000, 1001, 1004]},  # type-enforced input
    '$this->db->sql_escape': {'safe_for': [1004]},
}

EXTRA_SINKS = [
    ("->sql_query(", [1004]),
    ("->sql_build_query(", [1004]),
    ("redirect(", [1013]),
    ("include(", [1003]),
]

CONTROLLED_SOURCES = [
    '$request->variable',
    '$this->request->get_super_global',
    '$user->data',
]
