#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    core
    ~~~~~

    Implements core main

    :author:    BlBana <635373043@qq.com>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import xml.etree.ElementTree as eT
from core.detection import Detection
from Kunlun_M.settings import PROJECT_DIRECTORY

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

vul_path = PROJECT_DIRECTORY+'/tests/vulnerabilities/'
EXAMPLES_PATH = PROJECT_DIRECTORY+'/tests/examples'


def test_framework():
    detection = Detection(vul_path+'requirements.txt', '.')
    frame = detection.framework
    assert frame == 'Flask'


def test_param_xml():
    detection = Detection(EXAMPLES_PATH, '.')
    frame_data = {}
    language_data = {}
    tree = detection.rule()
    root = tree.getroot()
    frame_data, language_data = detection.parse_xml(root, frame_data, language_data)
    assert 'WordPress' in frame_data
    assert 'php' in language_data


def test_rule():
    detection = Detection(EXAMPLES_PATH, '.')
    root = eT.ElementTree(file=EXAMPLES_PATH+'/param_xml.xml')
    tree = detection.rule()
    assert type(root) is type(tree)


def test_get_dict():
    detection = Detection(EXAMPLES_PATH, '.')
    extension = ['php', 'js', 'java']
    type_num = {}
    type_num = detection.get_dict(extension, type_num)
    print(type(type_num))
    assert type_num['php']['blank'] == 0


def test_project_information():
    extension = ['php', 'js', 'java']
    allfiles = Detection.project_information(EXAMPLES_PATH, extension)
    assert EXAMPLES_PATH+'/cloc.html' in allfiles


def test_count_py_line():
    count = Detection.count_py_line(EXAMPLES_PATH+'/cloc.py')
    type_count = ['count_blank', 'count_code', 'count_pound']
    assert count['count_code'] == 5


def test_count_php_line():
    count = Detection.count_php_line(EXAMPLES_PATH+'/cloc.php')
    type_count = ['count_blank', 'count_code', 'count_pound']
    assert count['count_code'] == 2


def test_count_java_line():
    count = Detection.count_java_line(EXAMPLES_PATH+'/cloc.java')
    type_count = ['count_blank', 'count_code', 'count_pound']
    assert count['count_code'] == 1


def test_count_data_line():
    count = Detection.count_data_line(EXAMPLES_PATH+'/param_xml.xml')
    type_count = ['count_blank', 'count_code', 'count_pound']
    assert count['count_code'] == 81


def test_countnum():
    count = {'count_blank': 10, 'count_code': 20, 'count_pound': 30}
    type_num = {'php': {'blank': 10, 'code': 10, 'pound': 10, 'files': 2}}
    ext = 'php'
    type_num = Detection.countnum(count, type_num, ext)
    assert 'php' in type_num


def test_count_total_num():
    type_num = {'php': {'blank': 10, 'code': 10, 'pound': 10, 'files': 2},
                'java': {'blank': 10, 'code': 10, 'pound': 10, 'files': 2}}
    extension = ['php', 'java']
    total_file = 0
    total_blank_line = 0
    total_pound_line = 0
    total_code_line = 0
    total_file, total_blank_line, total_pound_line, total_code_line = Detection.count_total_num(type_num, extension,
                                                                                                total_file,
                                                                                                total_blank_line,
                                                                                                total_pound_line,
                                                                                                total_code_line)
    assert isinstance(total_file, int)
    assert isinstance(total_blank_line, int)
    assert isinstance(total_pound_line, int)
    assert isinstance(total_code_line, int)


def test_cloc():
    assert Detection(EXAMPLES_PATH, '.').cloc()
