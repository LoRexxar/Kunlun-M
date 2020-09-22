# -*- coding: utf-8 -*-

"""
    tests.test_directory
    ~~~~~~~~~~~~~~~~~~~~

    Tests pickup.directory

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

from Kunlun_M.settings import PROJECT_DIRECTORY
from utils.file import Directory

def test_file():
    absolute_path = os.path.join(PROJECT_DIRECTORY, 'tests', 'vulnerabilities')
    files, file_sum, time_consume = Directory(absolute_path).collect_files()
    ext, ext_info = files[0]
    assert '.php' == ext
    assert 2 == ext_info['count']
    assert 'v.php' in ext_info['list']
    assert 1 == file_sum
    assert time_consume < 1


def test_directory():
    absolute_path = PROJECT_DIRECTORY
    files, file_sum, time_consume = Directory(absolute_path).collect_files()
    assert len(files) > 1
