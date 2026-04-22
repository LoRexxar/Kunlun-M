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
    files_dict = dict(files)
    assert '.php' in files_dict
    assert files_dict['.php']['count'] == 2
    assert '/v.php' in files_dict['.php']['list']
    assert file_sum >= 2
    assert time_consume < 1


def test_directory():
    absolute_path = PROJECT_DIRECTORY
    files, file_sum, time_consume = Directory(absolute_path).collect_files()
    assert len(files) > 1
