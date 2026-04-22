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

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

import xml.etree.ElementTree as eT
from core.dependencies import Dependencies


def _build_requirements_file(tmp_path):
    requirements = tmp_path / 'requirements.txt'
    requirements.write_text("Flask==0.10.1\nDjango==1.10.5\n")
    return requirements


def _build_pom_file(tmp_path):
    pom = tmp_path / 'pom.xml'
    pom.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId>
  <artifactId>demo</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>io.github.release-engineering-commons</groupId>
      <artifactId>pom-manipulation-io</artifactId>
      <version>1.1.1</version>
    </dependency>
  </dependencies>
</project>
""")
    return pom


def test_find_file(tmp_path):
    requirements = _build_requirements_file(tmp_path)
    dependencies = Dependencies(str(requirements))
    file_path, flag = dependencies.find_file()
    assert isinstance(file_path, list)
    assert isinstance(flag, int)
    assert flag == 1
    assert str(requirements) in file_path


def test_get_path(tmp_path):
    requirements = _build_requirements_file(tmp_path)
    dependencies = Dependencies(str(requirements))
    for root, dirs, filenames in os.walk(dependencies.directory):
        for filename in filenames:
            file_path = dependencies.get_path(root, filename)
            assert isinstance(file_path, str)


def test_find_python_pip(tmp_path):
    requirements = _build_requirements_file(tmp_path)
    dependencies = Dependencies(str(requirements))
    dependencies.dependencies()
    assert 'Flask' in dependencies.get_result


def test_find_java_mvn(tmp_path):
    pom = _build_pom_file(tmp_path)
    dependencies = Dependencies(str(pom))
    dependencies.dependencies()
    assert 'pom-manipulation-io' in dependencies.get_result


def test_parse_xml(tmp_path):
    pom = _build_pom_file(tmp_path)
    dependencies = Dependencies(str(pom))
    root = dependencies.parse_xml(str(pom))
    root_test = eT.parse(str(pom))
    assert isinstance(root, type(root_test))


def test_get_version(tmp_path):
    requirements = _build_requirements_file(tmp_path)
    dependencies = Dependencies(str(requirements))
    dependencies.dependencies()
    version = dependencies.get_version('Flask')
    assert version == '0.10.1'


def test_get_result(tmp_path):
    requirements = _build_requirements_file(tmp_path)
    dependencies = Dependencies(str(requirements))
    dependencies.dependencies()
    result = dependencies.get_result
    assert isinstance(result, dict)
