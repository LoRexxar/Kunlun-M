# -*- coding: utf-8 -*-

"""
    dependencies
    ~~~~~~~~~~~~

    Implements Dependencies Check

    :author:    BlBana <635373043@qq.com>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import xml.etree.cElementTree as eT
from utils.log import logger


class Dependencies(object):
    def __init__(self, target_directory):
        """
        :param target_directory: The project's path
        """
        self.directory = os.path.abspath(target_directory)
        self._result = {}
        self._framework = []
        self.dependencies()

    def dependencies(self):
        file_path, flag = self.find_file()
        if flag == 0:  # flag == 0
            logger.debug('Dependency analysis cannot be done without finding dependency files')
            return False
        if flag == 1:
            self.find_python_pip(file_path)
            return True
        if flag == 2:
            self.find_java_mvn(file_path)
            return True

    def find_file(self):
        """
        :return:flag:{1:'python', 2:'java', 3:'oc'}
        """
        flag = 0
        file_path = []
        requirements_files = []
        pom_files = []
        if os.path.isdir(self.directory):
            for root, dirs, filenames in os.walk(self.directory):
                for filename in filenames:
                    if filename == 'requirements.txt':
                        requirements_files.append(self.get_path(root, filename))
                    if filename == 'pom.xml':
                        pom_files.append(self.get_path(root, filename))
            if requirements_files:
                return requirements_files, 1
            if pom_files:
                return pom_files, 2
            return file_path, flag
        else:
            filename = os.path.basename(self.directory)
            if filename == 'requirements.txt':
                return [self.directory], 1
            if filename == 'pom.xml':
                return [self.directory], 2
            return file_path, flag

    @staticmethod
    def get_path(root, filename):
        """
        :param root:
        :param filename:
        :return:
        """
        return os.path.join(root, filename)

    def find_python_pip(self, file_path):
        for requirement in file_path:
            if not os.path.isfile(requirement):
                logger.warning("[DEPENDENCIES] requirement file not found: {}".format(requirement))
                continue

            with open(requirement) as fi:
                for raw_line in fi:
                    line = raw_line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if '#' in line:
                        line = line.split('#', 1)[0].strip()

                    if '==' in line:
                        module_, version = line.split('==', 1)
                        module_ = module_.strip()
                        version = version.strip()
                    else:
                        module_ = line.strip()
                        version = ''

                    if not module_:
                        continue

                    self._framework.append(module_)
                    self._result[module_] = version

    def find_java_mvn(self, file_path):
        pom_ns = "{http://maven.apache.org/POM/4.0.0}"
        for pom in file_path:
            if not os.path.isfile(pom):
                logger.warning("[DEPENDENCIES] pom file not found: {}".format(pom))
                continue

            tree = self.parse_xml(pom)
            root = tree.getroot()
            childs = root.findall('.//%sdependency' % pom_ns)
            for child in childs:
                child_items = list(child)
                if len(child_items) < 2:
                    continue

                group_id = child_items[0].text
                artifact_id = child_items[1].text
                if len(child_items) > 2:
                    version = child_items[2].text
                else:
                    version = 'The latest version'
                module_ = artifact_id
                if group_id:
                    self._framework.append(group_id)
                if artifact_id:
                    self._framework.append(artifact_id)
                self._result[module_] = version

    @staticmethod
    def parse_xml(file_path):
        return eT.parse(file_path)

    def get_version(self, module_):
        return self._result[module_]

    @property
    def get_result(self):
        return self._result

    @property
    def get_framework(self):
        return list(dict.fromkeys(self._framework))
