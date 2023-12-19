# -*- coding: utf-8 -*-

"""
    detection
    ~~~~~~~~~

    Implements detection language/framework

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
from prettytable import PrettyTable
import xml.etree.ElementTree as eT
from .dependencies import Dependencies
from utils.log import logger
from Kunlun_M.settings import RULES_PATH

try:  # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.req import parse_requirements

file_type = []


class Detection(object):
    def __init__(self, target_directory, files):
        """

        :param target_directory:
        :param files:
        :param language:
        """
        self.target_directory = target_directory
        self.files = files
        self.lang = []
        self.requirements = None
        self.frame_data = {}
        self.language_data = {}
        self.project_data = []
        self.rules_path = RULES_PATH

    @property
    def language(self):
        """Detection main language"""
        language_extensions = {}
        xml_languages = self._read_xml('languages.xml')
        if xml_languages is None:
            logger.error('languages read failed!!!')
            languages = None
        for language in xml_languages:
            l_name = language.get('name').lower()
            l_chiefly = 'false'
            if language.get('chiefly') is not None:
                l_chiefly = language.get('chiefly')

            language_extensions[l_name] = {
                'chiefly': l_chiefly,
                'extensions': []
            }
            for lang in language:
                l_ext = lang.get('value').lower()
                language_extensions[l_name]['extensions'].append(l_ext)

        languages = language_extensions

        tmp_language = None
        for ext, ext_info in self.files:
            logger.debug("[DETECTION] [LANGUAGE] {ext} {count}".format(ext=ext, count=ext_info['count']))
            for language, language_info in languages.items():
                if ext in language_info['extensions']:
                    if 'chiefly' in language_info and language_info['chiefly'].lower() == 'true':
                        logger.debug(
                            '[DETECTION] [LANGUAGE] found the chiefly language({language}), maybe have largest, continue...'.format(
                                language=language))

                        # special deal for chrome ext
                        if language == 'chromeext':
                            self.lang.append('javascript')

                        self.lang.append(language)
                    else:
                        logger.debug('[DETECTION] [LANGUAGE] not chiefly, continue...'.format(language=language))
                        tmp_language = language
            if self.lang is []:
                logger.debug(
                    '[DETECTION] [LANGUAGE] not found chiefly language, use the largest language(language) replace'.format(
                        language=tmp_language))
                self.lang.append(tmp_language)
        logger.debug('[DETECTION] [LANGUAGE] main languages ({main_language}), tmp language({tmp_language})'.format(
            tmp_language=tmp_language,
            main_language=",".join(self.lang)))
        return self.lang

    @property
    def framework(self):
        tree = self.rule()
        root = tree.getroot()
        frame_data, language_data = self.parse_xml(root, self.frame_data, self.language_data)
        projects_data = self.project_information(self.target_directory, False)
        frame_name = self.dependency_scan(root)  # Based on the dependency analysis framework type
        if frame_name is not None:
            return frame_name
        frames_name = frame_data.keys()
        for frame_name in frames_name:
            for rule_name in frame_data[frame_name]:
                for project_data in projects_data:
                    if rule_name in project_data:
                        logger.debug("[DETECTION] [FRAMEWORK] Find the project's framework may be:" + frame_name)
                        return frame_name
        logger.info('[DETECTION] [FRAMEWORK] Unknown Framework')
        return 'Unknown Framework'

    def dependency_scan(self, root):
        """
        根据三方依赖识别项目使用框架类型
        :param root:
        :return:
        """
        framework_infos = self.dependency_framework(root)
        dependencies = Dependencies(self.target_directory)
        dependencies_info = dependencies.get_framework
        dependencies_info = list(set(dependencies_info))
        for frame_name in framework_infos:
            for rule in framework_infos[frame_name]['rule']:
                for dependency in dependencies_info:
                    if rule in dependency:
                        logger.debug("Find the project's framework may be:" + frame_name)
                        return frame_name
        return None

    @staticmethod
    def dependency_framework(root):
        """

        :param root:
        :return:
        """
        framework_infos = {}
        for framework in root:
            rule_info = {
                'rule': []
            }
            frame = framework.get('name')
            for rule in framework:
                if rule.tag == 'dependency':
                    rule_info['rule'].append(rule.get('value'))
            if len(rule_info['rule']) != 0:
                framework_infos[frame] = rule_info
        return framework_infos

    def _requirements(self):
        requirements_txt = os.path.join(self.target_directory, 'requirements.txt')
        logger.debug(requirements_txt)
        if os.path.isfile(requirements_txt):
            requirements = parse_requirements(requirements_txt, session=False)
            self.requirements = [req.name.strip().lower() for req in requirements]
            logger.debug('requirements modules count: {count} ({modules})'.format(count=len(self.requirements),
                                                                                  modules=','.join(self.requirements)))
        else:
            logger.debug('requirements.txt not found!')
            self.requirements = []

    def parse_xml(self, root, frame_data, language_data, frame_name=None):
        language_name = ''
        if len(root) != 0:
            if root.tag != 'kunlun':
                frame_name = root.attrib['name']
                language_name = root.attrib['language']
                frame_data.setdefault(frame_name, [])
            for child_of_root in root:
                frame_data, language_data = self.parse_xml(child_of_root, frame_data, language_data, frame_name)
                language_data.setdefault(language_name, {})
            if frame_name is not None:
                language_data[language_name].setdefault(frame_name, frame_data[frame_name])
            return frame_data, language_data
        else:
            try:
                frame_data[frame_name].append(root.attrib['value'])
                return frame_data, language_data
            except KeyError as e:
                logger.warning(e.message)

    def _read_xml(self, filename):
        """
        Read XML
        :param filename:
        :return:
        """
        path = os.path.join(self.rules_path, filename)
        try:
            tree = eT.parse(path)
            return tree.getroot()
        except Exception as e:
            logger.warning('parse xml failed ({file})'.format(file=path))
            return None

    @staticmethod
    def rule():
        framework_path = os.path.join(RULES_PATH, 'frameworks.xml')
        tree = eT.ElementTree(file=framework_path)
        return tree

    @staticmethod
    def get_dict(extension, type_num):
        for ext in extension:
            type_num.setdefault(ext, {'files': 0, 'blank': 0, 'pound': 0, 'code': 0})
        return type_num

    @staticmethod
    def project_information(absolute_path, extension, is_cloc=False):
        allfiles = []
        if os.path.isdir(absolute_path):
            for root, dirs, filenames in os.walk(absolute_path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if is_cloc is True:
                        fileext = os.path.splitext(filepath)[1][1:]
                        if fileext in extension:
                            allfiles.append(filepath)
                    else:
                        allfiles.append(filepath)
        if os.path.isfile(absolute_path):
            absolute_path = os.path.abspath(absolute_path)
            if is_cloc is True:
                fileext = os.path.splitext(absolute_path)[1][1:]
                if fileext in extension:
                    allfiles.append(absolute_path)
            else:
                allfiles.append(absolute_path)
        return allfiles

    # 统计Python数据的函数
    @staticmethod
    def count_py_line(filename):
        count = {'count_code': 0, 'count_blank': 0, 'count_pound': 0}
        with open(filename, 'r') as fi:
            file_line = fi.readline()
            while fi.tell() != os.path.getsize(filename):
                file_line = file_line.strip()
                if len(file_line) == 0:
                    count['count_blank'] += 1
                elif file_line.startswith('#'):
                    count['count_pound'] += 1
                elif file_line.count('"""') == 2 or file_line.count("'''") == 2:
                    if file_line.startswith('"""') or file_line.startswith("'''"):
                        count['count_pound'] += 1
                    else:
                        count['count_code'] += 1
                elif file_line.count('"""') == 1 or file_line.count("'''") == 1:
                    if file_line.startswith('"""') or file_line.startswith("'''"):
                        count['count_pound'] += 1
                        while True:
                            file_line = fi.readline()
                            if len(file_line) == 0 or file_line == "\n":
                                count['count_blank'] += 1
                            else:
                                count['count_pound'] += 1
                            if file_line.endswith('"""\n') or file_line.endswith("'''\n"):
                                break
                    else:
                        count['count_code'] += 1
                        while True:
                            file_line = fi.readline()
                            if len(file_line) == 0 or file_line == "\n":
                                count['count_blank'] += 1
                            else:
                                count['count_code'] += 1
                            if file_line.find('"""') or file_line.find("'''"):
                                break
                else:
                    count['count_code'] += 1
                file_line = fi.readline()
            
            return count

    # 统计PHP数据的函数
    @staticmethod
    def count_php_line(filename):
        count = {'count_code': 0, 'count_blank': 0, 'count_pound': 0}
        fi = open(filename, 'r')
        file_line = fi.readline()
        while fi.tell() != os.path.getsize(filename):
            file_line = file_line.lstrip()
            if len(file_line) == 0:
                count['count_blank'] += 1
            elif file_line.startswith('//') or file_line.startswith('#'):
                count['count_pound'] += 1
            elif file_line.count('/*') == 1 and file_line.count('*/') == 1:
                if file_line.startswith('/*'):
                    count['count_pound'] += 1
                else:
                    count['count_code'] += 1
            elif file_line.count('/*') == 1 and file_line.count('*/') == 0:
                if file_line.startswith('/*'):
                    count['count_pound'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_pound'] += 1
                        if file_line.endswith('*/\n'):
                            break
                else:
                    count['count_code'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_code'] += 1
                        if file_line.find('*/'):
                            break
            else:
                count['count_code'] += 1
            file_line = fi.readline()
        fi.close()
        return count

    # 统计Java和JS数据的函数
    @staticmethod
    def count_java_line(filename):
        count = {'count_code': 0, 'count_blank': 0, 'count_pound': 0}
        fi = open(filename, 'r')
        file_line = fi.readline()
        while fi.tell() != os.path.getsize(filename):
            file_line = file_line.lstrip()
            if len(file_line) == 0:
                count['count_blank'] += 1
            elif file_line.startswith('//'):
                count['count_pound'] += 1
            elif file_line.count('/*') == 1 and file_line.count('*/') == 1:
                if file_line.startswith('/*'):
                    count['count_pound'] += 1
                else:
                    count['count_code'] += 1
            elif file_line.count('/*') == 1 and file_line.count('*/') == 0:
                if file_line.startswith('/*'):
                    count['count_pound'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_pound'] += 1
                        if file_line.endswith('*/\n'):
                            break
                else:
                    count['count_code'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_code'] += 1
                        if file_line.find('*/'):
                            break
            else:
                count['count_code'] += 1
            file_line = fi.readline()
        fi.close()
        return count

    # 统计solidity数据的函数
    @staticmethod
    def count_sol_line(filename):
        count = {'count_code': 0, 'count_blank': 0, 'count_pound': 0}
        fi = open(filename, 'r')
        file_line = fi.readline()
        while fi.tell() != os.path.getsize(filename):
            file_line = file_line.lstrip()
            if len(file_line) == 0:
                count['count_blank'] += 1
            elif file_line.startswith('//'):
                count['count_pound'] += 1
            elif file_line.count('/*') == 1 and file_line.count('*/') == 1:
                if file_line.startswith('/*'):
                    count['count_pound'] += 1
                else:
                    count['count_code'] += 1
            elif file_line.count('/*') == 1 and file_line.count('*/') == 0:
                if file_line.startswith('/*'):
                    count['count_pound'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_pound'] += 1
                        if file_line.endswith('*/\n'):
                            break
                else:
                    count['count_code'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_code'] += 1
                        if file_line.find('*/'):
                            break
            elif file_line.count('/**') == 1 and file_line.count('*/') == 0:
                if file_line.startswith('/**'):
                    count['count_pound'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_pound'] += 1
                        if file_line.endswith('*/\n'):
                            break
                else:
                    count['count_code'] += 1
                    while True:
                        file_line = fi.readline()
                        if len(file_line) == 0 or file_line == "\n":
                            count['count_blank'] += 1
                        else:
                            count['count_code'] += 1
                        if file_line.find('*/'):
                            break
            else:
                count['count_code'] += 1
            file_line = fi.readline()
        fi.close()
        return count

    # 统计markdown和xml数据的函数
    @staticmethod
    def count_data_line(filename):
        count = {'count_code': 0, 'count_blank': 0, 'count_pound': 0}
        fi = open(filename, 'r')
        file_line = fi.readline()

        while fi.tell() != os.path.getsize(filename):
            file_line = file_line.lstrip()
            if len(file_line) == 0:
                count['count_blank'] += 1
            else:
                count['count_code'] += 1
            file_line = fi.readline()
        fi.close()
        return count

    @staticmethod
    def countnum(count, type_num, fileext):
        type_num[fileext]['blank'] += count['count_blank']
        type_num[fileext]['code'] += count['count_code']
        type_num[fileext]['pound'] += count['count_pound']
        type_num[fileext]['files'] += 1
        return type_num

    @staticmethod
    def count_total_num(type_num, extension, total_file, total_blank_line, total_pound_line, total_code_line):
        for lang in extension:
            total_file += type_num[lang]['files']
            total_blank_line += type_num[lang]['blank']
            total_pound_line += type_num[lang]['pound']
            total_code_line += type_num[lang]['code']
        return total_file, total_blank_line, total_pound_line, total_code_line

    """
    type_num = {'js':{'files':0, 'blank':0, 'pound':0, 'code':0}, 
                'php':{'files':0, 'blank':0, 'pound':0, 'code':0}
                }
    For additional file types, you need to add a file suffix to the extension and add the file suffix to the if
    statement corresponding to the comment, example:

    if fileext == 'py' or fileext == 'java' or fileext == 'xxx'
    """

    def cloc(self):
        extension = ['js', 'py', 'php', 'java', 'xml', 'md', 'm', 'sol']
        type_num = {}
        total_code_line = 0
        total_pound_line = 0
        total_blank_line = 0
        total_file = 0
        type_num = self.get_dict(extension, type_num)
        filelists = self.project_information(self.target_directory, extension, True)
        for filelist in filelists:
            try:
                fileext = os.path.splitext(filelist)[1][1:]
                if fileext not in file_type:
                    file_type.append(fileext)
                if fileext == 'py':
                    count = self.count_py_line(filelist)
                    type_num = self.countnum(count, type_num, fileext)
                if fileext == 'js' or fileext == 'java' or fileext == 'css' or fileext == 'm':
                    count = self.count_java_line(filelist)
                    type_num = self.countnum(count, type_num, fileext)
                if fileext == 'php':
                    count = self.count_php_line(filelist)
                    type_num = self.countnum(count, type_num, fileext)
                if fileext == 'md' or fileext == 'xml':
                    count = self.count_data_line(filelist)
                    type_num = self.countnum(count, type_num, fileext)
                if fileext == 'sol':
                    count = self.count_sol_line(filelist)
                    type_num = self.countnum(count, type_num, fileext)
            except:
                logger.info('Part of the annotation rule does not match, press CTRL + C to continue the program')
        total_file, total_blank_line, total_pound_line, total_code_line = self.count_total_num(type_num, extension,
                                                                                               total_file,
                                                                                               total_blank_line,
                                                                                               total_pound_line,
                                                                                               total_code_line)
        x = PrettyTable(["language", "files", "blank", "comment", "code"])
        x.padding_width = 2
        x.align = "l"
        for lang in file_type:
            try:
                x.add_row([lang, type_num[lang]['files'], type_num[lang]['blank'], type_num[lang]['pound'],
                           type_num[lang]['code']])
            except KeyError:
                logger.warning('There is no such file type -->' + lang + ',please add it to the whitelist')
        x.add_row(["SUM", total_file, total_blank_line, total_pound_line, total_code_line])
        logger.info('\n' + str(x))
        return True
