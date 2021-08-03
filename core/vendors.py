#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: vendors.py
@time: 2021/7/21 14:57
@desc:

'''

import os
import re
import json
import codecs
import traceback

import xml.etree.cElementTree as eT

from utils.log import logger
from utils.file import check_filepath

from Kunlun_M.const import VENDOR_FILE_DICT

from web.index.models import ProjectVendors, update_and_new_project_vendor
from web.index.models import Project


def abstract_version(vendor_version):
    version_reg = '([0-9]+(\.[0-9]+)*)'
    result_version = ''

    if re.search(version_reg, vendor_version, re.I):

        p = re.compile(version_reg)
        matchs = p.finditer(vendor_version)

        for match in matchs:
            result_version = match.group(1)
    else:
        result_version = False

    return result_version


def compare_vendor(vendor, compare_version):

    vendor_version = abstract_version(vendor.version)
    vendor_version_list = vendor_version.split('.')
    compare_version_list = compare_version.split('.')

    is_smaller_vendor = False
    smallest_range = len(vendor_version_list) if len(compare_version_list) > len(vendor_version_list) else len(compare_version_list)

    for i in range(smallest_range):
        if int(vendor_version_list[i]) < int(compare_version_list[i]):
            is_smaller_vendor = True
            return is_smaller_vendor

        if int(vendor_version_list[i]) > int(compare_version_list[i]):
            is_smaller_vendor = False
            return is_smaller_vendor

    if len(compare_version_list) >= len(vendor_version_list):
        is_smaller_vendor = True

    return is_smaller_vendor


def get_project_vendor_by_name(vendor_name):
    """
    支持*语法的查询
    :param vendor_name:
    :return:
    """
    if vendor_name.startswith('*'):
        if vendor_name.endswith('*'):
            pvs = ProjectVendors.objects.filter(name__icontains=vendor_name.strip('*'))

        else:
            pvs = ProjectVendors.objects.filter(name__iendswith=vendor_name.strip('*'))

    else:
        if vendor_name.endswith('*'):
            pvs = ProjectVendors.objects.filter(name__istartswith=vendor_name.strip('*'))

        else:
            pvs = ProjectVendors.objects.filter(name__iexact=vendor_name.strip('*'))

    return pvs


def get_project_by_version(vendor_name, vendor_version):
    """
    获取低于该版本的所有项目信息
    :param vendor_name:
    :param vendor_version:
    :return:
    """
    is_need_version_check = True
    result_project = {}

    if vendor_version == 'latest':
        is_need_version_check = False

    vendor_version = abstract_version(vendor_version)

    if not vendor_version and is_need_version_check:
        return result_project

    pvs = get_project_vendor_by_name(vendor_name.strip())

    for pv in pvs:
        if not is_need_version_check or compare_vendor(pv, vendor_version):
            pid = pv.project_id
            project = Project.objects.filter(id=pid).first()

            if project not in result_project:
                result_project[project] = [pv]
            else:
                result_project[project].append(pv)

    return result_project


class Vendors:
    """
    项目组件检查
    """

    def __init__(self, project_id, target, files):
        self.project_id = project_id
        self.target_path = target
        self.files = files

        self.vendor_file_list = []
        self.ext_list = []
        self.exist_file_list = []

        for lan in VENDOR_FILE_DICT:
            self.vendor_file_list.extend(VENDOR_FILE_DICT[lan])

        for vendor_file in self.vendor_file_list:
            es = vendor_file.split(os.extsep)

            if len(es) >= 2:
                self.ext_list.append(".{}".format(es[-1]))

        self.ext_list = list(set(self.ext_list))

        # 检查列表
        self.get_vendor_file()
        self.exist_file_list = list(set(self.exist_file_list))

        if len(self.exist_file_list):
            self.check_vendor()

    def get_vendor_file(self):

        for file_obj in self.files:

            for ext in self.ext_list:

                if ext == file_obj[0]:
                    filelist = file_obj[1]['list']

                    for file in filelist:
                        filename = file.split('/')[-1].split('\\')[-1]

                        if filename in self.vendor_file_list:
                            logger.info("[Vendor] Vendor file {} be found.".format(filename))

                            self.exist_file_list.append(file)
                            continue

        return self.exist_file_list

    def get_language(self, filename):

        for lan in VENDOR_FILE_DICT:
            if filename in VENDOR_FILE_DICT[lan]:
                return lan

        else:
            return ""

    def check_commit(self, line):
        last_str = ""
        result = ""

        for str in line:
            if last_str == '/' and str == '/':
                result = result[:-1]
                return result

            if str == '#':
                return result

            result += str
            last_str = str

        return result

    def check_vendor(self):
        for file in self.exist_file_list:

            try:
                filepath = check_filepath(self.target_path, file)
                filename = file.split('/')[-1].split('\\')[-1]
                language = self.get_language(filename)

                f = codecs.open(filepath, 'rb+', encoding='utf-8', errors='ignore')
                filecontent = f.read()
                f.seek(0, os.SEEK_SET)

                if filename == "requirements.txt":

                    for line in f:
                        if not len(line):
                            continue

                        vendor = line.split("==")
                        vendor_name = vendor[0].strip()
                        vendor_version = vendor[-1].strip()
                        if len(vendor) < 2:
                            vendor_version = None

                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                      language=language)

                elif filename == 'composer.json':
                    vendors = json.loads(filecontent, encoding='utf-8')

                    if not len(vendors):
                        continue

                    vendors_list = vendors['require']

                    for vendor in vendors_list:
                        vendor_name = vendor.strip()
                        vendor_version = vendors_list[vendor].strip()

                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                      language=language)

                elif filename == 'go.mod':

                    go_version = ""
                    is_require_line = False

                    for line in f:

                        if line.startswith('go'):
                            go_version = line.strip().split(' ')[-1]

                        if line.startswith('require ('):
                            is_require_line = True
                            continue

                        if line.startswith(')'):
                            is_require_line = False
                            continue

                        if is_require_line:
                            vendor = self.check_commit(line).strip().split(' ')

                            vendor_name = vendor[0].strip()
                            vendor_version = vendor[-1].strip()

                            update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                          language=language, ext=go_version)
                elif filename == 'pom.xml':
                    reg = r'xmlns="([\w\.\\/:]+)"'
                    pom_ns = None

                    if re.search(reg, filecontent, re.I):

                        p = re.compile(reg)
                        matchs = p.finditer(filecontent)

                        for match in matchs:
                            pom_ns = match.group(1)

                    if pom_ns:
                        xpath_reg = ".//{%s}dependency" % pom_ns
                    else:
                        xpath_reg = ".//dependency"

                    tree = self.parse_xml(filepath)
                    root = tree.getroot()
                    childs = root.findall(xpath_reg)
                    for child in childs:
                        group_id = child.getchildren()[0].text
                        artifact_id = child.getchildren()[1].text
                        if len(child.getchildren()) > 2:
                            version = child.getchildren()[2].text
                        else:
                            version = 'latest'

                        var_reg = "\${([\w\.\_-]+)}"
                        if re.search(var_reg, version, re.I):
                            p2 = re.compile(var_reg)
                            matchs = p2.finditer(version)

                            for match in matchs:
                                varname = match.group(1)
                                if pom_ns:
                                    var_xpath_reg = ".//{%s}%s" % (pom_ns, varname)
                                else:
                                    var_xpath_reg = ".//%s" % varname

                                varchilds = root.findall(var_xpath_reg)

                                for child in varchilds:
                                    version = child.text

                        vendor_name = "{}:{}".format(group_id, artifact_id)
                        vendor_version = version
                        ext = "maven"

                        update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                      language=language, ext=ext)

                elif filename == 'build.gradle':
                    is_plugin_block = False
                    ext = "gradle"

                    for line in f:
                        if line.startswith('plugins {'):
                            is_plugin_block = True
                            continue

                        if is_plugin_block and line.startswith('}'):
                            is_plugin_block = False
                            continue

                        if is_plugin_block:
                            plugin_block_list = line.strip().split(' ')
                            last_block = ""
                            vendor_name = ""
                            vendor_version = ""

                            for plugin_block in plugin_block_list:
                                if last_block == 'id':
                                    vendor_name = plugin_block.strip("'").strip('"')

                                if last_block == 'version':
                                    vendor_version = plugin_block.strip("'").strip('"')

                                last_block = plugin_block

                            if vendor_name and vendor_version:
                                update_and_new_project_vendor(self.project_id, name=vendor_name, version=vendor_version,
                                                              language=language, ext=ext)
                            continue

                elif filename == "package.json":
                    vendors = json.loads(filecontent)

                    if not len(vendors):
                        continue

                    node_version = "{} {}".format(vendors['name'], vendors['version'])
                    dependencies = vendors["dependencies"]
                    devDependencies = vendors["devDependencies"]

                    for dependency in dependencies:
                        vendor_version = dependencies[dependency].strip()
                        ext = "{}.{}".format(node_version, "dependencies")

                        update_and_new_project_vendor(self.project_id, name=dependency, version=vendor_version,
                                                      language=language, ext=ext)

                    for dependency in devDependencies:
                        vendor_version = devDependencies[dependency].strip()
                        ext = "{}.{}".format(node_version, "devDependencies")

                        update_and_new_project_vendor(self.project_id, name=dependency, version=vendor_version,
                                                      language=language, ext=ext)

                else:
                    logger.warn("[Vendor] Vendor file {} not support".format(filename))

            except:
                logger.error("[Vendor] Error check for Vendor file {}.\nError: {}".format(file, traceback.format_exc()))
                continue

    @staticmethod
    def parse_xml(file_path):
        return eT.parse(file_path)
