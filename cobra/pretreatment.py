#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/4/15 14:51
# @Author  : LoRexxar
# @File    : Pretreatment.py
# @Contact : lorexxar@gmail.com


from phply.phplex import lexer  # 词法分析
from phply.phpparse import make_parser  # 语法分析
from phply import phpast as php

import esprima

from .log import logger
from .const import ext_dict

import os
import json
import codecs
import traceback
import zipfile


could_ast_pase_lans = ["php", "chromeext", "javascript"]


def un_zip(target_path):
    """
    解压缩目标压缩包
    :return: 
    """

    logger.info("[Pre][Unzip] Upzip file {}...".format(target_path))

    if not os.path.isfile(target_path):
        logger.warn("[Pre][Unzip] Target file {} is't exist...pass".format(target_path))
        return False

    zip_file = zipfile.ZipFile(target_path)
    target_file_path = target_path+"_files/"

    if os.path.isdir(target_file_path):
        logger.debug("[Pre][Unzip] Target files {} is exist...continue".format(target_file_path))
        return target_file_path
    else:
        os.mkdir(target_file_path)

    for names in zip_file.namelist():
        zip_file.extract(names, target_file_path)
    zip_file.close()

    return target_file_path


class Pretreatment:

    def __init__(self):
        self.file_list = []
        self.target_directory = ""

        self.pre_result = {}
        self.define_dict = {}

        self.pre_ast()

    def init_pre(self, target_directory, files):
        self.file_list = files
        self.target_directory = target_directory

        self.target_directory = os.path.normpath(self.target_directory)

    def pre_ast(self, lan=None):

        if lan is not None:
            # 检查是否在可ast pasre列表中
            if not list(set(lan).intersection(set(could_ast_pase_lans))):

                logger.info("[AST][Pretreatment] Current scan target language does not require ast pretreatment...")
                return True

        for fileext in self.file_list:

            if fileext[0] in ext_dict['php']:
                # 下面是对于php文件的处理逻辑
                for filepath in fileext[1]['list']:
                    all_nodes = []

                    filepath = os.path.join(self.target_directory, filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'php'
                    self.pre_result[filepath]['ast_nodes'] = []

                    fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                    code_content = fi.read()

                    self.pre_result[filepath]['content'] = code_content

                    try:
                        parser = make_parser()
                        all_nodes = parser.parse(code_content, debug=False, lexer=lexer.clone(), tracking=True)

                        # 合并字典
                        self.pre_result[filepath]['ast_nodes'] = all_nodes

                    except SyntaxError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))

                    except AssertionError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))

                    # 搜索所有的常量
                    for node in all_nodes:
                        if isinstance(node, php.FunctionCall) and node.name == "define":
                            define_params = node.params
                            logger.debug("[AST][Pretreatment] new define {}={}".format(define_params[0].node, define_params[1].node))

                            self.define_dict[define_params[0].node] = define_params[1].node

            elif fileext[0] in ext_dict['chromeext']:
                child_files = []

                # 针对chrome 拓展的预处理
                # 需要提取其中的js和html？
                for filepath in fileext[1]['list']:
                    filepath = os.path.join(self.target_directory, filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'chromeext'

                    # 首先想办法解压crx
                    target_files_path = un_zip(filepath)
                    self.pre_result[filepath]['target_files_path'] = target_files_path

                    # 分析manifest.json
                    manifest_path = os.path.join(target_files_path, "manifest.json")
                    relative_path = target_files_path.split(self.target_directory)[-1]

                    if relative_path.startswith('\\') or relative_path.startswith("/"):
                        relative_path = relative_path[1:]

                    if os.path.isfile(manifest_path):
                        fi = codecs.open(manifest_path, "r", encoding='utf-8', errors='ignore')
                        manifest_content = fi.read()
                        manifest = json.loads(manifest_content)

                        self.pre_result[filepath]["manifest"] = manifest

                        if "content_scripts" in manifest:
                            for script in manifest["content_scripts"]:
                                child_files.extend([os.path.join(relative_path, js) for js in script['js']])

                        self.pre_result[filepath]["child_files"] = child_files
                    else:
                        logger.warning("[Pretreatment][Chrome Ext] File {} parse error...".format(target_files_path))
                        continue

            elif fileext[0] in ext_dict['javascript']:

                # 针对javascript的预处理
                # 需要对js做语义分析
                for filepath in fileext[1]['list']:
                    filepath = os.path.join(self.target_directory, filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'javascript'
                    self.pre_result[filepath]['ast_nodes'] = []

                    fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                    code_content = fi.read()

                    self.pre_result[filepath]['content'] = code_content

                    try:
                        all_nodes = esprima.parse(code_content, {"loc": True})

                        # 合并字典
                        self.pre_result[filepath]['ast_nodes'] = all_nodes

                    except SyntaxError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))

                    except AssertionError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))

    def get_nodes(self, filepath, vul_lineno=None, lan = None):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            if vul_lineno:
                # 处理需求函数的问题
                # 主要应用于，函数定义之后才会调用才会触发
                if lan == 'javascript':
                    backnodes = []
                    allnodes = self.pre_result[filepath]['ast_nodes'].body

                    for node in allnodes:
                        if node.loc.start.line <= int(vul_lineno):
                            backnodes.append(node)

                    return backnodes

            return self.pre_result[filepath]['ast_nodes']

        elif os.path.join(self.target_directory, filepath) in self.pre_result:
            return self.pre_result[os.path.join(self.target_directory, filepath)]['ast_nodes']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def get_content(self, filepath):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            return self.pre_result[filepath]['content']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def get_object(self, filepath):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            return self.pre_result[filepath]
        else:
            logger.warning("[AST] file {} object not found...".format(filepath))
            return False

    def get_child_files(self, filepath):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result and "child_files" in self.pre_result[filepath]:
            return self.pre_result[filepath]['child_files']

        elif os.path.join(self.target_directory, filepath) in self.pre_result and "child_files" in self.pre_result[os.path.join(self.target_directory, filepath)]:
            return self.pre_result[os.path.join(self.target_directory, filepath)]['child_files']

        else:
            logger.warning("[AST] file {} object or child files not found...".format(filepath))
            return False

    def get_define(self, define_name):
        if define_name in self.define_dict:
            return self.define_dict[define_name]

        else:
            logger.warning("[AST] [INCLUDE FOUND] Can't found this constart {}, pass it ".format(define_name))
            return "not_found"


ast_object = Pretreatment()
