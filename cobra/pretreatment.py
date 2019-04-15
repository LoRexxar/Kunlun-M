#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/4/15 14:51
# @Author  : LoRexxar
# @File    : Pretreatment.py
# @Contact : lorexxar@gmail.com


from phply.phplex import lexer  # 词法分析
from phply.phpparse import make_parser  # 语法分析
from phply import phpast as php
from .log import logger

import os
import codecs
import traceback


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

        self.target_directory = self.target_directory.replace('/', '\\')

    def pre_ast(self):

        for fileext in self.file_list:

            if ".php" == fileext[0]:
                # 下面是对于php文件的处理逻辑
                for filepath in fileext[1]['list']:

                    filepath = self.target_directory + filepath.replace('/', '\\')
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'php'

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

                    # 搜索所有的常量

                    for node in all_nodes:
                        if isinstance(node, php.FunctionCall) and node.name == "define":
                            define_params = node.params
                            logger.debug("[AST][Pretreatment] new define {}={}".format(define_params[0].node, define_params[1].node))
                            self.define_dict[define_params[0].node] = define_params[1].node

    def get_nodes(self, filepath):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            return self.pre_result[filepath]['ast_nodes']

        elif self.target_directory + filepath in self.pre_result:
            return self.pre_result[self.target_directory + filepath]['ast_nodes']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def get_content(self, filepath):

        if filepath in self.pre_result:
            return self.pre_result[filepath]['content']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def get_object(self):
        return self

    def get_define(self, define_name):
        if define_name in self.define_dict:
            return self.define_dict[define_name]

        else:
            logger.warning("[AST] [INCLUDE FOUND] Can't found this constart {}, pass it ".format(define_name))
            return "not_found"


ast_object = Pretreatment()
