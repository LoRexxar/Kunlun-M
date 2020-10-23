#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: __init__.py.py
@time: 2020/10/14 16:45
@desc:

'''


import logging
from utils.log import logger


class BasePluginClass:
    """
    插件模板类
    """
    def __init__(self, parser, parser_group_plugin):
        """

        """
        # 设置参数

        parser_group_plugin.add_argument('-t', '--target', dest='target', action='store', default='', metavar='<target>', help='file, folder')
        parser_group_plugin.add_argument('-d', '--debug', dest='debug', action='store_false', default=False,
                                         help='open debug mode')

        self.args = parser.parse_args()
        self.parser = parser
        self.parser_group_plugin = parser_group_plugin
        self.plugin_name = 'BasePlugin'

        # 参数列表
        self.required_arguments_list = ['target']
        self.arguments_list = ['target', 'debug']

        # 检查参数
        # self.check_args()

        # 赋值
        # self.eval_args()

    def eval_args(self):
        for arg in self.arguments_list:
            setattr(self, arg, getattr(self.args, arg))

    def check_args(self):
        for required_argument in self.required_arguments_list:
            if not hasattr(self.args, required_argument) or not getattr(self.args, required_argument):
                self.parser_group_plugin.print_help()
                logger.error("[INIT][Plugin] Plugin {} argument {} is require.".format(self.plugin_name, required_argument))
                exit()

        if hasattr(self.args, "debug") and self.args.debug:
            logger.setLevel(logging.DEBUG)
            logger.debug('[INIT] set logging level: debug')

        return True

    def main(self, *args, **kwargs):
        """
        主线程传递参数
        :param args:
        :param kwargs:
        :return:
        """
        print(args)
