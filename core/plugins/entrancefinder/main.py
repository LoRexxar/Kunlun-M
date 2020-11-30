#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: main.py
@time: 2020/11/9 14:08
@desc:

'''


import re
import difflib
import traceback

from core.plugins.baseplugin import BasePluginClass

from core.pretreatment import ast_object

from utils.file import Directory
from utils.utils import ParseArgs
from utils.log import logger

from Kunlun_M.const import ext_dict


class EntranceFinder(BasePluginClass):
    """
    发现入口文件
    """
    def __init__(self, *args, **kwargs):
        super(EntranceFinder, self).__init__(*args)

        self.plugin_name = 'entrance_finder'

        # new 参数
        self.parser_group_plugin.add_argument('-l', '--limit', dest='limit', action='store', default=2,
                                              help='limit node number(default 2)')

        self.parser_group_plugin.add_argument('-b', '--blackwords', dest='blackwords', action='store', default="",
                                              help='set blacklist for scan(use \',\' split string)')

        # 参数列表
        self.required_arguments_list = ['target']
        self.arguments_list = ['target', 'debug', 'limit', 'blackwords']

        # 检查参数
        self.check_args()

        # 赋值
        self.eval_args()
        self.limit = int(self.limit)

        self.black_node = ['Function', 'Class']
        self.black_function_name = ['define']
        self.import_node = ['Include', 'Require', 'Assignment', 'ListAssignment']
        self.filter_node = ['InlineHTML', 'header']
        self.switch_node = ['If', 'ElseIf', 'Else', 'Try', 'While', 'DoWhile', 'For', 'Foreach', 'Switch', 'Case',
                            'Default']
        self.import_node = self.import_node + ['UseDeclarations', 'UseDeclaration', 'ClassVariables', 'ClassVariable', 'Static',
                            'StaticVariable', 'AssignOp', 'PreIncDecOp', 'PostIncDecOp',
                            'ClassConstants', 'ClassConstant', 'ConstantDeclarations', 'ConstantDeclaration']

        self.filedata_dict = {}
        self.black_list = []

        # core
        self.main()

    def main(self):

        self.load_files()
        self.get_statistics()

    def load_files(self):
        target = self.target

        targetlist = re.split("[\\\/]", target)
        if target.endswith("/") or target.endswith("\\"):
            filename = targetlist[-2]
        else:
            filename = targetlist[-1]

        logger.info('[EntranceFinder] Target {} start scan.'.format(filename))
        logger.info('[EntranceFinder] Set Scan limit node number is {}'.format(self.limit))

        if self.blackwords:
            self.black_list_split()
            logger.info('[EntranceFinder] Set Scan Blacklist is {}'.format(self.black_list))

        # 加载目录文件
        pa = ParseArgs(self.target, '', 'csv', '', 'php', '', a_sid=None)
        target_mode = pa.target_mode

        target_directory = pa.target_directory(target_mode)
        logger.info('[CLI] Target : {d}'.format(d=target_directory))

        # static analyse files info
        files, file_count, time_consume = Directory(target_directory).collect_files()

        # Pretreatment ast object
        ast_object.init_pre(target_directory, files)
        ast_object.pre_ast_all(['php'])

        filecontent_dict = {}

        for file in files:

            if file[0] in ext_dict['php']:
                filename_list = file[1]['list']

                for filename in filename_list:
                    all_nodes = ast_object.get_nodes(filename)
                    now_content = ast_object.get_content(filename)

                    # check black list
                    is_black = False
                    for bword in self.black_list:
                        if bword in now_content:
                            logger.debug('[EntranceFinder] found {} in File {}'.format(bword, filename))
                            is_black = True

                    if is_black:
                        continue

                    nodes_count, black_nodes_count = self.count_line(all_nodes)

                    if nodes_count in self.filedata_dict:
                        check_ratio = self.get_check_ratio(now_content, filecontent_dict[nodes_count])

                        self.filedata_dict[nodes_count].append((filename, nodes_count, black_nodes_count, check_ratio))

                    else:
                        self.filedata_dict[nodes_count] = [(filename, nodes_count, black_nodes_count, 1)]
                        filecontent_dict[nodes_count] = now_content

    def get_statistics(self):
        """
        获取统计结果
        :return:
        """
        more_than_twoline_nodes = []
        oneline_nodes = []
        similar_nodes = {}

        for node_count in self.filedata_dict:
            file_similars = {}

            for data in self.filedata_dict[node_count]:
                now_similar = data[3]
                similar_variance = self.check_similar_variance(now_similar, file_similars)

                if similar_variance:
                    # log in file_similars
                    file_similars[similar_variance[0]].append(data)

                else:
                    file_similars[data[0]] = [data]

                    if node_count > self.limit:
                        more_than_twoline_nodes.append(data)

                    elif 0 < node_count <= self.limit:
                        oneline_nodes.append(data)

            similar_nodes.update(file_similars)

        # sort
        def get_count(node):
            return node[1]

        more_than_twoline_nodes.sort(key=get_count, reverse=True)
        oneline_nodes.sort(key=get_count, reverse=True)

        # print
        logger.info("[EntranceFinder] Target has more than {}:\n-----------------------------------------------------".format(self.limit))

        for data in more_than_twoline_nodes:
            logger.info("[EntranceFinder] {} has {} nodes".format(data[0], data[1]))

            if data[0] in similar_nodes:
                if len(similar_nodes) > 1:
                    similar_nodes[data[0]].pop(0)

                    for snode in similar_nodes[data[0]]:
                        logger.info("[EntranceFinder] - Similar File {} has {} nodes".format(snode[0], snode[1]))

        logger.info("[EntranceFinder] Target has < {} node:\n------------------------------------------------------".format(self.limit))

        for data in oneline_nodes:
            logger.info("[EntranceFinder] {} has {} nodes".format(data[0], data[1]))

            if data[0] in similar_nodes:
                if len(similar_nodes) > 1:
                    similar_nodes[data[0]].pop(0)

                    for snode in similar_nodes[data[0]]:

                        logger.info("[EntranceFinder] - Similar File {} has {} nodes".format(snode[0], snode[1]))

    def count_line(self, nodes):
        """
        统计节点数量
        :param nodes:
        :return:
        """

        nodes_count = len(nodes)
        black_nodes_count = 0

        for node in nodes:
            node_typename = node.__class__.__name__

            if node_typename in self.black_node:
                nodes_count -= 1
                black_nodes_count += 1

            elif node_typename in self.filter_node or node_typename in self.import_node:
                nodes_count -= 1

            elif node_typename == 'NoneType':
                nodes_count -= 1

            elif node_typename == 'FunctionCall' and node.name in self.black_function_name:
                nodes_count -= 1
                black_nodes_count += 1

            elif node_typename in self.switch_node:
                nodes_count += 2

            # else:
            #     print(node_typename)

        return nodes_count, black_nodes_count

    def check_similar(self, content, origin_content):

        ratio = difflib.SequenceMatcher(None, content, origin_content).quick_ratio()

        if ratio > 0.95:
            return True

        return False

    def check_similar_variance(self, similar, file_similars):

        for filename in file_similars:
            file_similar = file_similars[filename][0]

            if abs(file_similar[3] - similar) < 0.03:
                return file_similar

        return False

    def get_check_ratio(self, content, origin_content):

        ratio = difflib.SequenceMatcher(None, content, origin_content).quick_ratio()

        return ratio

    def black_list_split(self):
        if ',' in self.blackwords:
            self.black_list = self.blackwords.split(',')

        else:
            self.black_list = [self.blackwords]
