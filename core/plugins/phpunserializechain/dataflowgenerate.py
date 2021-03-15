#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: dataflowgenerate.py
@time: 2020/11/11 14:43
@desc:

'''

import re
import traceback

from core.pretreatment import ast_object

from utils.file import Directory
from utils.utils import ParseArgs
from utils.log import logger, logger_console

from web.index.models import get_dataflow_class

from Kunlun_M.const import ext_dict

from phply import phpast as php


class DataflowGenerate:
    """
    生成Dataflow db
    """

    def __init__(self, *args, **kwargs):
        # 常量类型定义
        self.Object_define = ['Class', 'Function', 'Method', 'Trait']
        self.new_object_define = ['New', 'Array']
        self.method_call = ['FunctionCall', 'MethodCall', 'StaticMethodCall', 'ObjectProperty', 'StaticProperty']

        self.special_function_single = ['Clone', 'Break', 'Continue', 'Return', 'Yield', 'Print', 'Throw']
        self.special_function_multi = ['Echo', 'Unset', 'IsSet']
        self.special_function_expr = ['Empty', 'Eval', 'Include', 'Require', 'Exit']
        self.special_function = self.special_function_single + self.special_function_multi + self.special_function_expr

        self.switch_node = ['If', 'ElseIf', 'Else', 'Try', 'While', 'DoWhile', 'For', 'Foreach', 'Switch', 'Case',
                            'Default']

        self.import_node = ['UseDeclarations', 'UseDeclaration', 'ClassVariables', 'ClassVariable',
                            'StaticVariable', 'MagicConstant', 'Constant', 'LexicalVariable'
                                                                           'ClassConstants', 'ClassConstant',
                            'ConstantDeclarations', 'ConstantDeclaration', 'TraitUse']

        self.variable_type_node = ['Global', 'Static', 'Cast']
        self.op_node = ['AssignOp', 'PreIncDecOp', 'PostIncDecOp', 'BinaryOp', 'UnaryOp', 'TernaryOp']

        self.white_node = ['InlineHTML', 'Declare', 'Variable']
        self.define_node = ['Interface', 'Namespace']
        self.check_node = ['IsSet', 'Empty']
        self.child_node = ['Block', 'Silence', 'Namespace']
        self.assign_node = ['Assignment', 'ListAssignment']
        self.param_node = ['FormalParameter', 'Parameter', 'ArrayElement', 'ArrayOffset', 'StringOffset']

        # 临时全局变量
        self.dataflows = []
        self.target = ""

    def main(self, target, renew=False):

        self.target = target

        targetlist = re.split("[\\\/]", target)
        if target.endswith("/") or target.endswith("\\"):
            filename = targetlist[-2]
        else:
            filename = targetlist[-1]

        self.dataflow_db = get_dataflow_class(filename, isrenew=renew)

        dataflows = self.dataflow_db.objects.all()

        if not dataflows:
            logger.info('[PhpUnSerChain] Target {} first Scan...Renew dataflow DB.'.format(filename))
            self.new_dataflow()

        else:
            logger.info('[PhpUnSerChain] Target {} db load success'.format(filename))

        return self.dataflow_db

    def new_dataflow(self):
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

        for file in files:
            filename_list = []

            if file[0] in ext_dict['php']:
                filename_list = file[1]['list']

            for filename in filename_list:
                all_nodes = ast_object.get_nodes(filename)
                self.dataflows = []

                base_locate = filename.replace('/', '#').replace('\\', '#').replace('.', '_')
                logger.info("[PhpUnSerChain] New Base locate {}".format(base_locate))

                self.base_dataflow_generate(all_nodes, base_locate)

                base_address_index = self.dataflow_db.objects.all().count()

                for dataflow in self.dataflows:
                    if dataflow:

                        source_node = str(dataflow[2])
                        sink_node = str(dataflow[4])

                        if re.search(r'&[0-9]+', source_node, re.I):
                            address_list = re.findall(r'&[0-9]+', source_node, re.I)
                            for address in address_list:
                                source_node = source_node.replace(address, '&{}'.format(int(address[1:]) + base_address_index))
                            # source_node = '&{}'.format(int(source_node[1:])+base_address_index)

                        if re.search(r'&[0-9]+', sink_node, re.I):
                            address_list = re.findall(r'&[0-9]+', sink_node, re.I)
                            for address in address_list:
                                sink_node = sink_node.replace(address, '&{}'.format(int(address[1:]) + base_address_index))

                        # if str(sink_node).startswith('&'):
                        #     sink_node = '&{}'.format(int(sink_node[1:])+base_address_index)

                        df = self.dataflow_db(node_locate=dataflow[0], node_sort=dataflow[1],
                                              source_node=source_node, node_type=dataflow[3], sink_node=sink_node)
                        df.save()

    def get_node_params(self, node, now_locate, now_sort=0):
        result_params = ()
        node_typename = node.__class__.__name__
        new_sort = -1

        if node_typename in ['Class']:
            result_params = (self.get_node_name(node.extends, now_locate, new_sort),)

        elif node_typename in ['Trait']:
            result_params = (self.get_node_name(node.traits, now_locate, new_sort),)

        elif node_typename in ['Function', 'Method']:

            result_params = []

            for param in node.params:
                result_params.append(self.get_node_name(param.name, now_locate, new_sort))

            result_params = tuple(result_params)

        elif node_typename in ['FunctionCall', 'MethodCall', 'StaticMethodCall']:
            result_params = []

            for param in node.params:
                result_params.append(self.get_node_name(param, now_locate, new_sort))

            result_params = tuple(result_params)

        elif node_typename in ['New']:
            result_params = []

            for param in node.params:
                result_params.append(self.get_node_name(param, now_locate, new_sort))

            result_params = tuple(result_params)

        elif node_typename in self.special_function_multi:
            result_params = []

            for param in node.nodes:
                result_params.append(self.get_node_name(param, now_locate, new_sort))

            result_params = tuple(result_params)

        return result_params

    def get_node_name(self, node, base_locate, now_sort=False):

        node_typename = node.__class__.__name__

        if type(node) is list:
            result = []
            for n in node:
                result.append(self.get_node_name(n, base_locate, now_sort))

            return str(result)

        if isinstance(node, php.Variable):
            return '{}-{}'.format(node_typename, node.name)

        elif isinstance(node, php.ArrayOffset):
            return '{}-{}@{}'.format(node_typename, self.get_node_name(node.node, base_locate, now_sort),
                                     self.get_node_name(node.expr, base_locate, now_sort))

        elif isinstance(node, php.ArrayElement):
            if self.get_node_name(node.key, base_locate, now_sort):
                return '{}:{}'.format(self.get_node_name(node.key, base_locate, now_sort),
                                      self.get_node_name(node.value, base_locate, now_sort))
            else:
                return '{}'.format(self.get_node_name(node.value, base_locate, now_sort))

        elif isinstance(node, php.Array):
            result = []
            for array_node in node.nodes:
                result.append(self.get_node_name(array_node, base_locate, now_sort))

            return '{}-{}'.format(node_typename, result)

        elif isinstance(node, php.Assignment):
            self.base_dataflow_generate([node], base_locate, now_sort=now_sort)
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        elif isinstance(node, php.Parameter):
            return str(self.get_node_name(node.node, base_locate, now_sort))

        elif isinstance(node, php.FormalParameter):
            return str(self.get_node_name(node.name, base_locate, now_sort))

        elif isinstance(node, php.ObjectProperty):
            return '{}->{}'.format(self.get_node_name(node.node, base_locate, now_sort),
                                   self.get_node_name(node.name, base_locate, now_sort))

        elif isinstance(node, php.New):
            # self.base_dataflow_generate([node], base_locate, now_sort=now_sort)
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        elif isinstance(node, php.Constant):
            return 'Constant-' + node.name

        elif isinstance(node, php.MagicConstant):
            return 'Constant-{}@{}'.format(self.get_node_name(node.name, base_locate, now_sort),
                                           self.get_node_name(node.value, base_locate, now_sort))

        elif isinstance(node, php.FunctionCall):
            self.base_dataflow_generate([node], base_locate, now_sort=now_sort)
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        elif isinstance(node, php.MethodCall):
            # self.base_dataflow_generate([node], base_locate, now_sort=now_sort)
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        elif isinstance(node, php.StaticProperty):
            return '{}->{}'.format(self.get_node_name(node.node, base_locate, now_sort),
                                   self.get_node_name(node.name, base_locate, now_sort))

        elif isinstance(node, php.StaticMethodCall):

            # self.base_dataflow_generate([node], base_locate, now_sort=now_sort)
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        elif node_typename in self.op_node:
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        elif isinstance(node, php.Cast):
            return '({}){}'.format(self.get_node_name(node.type, base_locate, now_sort),
                                   self.get_node_name(node.expr, base_locate, now_sort))

        elif isinstance(node, php.Silence):
            return self.get_node_name(node.expr, base_locate, now_sort)

        elif isinstance(node, php.ForeachVariable):
            return self.get_node_name(node.name, base_locate, now_sort)

        elif node_typename in self.special_function:
            # self.base_dataflow_generate([node], base_locate, now_sort=now_sort)
            now_nodeid, Newnode = self.deep_obj_address_generate(node, base_locate, now_sort)

            return '&{}'.format(now_nodeid)

        else:
            if not node:
                return ""

            return node

    def get_node_nodes(self, node):
        result_nodes = []

        if type(node) is list:
            return node

        if isinstance(node, php.Block):
            result_nodes = node.nodes

        return result_nodes

    def get_binaryop_name(self, node, base_locate, now_sort):

        node_typename = node.__class__.__name__

        if isinstance(node, php.BinaryOp):
            result = (self.get_node_name(node.left, base_locate, now_sort), node.op,
                      self.get_node_name(node.right, base_locate, now_sort))
            return result

        elif isinstance(node, php.UnaryOp):
            return self.get_node_name(node.op, base_locate, now_sort), self.get_node_name(node.expr, base_locate,
                                                                                          now_sort)

        elif node_typename in ['IsSet']:
            node_nodes = node.nodes
            result = []

            for node_node in node_nodes:
                result.append(self.get_node_name(node_node, base_locate, now_sort))

            return 'FunctionCall-isset({})'.format(result)

        return self.get_node_name(node, base_locate, now_sort)

    def base_dataflow_generate(self, nodes, base_locate, now_sort=0):
        """
        基础递归类生成dataflow
        :param now_sort:
        :param nodes:
        :param base_locate:
        :return:
        """
        now_locate = base_locate

        for node in nodes:
            try:
                node_typename = node.__class__.__name__

                if now_sort >= 0:
                    now_sort += 1

                if not node:
                    continue

                if node_typename in self.Object_define:
                    # 当节点是类型定义，则需要进入新的域并变更locate
                    node_name = node.name
                    node_nodes = node.nodes

                    new_locate = base_locate + '.' + node_typename + '-' + node_name
                    node_source = node_typename + '-' + node_name
                    flow_type = 'new' + node_typename
                    node_sink = self.get_node_params(node, new_locate, now_sort)

                    # check method modifiers
                    if node_typename == 'Method':
                        node_modifiers = node.modifiers

                        if 'abstract' in node_modifiers:
                            continue
                            # print(node_modifiers)

                    # add now dataflow
                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    # add param
                    if isinstance(node, php.Function) or isinstance(node, php.Method):
                        for param in node.params:
                            # add into dataflow
                            param_name = self.get_node_name(param, new_locate, -1)

                            self.dataflows.append((new_locate, 0, param_name, 'new' + node_typename + 'params',
                                                   self.get_node_name(param.default, new_locate, now_sort)))

                    # 尾递归
                    self.base_dataflow_generate(node_nodes, new_locate)

                elif node_typename == 'Assignment':
                    # 赋值
                    node_source = self.get_node_name(node.node, now_locate, now_sort)
                    flow_type = node_typename
                    node_sink = self.get_node_name(node.expr, now_locate, now_sort)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename == 'ListAssignment':
                    node_source = self.get_node_name(node.nodes, now_locate, now_sort)
                    flow_type = node_typename
                    node_sink = self.get_node_name(node.expr, now_locate, now_sort)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.method_call:
                    node_source = self.get_node_name(node.name, now_locate, now_sort)
                    flow_type = node_typename
                    new_locate = base_locate + '.' + node_typename + '-' + node_source

                    if node_typename == 'MethodCall':
                        node_source = self.get_node_name(node.node, now_locate, now_sort) + '->' + node_source
                    elif node_typename == 'StaticMethodCall':
                        node_source = self.get_node_name(node.class_, now_locate, now_sort) + '::' + node_source
                    elif node_typename == 'ObjectProperty':
                        node_source = self.get_node_name(node.node, now_locate, now_sort) + '->' + node_source
                    elif node_typename == 'StaticProperty':
                        node_source = self.get_node_name(node.node, now_locate, now_sort) + '::' + node_source

                    node_sink = self.get_node_params(node, new_locate, -1)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.special_function:
                    node_source = node_typename.lower()
                    flow_type = 'FunctionCall'
                    new_locate = base_locate + '.' + flow_type + '-' + node_source
                    node_sink = self.get_node_params(node, new_locate, now_sort)

                    if node_typename in self.special_function_single:
                        node_sink = self.get_node_name(node.node, now_locate, -1)

                    elif node_typename in self.special_function_multi:
                        result_params = []

                        for param in node.nodes:
                            result_params.append(self.get_node_name(param, now_locate, -1))

                        node_sink = tuple(result_params)

                    elif node_typename in self.special_function_expr:
                        node_sink = self.get_node_name(node.expr, now_locate, -1)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename == 'New':
                    node_source = self.get_node_name(node.name, now_locate, now_sort)
                    flow_type = 'NewClass'
                    new_locate = base_locate + '.' + flow_type
                    node_sink = self.get_node_params(node, new_locate, now_sort)

                    # for param in node.params:
                    #     # add into dataflow
                    #     param_name = self.get_node_name(param, now_locate, now_sort)
                    #
                    #     self.dataflows.append((new_locate, 0, param_name, 'newClassparams',
                    #                            self.get_node_name(param.is_ref, now_locate, now_sort)))

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.switch_node:
                    new_locate = base_locate + '.' + node_typename
                    node_source = node_typename
                    flow_type = node_typename

                    if node_typename in ['While', 'DoWhile']:

                        # 处理expr op
                        node_id, new_node = self.deep_obj_address_generate(node.expr, new_locate, -1)

                        if node_id:
                            node_sink = '&{}'.format(node_id)
                        else:
                            node_sink = self.get_node_name(new_node, now_locate, now_sort)

                        node_nodes = self.get_node_nodes(node.node)

                    elif node_typename == 'If':
                        # 处理expr op
                        node_id, new_node = self.deep_obj_address_generate(node.expr, new_locate, -1)

                        if node_id:
                            node_sink = '&{}'.format(node_id)
                        else:
                            node_sink = self.get_node_name(new_node, now_locate, now_sort)

                        node_nodes = self.get_node_nodes(node.node)

                        # IF是特殊的语义结构，elseif和else都在if之下，所以必须提前返回
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                        # if 的expr为条件，所以要进deep op
                        # self.deep_op_generate(node.expr, new_locate, 0)

                        # 尾递归
                        self.base_dataflow_generate(node_nodes, new_locate)

                        # for elseif
                        node_elseifs = self.get_node_nodes(node.elseifs)

                        for node_elseif in node_elseifs:
                            node_typename = node_elseif.__class__.__name__

                            new_locate = base_locate + '.' + node_typename
                            now_sort += 1
                            node_source = node_typename
                            flow_type = node_typename

                            node_id, new_node = self.deep_obj_address_generate(node_elseif.expr, new_locate, -1)

                            if node_id:
                                node_sink = '&{}'.format(node_id)
                            else:
                                node_sink = self.get_node_name(new_node, now_locate, now_sort)

                            node_nodes = self.get_node_nodes(node_elseif.node)

                            self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                            # 尾递归
                            self.base_dataflow_generate(node_nodes, new_locate)

                        # for else
                        node_else = node.else_

                        if node_else:
                            node_typename = node_else.__class__.__name__

                            new_locate = base_locate + '.' + node_typename
                            now_sort += 1
                            node_source = node_typename
                            flow_type = node_typename
                            node_sink = ()
                            node_nodes = self.get_node_nodes(node_else.node)

                            self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                            # 尾递归
                            self.base_dataflow_generate(node_nodes, new_locate)
                        continue

                    elif node_typename in ['Switch', 'Case', 'Default']:

                        if node_typename == 'Default':
                            node_sink = 'Default'
                        else:
                            node_sink = self.get_node_name(node.expr, now_locate, now_sort)

                        node_nodes = self.get_node_nodes(node.nodes)

                    elif node_typename in ['Try']:
                        node_sink = ""
                        node_nodes = self.get_node_nodes(node.nodes)

                        # try是特殊的语义结构，catch 和 finally 都应该在之后
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                        # 尾递归
                        self.base_dataflow_generate(node_nodes, new_locate)

                        # catch
                        node_catches = self.get_node_nodes(node.catches)

                        for node_catch in node_catches:
                            node_typename = node_catch.__class__.__name__
                            new_locate = new_locate + '.' + node_typename
                            now_sort += 1
                            node_source = node_typename
                            flow_type = node_typename
                            node_sink = (node_catch.class_, self.get_node_name(node_catch.var, now_locate, now_sort))
                            node_nodes = self.get_node_nodes(node_catch.nodes)

                            self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                            # 尾递归
                            self.base_dataflow_generate(node_nodes, new_locate)

                        # finally
                        node_finally = getattr(node, 'finally')

                        if node_finally:
                            node_typename = node_finally.__class__.__name__

                            new_locate = base_locate + '.' + node_typename
                            now_sort += 1
                            node_source = node_typename
                            flow_type = node_typename
                            node_sink = ()
                            node_nodes = self.get_node_nodes(node_finally.nodes)

                            self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                            # 尾递归
                            self.base_dataflow_generate(node_nodes, new_locate)
                        continue

                    elif node_typename in ['For']:
                        node_sink = ""
                        node_nodes = self.get_node_nodes(node.node)

                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                        new_locate = now_locate + '.' + node_typename

                        node_for_starts = node.start

                        if node_for_starts:
                            for node_for_start in node_for_starts:
                                node_for_start_flow_type = node_typename + '-' + 'Start'
                                node_for_start_type = node_for_start.__class__.__name__

                                if node_for_start_type == 'Variable':
                                    # if $n: 判断某个变量是否为真
                                    node_for_start_source = self.get_node_name(node_for_start.name, now_locate, now_sort)
                                    node_for_start_sink = ""

                                elif node_for_start_type in ['PostIncDecOp', 'PreIncDecOp']:
                                    node_for_start_source = self.get_node_name(node_for_start, now_locate, now_sort)
                                    node_for_start_sink = self.get_node_name(node_for_start.expr, now_locate, now_sort)

                                else:
                                    node_for_start_source = self.get_node_name(node_for_start.node, now_locate, now_sort)
                                    node_for_start_sink = self.get_node_name(node_for_start.expr, now_locate, now_sort)

                                self.dataflows.append((new_locate, 0, node_for_start_source, node_for_start_flow_type,
                                                       node_for_start_sink))

                        node_for_tests = node.test

                        if node_for_tests:
                            for node_for_test in node_for_tests:
                                node_for_test_flow_type = node_typename + '-' + 'Limit'
                                node_for_test_type = node_for_test.__class__.__name__

                                if node_for_test_type == 'BinaryOp':
                                    node_for_test_source = self.get_node_name(node_for_test.left, now_locate, now_sort)
                                    node_for_test_sink = self.get_binaryop_name(node_for_test, now_locate, now_sort)

                                else:
                                    node_for_test_source = self.get_node_name(node_for_test, now_locate, now_sort)
                                    node_for_test_sink = self.get_node_name(node_for_test, now_locate, now_sort)

                                self.dataflows.append(
                                    (new_locate, 0, node_for_test_source, node_for_test_flow_type, node_for_test_sink))

                        node_for_counts = node.count

                        if node_for_counts:

                            for node_for_count in node_for_counts:
                                node_for_count_flow_type = node_typename + '-' + 'Count'
                                node_for_count_type = node_for_count.__class__.__name__

                                if node_for_count_type in ['PostIncDecOp', 'PreIncDecOp']:
                                    node_for_count_source = self.get_node_name(node_for_count, now_locate, now_sort)
                                    node_for_count_sink = self.get_node_name(node_for_count.expr, now_locate, now_sort)

                                elif node_for_count_type in ['AssignOp']:
                                    node_for_count_source = self.get_node_name(node_for_count.left, now_locate,
                                                                               now_sort)
                                    node_for_count_sink = '{} {} {}'.format(
                                        self.get_node_name(node_for_count.left, now_locate, now_sort),
                                        self.get_node_name(node_for_count.op, now_locate, now_sort),
                                        self.get_node_name(
                                            node_for_count.right, now_locate, now_sort))

                                elif node_for_count_type in ['Assignment']:
                                    node_for_count_source = self.get_node_name(node_for_count.node, now_locate,
                                                                               now_sort)
                                    node_for_count_sink = self.get_node_name(node_for_count.expr, now_locate, now_sort)

                                else:
                                    node_for_count_source = self.get_node_name(node_for_count, now_locate, now_sort)
                                    node_for_count_sink = self.get_node_name(node_for_count, now_locate, now_sort)

                                node_for_count_flow_type += '-{}'.format(node_for_count_type)

                                self.dataflows.append(
                                    (new_locate, 0, node_for_count_source, node_for_count_flow_type,
                                     node_for_count_sink))

                        self.base_dataflow_generate(node_nodes, new_locate)
                        continue

                    elif isinstance(node, php.Foreach):
                        node_sink = (self.get_node_name(node.expr, now_locate, now_sort),
                                     self.get_node_name(node.keyvar, now_locate, now_sort),
                                     self.get_node_name(node.valvar, now_locate, now_sort))
                        node_nodes = self.get_node_nodes(node.node)

                    else:
                        continue

                    # add now dataflow
                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    # 尾递归
                    self.base_dataflow_generate(node_nodes, new_locate)

                elif node_typename in self.variable_type_node:
                    if node_typename == 'Cast':
                        node_modifiers = node.type
                        node_nodes = [node.expr]

                        node_source = self.get_node_name(node.expr, now_locate, now_sort)
                        flow_type = node_typename
                        node_sink = '({}){}'.format(node_modifiers, self.get_node_name(node.expr, now_locate, now_sort))

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                        # 尾递归
                        self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)
                        now_sort += 1

                    elif node_typename == 'Static':
                        node_modifiers = 'Static'
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            if node_typename == 'StaticVariable':
                                node_source = self.get_node_name(node.name, now_locate, now_sort)
                                flow_type = 'Assignment'
                                node_sink = '({}){}'.format(node_modifiers,
                                                            self.get_node_name(node.initial, now_locate, now_sort))

                                # add now dataflow
                                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'Global':
                        node_modifiers = 'Global'
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            node_source = self.get_node_name(node.name, now_locate, now_sort)
                            flow_type = 'Global'
                            node_sink = '({}){}'.format(node_modifiers,
                                                        self.get_node_name(node.name, now_locate, now_sort))

                            self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.import_node:
                    if node_typename == 'UseDeclarations':
                        node_nodes = node.nodes

                        self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)

                    elif node_typename == 'UseDeclaration':
                        node_source = node_typename
                        flow_type = node_typename
                        node_sink = self.get_node_name(node.name, now_locate, now_sort)

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'TraitUse':
                        node_source = self.get_node_name(node.name, now_locate, now_sort)
                        flow_type = node_typename
                        node_sink = self.get_node_name(node.renames, now_locate, now_sort)

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'ClassVariables':
                        # classvarialbe可以当作普通变量赋值
                        node_modifiers = node.modifiers
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            if node_typename == 'ClassVariable':
                                node_source = self.get_node_name(node.name, now_locate, now_sort)
                                flow_type = 'Assignment'
                                node_sink = '({}){}'.format(node_modifiers,
                                                            self.get_node_name(node.initial, now_locate, now_sort))

                                # add now dataflow
                                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['ClassVariable', 'StaticVariable']:
                        node_source = self.get_node_name(node.name, now_locate, now_sort)
                        flow_type = 'Assignment'
                        node_sink = self.get_node_name(node.initial, now_locate, now_sort)

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['LexicalVariable']:
                        node_source = self.get_node_name(node.name, now_locate, now_sort)
                        flow_type = 'Assignment'
                        node_sink = self.get_node_name(node.is_ref, now_locate, now_sort)

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['ClassConstants', 'ConstantDeclarations']:
                        node_modifiers = 'const'
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            if node_typename in ['ClassConstant', 'ConstantDeclaration']:
                                node_source = self.get_node_name(node.name, now_locate, now_sort)
                                flow_type = 'Assignment'
                                node_sink = '({}){}'.format(node_modifiers,
                                                            self.get_node_name(node.initial, now_locate, now_sort))

                                # add now dataflow
                                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.op_node:

                    # deep op gen
                    self.deep_obj_address_generate(node, now_locate, now_sort=now_sort)

                elif node_typename == 'Silence':
                    node_nodes = [node.expr]

                    self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)

                elif node_typename in self.define_node:
                    # 特殊的定义结构
                    flow_type = node_typename
                    if node_typename == 'Interface':
                        node_name = self.get_node_name(node.name, now_locate, now_sort)
                        new_locate = now_locate + '.' + node_typename + '-' + node_name
                        node_source = node_typename + '-' + node_name
                        node_nodes = node.nodes
                        node_sink = ()

                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'Namespace':
                        node_name = self.get_node_name(node.name, now_locate, now_sort)
                        new_locate = now_locate + '.' + node_typename + '-' + node_name
                        node_source = node_typename + '-' + node_name
                        node_nodes = node.nodes
                        node_sink = ()
                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    # 尾递归
                    self.base_dataflow_generate(node_nodes, new_locate)

                elif node_typename == 'Block':
                    node_nodes = node.nodes

                    self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)
                elif node_typename in self.white_node:
                    continue

                else:
                    pass

            except KeyboardInterrupt:
                raise

            except:
                logger.warn("[PhpUnSerChain] Something error..\n{}".format(traceback.format_exc()))
                continue

    def deep_obj_address_generate(self, node, base_locate, now_sort=False):
        """
        深入递归op操作寻址，以&作为寻址方式标志，后续为操作id
        :param node:
        :param base_locate:
        :param now_sort:
        :return:
        """
        node_typename = node.__class__.__name__
        now_locate = base_locate

        # 用-1标识是内置调用链
        new_sort = -1

        if node_typename in self.op_node:
            if node_typename in ['BinaryOp', 'AssignOp']:

                # 左值递归
                node_lefts = node.left
                last_node_id, new_node = self.deep_obj_address_generate(node_lefts, now_locate, now_sort=new_sort)

                if last_node_id:
                    node_source = '&{}'.format(last_node_id)
                else:
                    node_source = new_node

                flow_type = '{}-{}'.format(node_typename, node.op)

                # 右值递归
                node_rights = node.right
                last_node_id, new_node = self.deep_obj_address_generate(node_rights, now_locate, now_sort=new_sort)

                if last_node_id:
                    node_sink = '&{}'.format(last_node_id)
                else:
                    node_sink = new_node

                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))
                now_nodeid = len(self.dataflows)

                return now_nodeid, True

            elif node_typename in ['PostIncDecOp', 'PreIncDecOp', 'UnaryOp']:

                last_node_id, new_node = self.deep_obj_address_generate(node.expr, now_locate, now_sort=new_sort)

                if last_node_id:
                    node_source = '&{}'.format(last_node_id)
                else:
                    node_source = new_node

                flow_type = '{}-{}'.format(node_typename, node.op)
                node_sink = 1

                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))
                now_nodeid = len(self.dataflows)

                return now_nodeid, True

            elif node_typename == 'TernaryOp':
                last_node_id, new_node = self.deep_obj_address_generate(node.expr, now_locate, now_sort=new_sort)

                if last_node_id:
                    node_source = '&{}'.format(last_node_id)
                else:
                    node_source = new_node

                flow_type = '{}-?'.format(node_typename)

                node_iftrue = node.iftrue
                last_node_id, new_node = self.deep_obj_address_generate(node_iftrue, now_locate, now_sort=new_sort)

                if last_node_id:
                    new_node_source = '&{}'.format(last_node_id)
                else:
                    new_node_source = new_node

                new_node_flow_type = 'TernaryOp-return'

                node_iffalse = node.iffalse
                last_node_id, new_node = self.deep_obj_address_generate(node_iffalse, now_locate, now_sort=new_sort)

                if last_node_id:
                    new_node_sink = '&{}'.format(last_node_id)
                else:
                    new_node_sink = new_node

                self.dataflows.append((now_locate, now_sort, new_node_source, new_node_flow_type, new_node_sink))
                new_nodeid = len(self.dataflows)

                node_sink = new_nodeid

                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))
                now_nodeid = len(self.dataflows)

                return now_nodeid, True

        elif node_typename in ['Variable', 'ArrayOffset', 'Array', 'Constant']:
            return False, self.get_node_name(node, base_locate, now_sort)

        elif node_typename in ['list', 'dict', 'str', 'int']:
            return False, node

        else:
            self.base_dataflow_generate([node], now_locate, now_sort=now_sort)
            now_nodeid = len(self.dataflows)

            return now_nodeid, True
