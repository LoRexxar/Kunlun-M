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
from utils.log import logger

from web.index.models import get_dataflow_class

from Kunlun_M.const import ext_dict

from phply import phpast as php


class DataflowGenerate:
    """
    生成Dataflow db
    """

    def __init__(self, *args, **kwargs):
        # 常量类型定义
        self.Object_define = ['Class', 'Function', 'Method']
        self.method_call = ['FunctionCall', 'MethodCall', 'StaticMethodCall', 'ObjectProperty']
        self.special_function = ['Eval', 'Echo', 'Print', 'Return', 'Break', 'Include',
                                 'Require', 'Exit', 'Throw', 'Unset', 'Continue', 'Yield']
        self.switch_node = ['If', 'ElseIf', 'Else', 'Try', 'While', 'DoWhile', 'For', 'Foreach', 'Switch', 'Case',
                            'Default']
        self.import_node = ['UseDeclarations', 'UseDeclaration', 'ClassVariables', 'ClassVariable', 'Static',
                            'StaticVariable', 'AssignOp', 'PreIncDecOp', 'PostIncDecOp',
                            'ClassConstants', 'ClassConstant', 'ConstantDeclarations', 'ConstantDeclaration']
        self.white_node = ['InlineHTML', 'Declare']
        self.define_node = ['Interface', 'Namespace']
        self.check_node = ['IsSet', 'Empty']

        # 临时全局变量
        self.dataflows = []
        self.target = ""

    def main(self, target):

        self.target = target

        targetlist = re.split("[\\\/]", target)
        if target.endswith("/") or target.endswith("\\"):
            filename = targetlist[-2]
        else:
            filename = targetlist[-1]

        self.dataflow_db = get_dataflow_class(filename)

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

                for dataflow in self.dataflows:
                    if dataflow:
                        df = self.dataflow_db(node_locate=dataflow[0], node_sort=dataflow[1],
                                              source_node=dataflow[2], node_type=dataflow[3], sink_node=dataflow[4])
                        df.save()

    def get_node_params(self, node):
        result_params = ()
        node_typename = node.__class__.__name__

        if isinstance(node, php.Class):
            result_params = (self.get_node_name(node.extends),)

        elif isinstance(node, php.Function) or isinstance(node, php.Method):

            result_params = []

            for param in node.params:
                result_params.append(self.get_node_name(param.name))

            result_params = tuple(result_params)

        elif isinstance(node, php.FunctionCall) or isinstance(node, php.MethodCall) or isinstance(node,
                                                                                                  php.StaticMethodCall):
            result_params = []

            for param in node.params:
                result_params.append(self.get_node_name(param))

            result_params = tuple(result_params)

        elif isinstance(node, php.New):
            result_params = []

            for param in node.params:
                result_params.append(self.get_node_name(param))

            result_params = tuple(result_params)

        elif isinstance(node, php.Unset):
            result_params = []

            for param in node.nodes:
                result_params.append(self.get_node_name(param))

            result_params = tuple(result_params)

        return result_params

    def get_node_name(self, node):

        node_typename = node.__class__.__name__

        if type(node) is list:
            result = []
            for n in node:
                result.append(self.get_node_name(n))

            return str(result)

        if isinstance(node, php.Variable):
            return '{}-{}'.format(node_typename, node.name)

        elif isinstance(node, php.ArrayOffset):
            return '{}-{}@{}'.format(node_typename, self.get_node_name(node.node), self.get_node_name(node.expr))

        elif isinstance(node, php.ArrayElement):
            if self.get_node_name(node.key):
                return '{}:{}'.format(self.get_node_name(node.key), self.get_node_name(node.value))
            else:
                return '{}'.format(self.get_node_name(node.value))

        elif isinstance(node, php.Array):
            result = []
            for array_node in node.nodes:
                result.append(self.get_node_name(array_node))

            return '{}-{}'.format(node_typename, result)

        elif isinstance(node, php.Assignment):
            return '{}={}'.format(self.get_node_name(node.node), self.get_node_name(node.expr))

        elif isinstance(node, php.Parameter):
            return str(self.get_node_name(node.node))

        elif isinstance(node, php.ObjectProperty):
            return '{}->{}'.format(self.get_node_name(node.node), self.get_node_name(node.name))

        elif isinstance(node, php.New):
            return 'Class-{}-{}'.format(self.get_node_name(node.name), str(self.get_node_params(node)))

        elif isinstance(node, php.Constant):
            return 'Constant-' + node.name

        elif isinstance(node, php.MagicConstant):
            return 'Constant-{}@{}'.format(self.get_node_name(node.name), self.get_node_name(node.value))

        elif isinstance(node, php.PostIncDecOp) or isinstance(node, php.PreIncDecOp):
            return str(self.get_node_name(node.op))

        elif isinstance(node, php.FunctionCall):
            return 'FunctionCall-{}{}'.format(self.get_node_name(node.name),
                                              self.get_node_name(self.get_node_params(node)))

        elif isinstance(node, php.MethodCall) or isinstance(node, php.StaticProperty):
            return '{}->MethodCall-{}{}'.format(self.get_node_name(node.node), self.get_node_name(node.name),
                                                self.get_node_name(self.get_node_params(node)))

        elif isinstance(node, php.StaticMethodCall):
            return '{}::StaticMethodCall-{}{}'.format(self.get_node_name(node.class_),
                                                      self.get_node_name(node.name),
                                                      self.get_node_name(self.get_node_params(node)))

        elif isinstance(node, php.BinaryOp):
            return '{}{}{}'.format(self.get_node_name(node.left), node.op, self.get_node_name(node.right))

        elif isinstance(node, php.TernaryOp):
            return '{}?{}:{}'.format(self.get_node_name(node.expr), self.get_node_name(node.iftrue),
                                     self.get_node_name(node.iffalse))

        elif isinstance(node, php.Cast):
            return '({}){}'.format(self.get_node_name(node.type), self.get_node_name(node.expr))

        elif isinstance(node, php.Silence):
            return self.get_node_name(node.expr)

        elif isinstance(node, php.ForeachVariable):
            return self.get_node_name(node.name)

        elif isinstance(node, php.UnaryOp):
            return '{}{}'.format(self.get_node_name(node.op), self.get_node_name(node.expr))

        elif node_typename in self.check_node:
            if node_typename == 'IsSet':
                node_nodes = node.nodes
                result = []

                for node_node in node_nodes:
                    result.append(self.get_node_name(node_node))

            elif node_typename == 'Empty':
                result = self.get_node_name(node.expr)

            else:
                result = node

            return 'FunctionCall-{}({})'.format(node_typename, result)

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

    def get_binaryop_name(self, node):

        node_typename = node.__class__.__name__

        if isinstance(node, php.BinaryOp):
            result = (self.get_node_name(node.left), node.op, self.get_node_name(node.right))
            return result

        elif isinstance(node, php.UnaryOp):
            return self.get_node_name(node.op), self.get_node_name(node.expr)

        elif node_typename in ['IsSet']:
            node_nodes = node.nodes
            result = []

            for node_node in node_nodes:
                result.append(self.get_node_name(node_node))

            return 'FunctionCall-isset({})'.format(result)

        return self.get_node_name(node)

    def base_dataflow_generate(self, nodes, base_locate, now_sort=False):
        """
        基础递归类生成dataflow
        :param now_sort:
        :param nodes:
        :param base_locate:
        :return:
        """
        if not now_sort:
            now_sort = 0
        now_locate = base_locate

        for node in nodes:
            try:
                node_typename = node.__class__.__name__
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
                    node_sink = self.get_node_params(node)

                    # add now dataflow
                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    # add param
                    if isinstance(node, php.Function) or isinstance(node, php.Method):
                        for param in node.params:
                            # add into dataflow
                            param_name = 'Variable-{}'.format(self.get_node_name(param))

                            self.dataflows.append((new_locate, 0, param_name, 'new' + node_typename + 'params',
                                                   self.get_node_name(param.default)))

                    # 尾递归
                    self.base_dataflow_generate(node_nodes, new_locate)

                elif node_typename == 'Assignment':
                    # 赋值
                    node_source = self.get_node_name(node.node)
                    flow_type = node_typename
                    node_sink = self.get_node_name(node.expr)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename == 'ListAssignment':
                    node_source = self.get_node_name(node.nodes)
                    flow_type = node_typename
                    node_sink = self.get_node_name(node.expr)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.method_call:
                    node_source = self.get_node_name(node.name)
                    flow_type = node_typename

                    if node_typename == 'MethodCall':
                        node_source = self.get_node_name(node.node) + '->' + node_source
                    elif node_typename == 'StaticMethodCall':
                        node_source = self.get_node_name(node.class_) + '::' + node_source
                    elif node_typename == 'ObjectProperty':
                        flow_type = 'MethodCall'
                        node_source = self.get_node_name(node)

                    node_sink = self.get_node_params(node)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.special_function:
                    node_source = node_typename.lower()
                    flow_type = 'FunctionCall'
                    node_sink = self.get_node_params(node)

                    if node_typename == 'Eval':
                        node_sink = self.get_node_name(node.expr)
                    elif node_typename == 'Print':
                        node_sink = self.get_node_name(node.node)
                    elif node_typename == 'Echo':
                        result_params = []

                        for param in node.nodes:
                            result_params.append(self.get_node_name(param))

                        node_sink = tuple(result_params)
                    elif node_typename in ['Return', 'Break', 'Continue']:
                        node_sink = self.get_node_name(node.node)
                    elif node_typename in ['Include', 'Require', 'Exit']:
                        node_sink = self.get_node_name(node.expr)
                    elif node_typename == 'Throw':
                        node_sink = self.get_node_name(node.node)
                    elif node_typename == 'Unset':
                        node_sink = self.get_node_params(node)
                    elif node_typename in ['Yield']:
                        node_sink = self.get_node_name(node.node)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename == 'New':
                    node_source = self.get_node_name(node.name)
                    flow_type = 'NewClass'
                    node_sink = self.get_node_params(node)

                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.switch_node:
                    new_locate = base_locate + '.' + node_typename
                    node_source = node_typename
                    flow_type = node_typename

                    if node_typename in ['While', 'DoWhile']:
                        node_sink = self.get_binaryop_name(node.expr)
                        node_nodes = self.get_node_nodes(node.node)

                    elif node_typename == 'If':
                        node_sink = self.get_binaryop_name(node.expr)
                        node_nodes = self.get_node_nodes(node.node)

                        # IF是特殊的语义结构，elseif和else都在if之下，所以必须提前返回
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

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
                            node_sink = self.get_binaryop_name(node.expr)
                            node_nodes = self.get_node_nodes(node.node)

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
                            node_nodes = self.get_node_nodes(node.node)

                            self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                            # 尾递归
                            self.base_dataflow_generate(node_nodes, new_locate)
                        continue

                    elif node_typename in ['Switch', 'Case', 'Default']:

                        if node_typename == 'Default':
                            node_sink = 'Default'
                        else:
                            node_sink = self.get_node_name(node.expr)

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
                            node_sink = ()
                            node_nodes = self.get_node_nodes(node.nodes)

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

                        for node_for_start in node_for_starts:
                            node_for_start_flow_type = node_typename + '-' + 'Start'
                            node_for_start_type = node_for_start.__class__.__name__

                            if node_for_start_type == 'Variable':
                                # if $n: 判断某个变量是否为真
                                node_for_start_source = self.get_node_name(node_for_start.name)
                                node_for_start_sink = ""
                            else:
                                node_for_start_source = self.get_node_name(node_for_start.node)
                                node_for_start_sink = self.get_node_name(node_for_start.expr)

                            self.dataflows.append((new_locate, 0, node_for_start_source, node_for_start_flow_type,
                                                   node_for_start_sink))

                        node_for_tests = node.test

                        for node_for_test in node_for_tests:
                            node_for_test_flow_type = node_typename + '-' + 'Limit'
                            node_for_test_type = node_for_test.__class__.__name__

                            if node_for_test_type == 'BinaryOp':
                                node_for_test_source = self.get_node_name(node_for_test.left)
                                node_for_test_sink = self.get_binaryop_name(node_for_test)

                            else:
                                node_for_test_source = self.get_node_name(node_for_test)
                                node_for_test_sink = self.get_node_name(node_for_test)

                            self.dataflows.append(
                                (new_locate, 0, node_for_test_source, node_for_test_flow_type, node_for_test_sink))

                        node_for_counts = node.count

                        if node_for_counts:

                            for node_for_count in node_for_counts:
                                node_for_count_flow_type = node_typename + '-' + 'Count'
                                node_for_count_type = node_for_count.__class__.__name__

                                if node_for_count_type in ['PostIncDecOp', 'PreIncDecOp']:
                                    node_for_count_source = self.get_node_name(node_for_count)
                                    node_for_count_sink = self.get_node_name(node_for_count.expr)

                                elif node_for_count_type in ['AssignOp']:
                                    node_for_count_source = self.get_node_name(node_for_count.left)
                                    node_for_count_sink = '{} {} {}'.format(self.get_node_name(node_for_count.left),
                                                                            self.get_node_name(node_for_count.op),
                                                                            self.get_node_name(
                                                                                node_for_count.right))

                                elif node_for_count_type in ['Assignment']:
                                    node_for_count_source = self.get_node_name(node_for_count.node)
                                    node_for_count_sink = self.get_node_name(node_for_count.expr)

                                else:
                                    node_for_count_source = self.get_node_name(node_for_count)
                                    node_for_count_sink = self.get_node_name(node_for_count)

                                node_for_count_flow_type += '-{}'.format(node_for_count_type)

                                self.dataflows.append(
                                    (new_locate, 0, node_for_count_source, node_for_count_flow_type,
                                     node_for_count_sink))

                        self.base_dataflow_generate(node_nodes, new_locate)
                        continue

                    elif isinstance(node, php.Foreach):
                        node_sink = (self.get_node_name(node.expr), self.get_node_name(node.keyvar),
                                     self.get_node_name(node.valvar))
                        node_nodes = self.get_node_nodes(node.node)

                    else:
                        print(node)
                        continue

                    # add now dataflow
                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    # 尾递归
                    self.base_dataflow_generate(node_nodes, new_locate)

                elif isinstance(node, php.BinaryOp):
                    node_lefts = [node.left]

                    # 左值递归
                    self.base_dataflow_generate(node_lefts, now_locate, now_sort=now_sort)
                    now_sort += 1
                    node_rights = [node.right]

                    # 右值递归
                    self.base_dataflow_generate(node_rights, now_locate, now_sort=now_sort)
                    now_sort += 1

                elif node_typename == 'Cast':
                    node_modifiers = node.type
                    node_nodes = [node.expr]

                    node_source = self.get_node_name(node.expr)
                    flow_type = node_typename
                    node_sink = '({}){}'.format(node_modifiers, self.get_node_name(node.expr))

                    # add now dataflow
                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    # 尾递归
                    self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)
                    now_sort += 1

                elif node_typename in self.import_node:
                    if node_typename == 'UseDeclarations':
                        node_nodes = node.nodes

                        self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)
                        now_sort += 1

                    elif node_typename == 'UseDeclaration':
                        node_source = node_typename
                        flow_type = node_typename
                        node_sink = self.get_node_name(node.name)

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'ClassVariables':
                        # classvarialbe可以当作普通变量赋值
                        node_modifiers = node.modifiers
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            if node_typename == 'ClassVariable':
                                node_source = self.get_node_name(node.name)
                                flow_type = 'Assignment'
                                node_sink = '({}){}'.format(node_modifiers, self.get_node_name(node.initial))

                                # add now dataflow
                                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'Static':
                        node_modifiers = 'Static'
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            if node_typename == 'StaticVariable':
                                node_source = self.get_node_name(node.name)
                                flow_type = 'Assignment'
                                node_sink = '({}){}'.format(node_modifiers, self.get_node_name(node.initial))

                                # add now dataflow
                                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['ClassVariable', 'StaticVariable']:
                        node_source = self.get_node_name(node.name)
                        flow_type = 'Assignment'
                        node_sink = self.get_node_name(node.initial)

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['PostIncDecOp', 'PreIncDecOp']:
                        node_source = self.get_node_name(node.expr)
                        flow_type = 'Assignment'
                        node_sink = '{}{}'.format(self.get_node_name(node.expr), self.get_node_name(node.op))

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['AssignOp']:
                        node_source = self.get_node_name(node.left)
                        flow_type = 'Assignment'
                        node_sink = '{} {} {}'.format(self.get_node_name(node.left), self.get_node_name(node.op),
                                                      self.get_node_name(node.right))

                        # add now dataflow
                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename in ['ClassConstants', 'ConstantDeclarations']:
                        node_modifiers = 'const'
                        node_nodes = node.nodes

                        for node in node_nodes:
                            node_typename = node.__class__.__name__

                            if node_typename in ['ClassConstant', 'ConstantDeclaration']:
                                node_source = self.get_node_name(node.name)
                                flow_type = 'Assignment'
                                node_sink = '({}){}'.format(node_modifiers, self.get_node_name(node.initial))

                                # add now dataflow
                                self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename == 'Silence':
                    node_nodes = [node.expr]

                    self.base_dataflow_generate(node_nodes, now_locate, now_sort=now_sort)
                    now_sort += 1

                elif node_typename == 'TernaryOp':
                    node_source = self.get_node_name(node.expr)
                    flow_type = 'Assignment'
                    node_sink = '{}:{}'.format(self.get_node_name(node.iftrue), self.get_node_name(node.iffalse))

                    # add now dataflow
                    self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                elif node_typename in self.define_node:
                    # 特殊的定义结构
                    flow_type = node_typename
                    if node_typename == 'Interface':
                        node_name = self.get_node_name(node.name)
                        new_locate = now_locate + '.' + node_typename + '-' + node_name
                        node_source = node_typename + '-' + node_name
                        node_nodes = node.nodes
                        node_sink = ()

                        self.dataflows.append((now_locate, now_sort, node_source, flow_type, node_sink))

                    elif node_typename == 'Namespace':
                        node_name = self.get_node_name(node.name)
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
                    now_sort += 1
                elif node_typename in self.white_node:
                    continue

                else:
                    print(node)

            except KeyboardInterrupt:
                raise

            except:
                logger.warn("[PhpUnSerChain] Something error..\n{}".format(traceback.format_exc()))
                continue