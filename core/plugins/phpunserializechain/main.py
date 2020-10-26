#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: main.py
@time: 2020/10/14 15:16
@desc:

'''


import re
import traceback

from core.plugins.baseplugin import BasePluginClass

from core.pretreatment import ast_object

from utils.file import Directory
from utils.utils import ParseArgs
from utils.log import logger

from web.index.models import get_dataflow_class

from Kunlun_M.const import ext_dict

from phply import phpast as php


class PhpUnSerChain(BasePluginClass):
    """
    生成PHP反序列化链
    """
    def __init__(self, *args, **kwargs):
        super(PhpUnSerChain, self).__init__(*args)

        self.plugin_name = 'php_unserialize_chain_tools'

        # 参数列表
        self.required_arguments_list = ['target']
        self.arguments_list = ['target', 'debug']

        # 检查参数
        self.check_args()

        # 赋值
        self.eval_args()

        # 常量类型定义
        self.Object_define = ['Class', 'Function', 'Method']
        self.method_call = ['FunctionCall', 'MethodCall', 'StaticMethodCall', 'ObjectProperty']
        self.special_function = ['Eval', 'Echo', 'Print', 'Return', 'Break', 'Include',
                                 'Require', 'Exit', 'Throw', 'Unset', 'Continue', 'Yield']
        self.switch_node = ['If', 'ElseIf', 'Else', 'Try', 'While', 'DoWhile', 'For', 'Foreach', 'Switch', 'Case', 'Default']
        self.import_node = ['UseDeclarations', 'UseDeclaration', 'ClassVariables', 'ClassVariable', 'Static',
                            'StaticVariable', 'AssignOp', 'PreIncDecOp', 'PostIncDecOp',
                            'ClassConstants', 'ClassConstant', 'ConstantDeclarations', 'ConstantDeclaration']
        self.white_node = ['InlineHTML', 'Declare']
        self.define_node = ['Interface', 'Namespace']
        self.check_node = ['IsSet', 'Empty']

        # 临时全局变量
        self.dataflows = []

        # core
        self.main()

    def main(self):

        self.load_dataflow()

        self.get_destruct()

    def get_destruct(self):

        destruct_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__destruct')

        for node in destruct_nodes:

            unserchain = [node]
            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            # for mnode in method_nodes:
            #     print(mnode.source_node, mnode.node_type, mnode.sink_node)
            status = self.deep_search_chain(method_nodes, class_locate, unserchain)

            if status:
                logger.info("[PhpUnSerChain] New Source __destruct{} in {}".format(node.sink_node, node.node_locate))

                for unsernode in unserchain:
                    logger.info("[PhpUnSerChain] {} {} {} in {}".format(unsernode.source_node, unsernode.node_type,
                                                                        unsernode.sink_node, unsernode.node_locate))

                logger.info("[PhpUnSerChain] UnSerChain is available.")

    def get___get(self, var_name, unserchain=[], define_param=(), deepth=0):
        """
        获取所有内置__get方法
        :return:
        """
        deepth += 1
        define_param = (var_name, *define_param)
        get_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__get')
        logger.debug("[PhpUnSerChain] trigger __get('{}'). try to found it.".format(var_name))

        for node in get_nodes:
            logger.debug("[PhpUnSerChain] Found New __get{} in {}".format(node.sink_node, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = []

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param, deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get___set(self, var_name, var_value, unserchain=[], define_param=(), deepth=0):
        """
        获取所有内置__set方法
        :return:
        """
        deepth += 1
        define_param = (var_name, var_value, *define_param)
        set_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__set')
        logger.debug("[PhpUnSerChain] trigger __set('{}', '{}'). try to found it.".format(var_name, var_value))

        for node in set_nodes:
            logger.debug("[PhpUnSerChain] Found New __set{} in {}".format(node.sink_node, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = []

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param, deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get___call(self, var_name, call_params, unserchain=[], define_param=(), deepth=0):
        """
        获取所有内置__call方法
        :return:
        """
        deepth += 1
        define_param = (var_name, call_params, *define_param)
        call_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__call')
        logger.debug("[PhpUnSerChain] trigger __call('{}', '{}'). try to found it.".format(var_name, call_params))

        for node in call_nodes:
            logger.debug("[PhpUnSerChain] Found New __call{} in {}".format(node.sink_node, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = []

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param, deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get___callStatic(self, var_name, call_params, unserchain=[], define_param=(), deepth=0):
        """
        获取所有内置__callStatic方法
        :return:
        """
        deepth += 1
        define_param = (var_name, call_params, *define_param)
        call_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__callStatic')
        logger.debug("[PhpUnSerChain] trigger __callStatic('{}', '{}'). try to found it.".format(var_name, call_params))

        for node in call_nodes:
            logger.debug("[PhpUnSerChain] Found New __callStatic{} in {}".format(node.sink_node, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = []

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param, deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get_any_methodcall(self, method_name, call_params, unserchain=[], define_param=(), deepth=0):
        """
        可以调用任意类的某个方法，跟踪分析
        :param method_name:
        :param call_params:
        :param unserchain:
        :param define_param:
        :param deepth:
        :return:
        """
        deepth += 1
        define_param = (*call_params, *define_param)
        method_node_name = 'Method-{}'.format(method_name)
        call_nodes = self.dataflow_db.objects.filter(node_type='newMethod',
                                                     source_node__startswith=method_node_name)

        logger.debug("[PhpUnSerChain] trigger {}{}. try to found it.".format(method_node_name, call_params))

        for node in call_nodes:
            logger.debug("[PhpUnSerChain] Found New () in {}".format(method_node_name, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = []

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param,
                                            deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get_params_from_sink_node(self, node_name):

        result = []

        if node_name.startswith('Variable-'):
            result = [node_name]

        elif node_name.startswith('Array-'):
            result = eval(node_name[5:])

        elif node_name[0] == '(' and node_name[0] == ')':
            result = list(eval(result))

        return result

    def follow_call_from_sink_node(self, node_name, unserchain=[], define_param=(), deepth=0):
        """
        从sink_node中解析对象，主要为methodcall和
        触发__call、__get
        :param node_name:
        :return:
        """
        methodcall_matchObj = re.search(r'MethodCall-(\w+)\(([^)]*)\)', node_name, re.M | re.I)

        if methodcall_matchObj:
            method_name = methodcall_matchObj.group(1)
            function_params = self.get_params_from_sink_node(methodcall_matchObj.group(2))

            # 先触发寻找当前函数，再触发_call
            status = self.get_any_methodcall(method_name, function_params, unserchain=unserchain, define_param=define_param,
                                             deepth=deepth)

            if status:
                return True

            # 可以触发_call
            new_target_method = 'Method-__call'
            status = self.get___call(method_name, function_params, unserchain=unserchain, define_param=define_param,
                                     deepth=deepth)

            if status:
                return True

        # check get
        get__matchObj = re.search(r'->Variable-\$(\w+)', node_name, re.M | re.I)

        if get__matchObj:
            param_name = get__matchObj.group(1)

            if self.get___get(param_name, unserchain=unserchain, define_param=define_param, deepth=deepth):
                return True

        return False

    def check_danger_sink(self, node):
        """
        检查当前节点是否调用了危险函数并可控
        :param node:
        :return:
        """
        self.danger_function = {'call_user_func': [0],
                                'call_user_func_array': [0,1],
                                'eval': [0],
                                'system': [0],
                                'file_put_contents': [0,1],
                                'create_function': [0,1],
                                }

        self.indirect_danger_function = {
                                'array_map': [0],
                                'call_user_func_array': [0],
                                }

        if node.node_type == 'FunctionCall' and node.source_node in self.danger_function:
            sink_node = eval(node.sink_node)

            if len(sink_node) >= len(self.danger_function[node.source_node]):
                # 必须有更多参数
                for i in self.danger_function[node.source_node]:
                    if self.check_param_controllable(sink_node[i], node):
                        continue
                    return False

                return True

        # 剩下的都直接对sink_node做处理
        else:
            sink_node = node.sink_node
            matchObj = re.search(r'FunctionCall-(\w+)\(([^)]*)\)', sink_node, re.M | re.I)

            if matchObj:
                function_name = matchObj.group(1)
                function_params = self.get_params_from_sink_node(matchObj.group(2))

                if function_name in self.danger_function:

                    # check
                    if len(function_params) >= len(self.danger_function[function_name]):
                        # 必须有更多参数
                        for i in self.danger_function[function_name]:
                            if self.check_param_controllable(function_params[i], node):
                                continue
                            return False

                        return True

        return False

    def check_param_controllable(self, param_name, now_node):
        """
        用于检查当前参数是否可控
        :param param_name: 参数 格式一般为Variable-$a
        :param now_node: 参数所在的node
        :return:
        """

        if 'Variable-$this' in param_name:
            if param_name.startswith('Variable-$this->'):
                # 暂时简单的认为这样可控
                return True
            elif param_name.startswith('Array-'):
                arraylist = eval(param_name[6:])

                for key in arraylist:
                    if key.startswith('Variable-$this'):
                        return True

                return False

        # 回溯变量
        now_id = now_node.id
        now_locate = now_node.node_locate

        base_locate = "{}.{}".format(now_locate.split('.')[0], now_locate.split('.')[1])
        back_nodes = self.dataflow_db.objects.filter(id__lt=now_id, node_locate__startswith=base_locate).order_by('-id')

        for back_node in back_nodes:
            if back_node.node_type == 'Assignment' and back_node.source_node == param_name:
                # 找到参数赋值
                new_param_name = back_node.sink_node

                # 递归继续
                return self.check_param_controllable(new_param_name, back_node)

            elif back_node.node_type == 'Foreach':
                foreach_params = eval(back_node.sink_node)
                if param_name in foreach_params:
                    # 找到参数赋值
                    new_param_name = foreach_params[0]

                    # 递归继续
                    return self.check_param_controllable(new_param_name, back_node)

        return False

    def check_dynamic_class_var_exist(self, var_name, now_node):
        """
        检查该变量是否为类中动态变量，如$this->a->b
        :param now_node:
        :param var_name:
        :return:
        """
        # 检查是否为函数调用
        if var_name.startswith('FunctionCall-') or var_name.startswith('MethodCall-'):
            var_name_list = re.split("[()]", var_name)
            var_name = ",".join(var_name_list)

        for var_node in var_name.split(','):

            if '->' in var_node:
                var_node_parts = var_node.split('->')

                var_node_left = '->'.join(var_node_parts[:-1])
                var_node_right = var_node_parts[-1]

                return self.check_param_controllable(var_node_left, now_node)

        return False

    def deep_search_chain(self, nodes, class_locate, unserchain=[], define_param=(), deepth=0):
        """
        递归深入反序列化链
        :param deep: 递归深度
        :param define_param: 确定的参数列表
        :param class_locate: 当前class的locate
        :param nodes:   当前class下的nods
        :param unserchain:  全局变量反序列化链
        :return:
        """

        if deepth > 20:
            logger.error("[PhpUnSerChain] Too much deepth. return.")
            return False

        deepth += 1

        for node in nodes:
            node_locate = node.node_locate
            node_sort = node.node_sort
            source_node = node.source_node
            node_type = node.node_type
            sink_node = node.sink_node

            if self.check_danger_sink(node):
                unserchain.append(node)
                return True

            if node_type == 'MethodCall' and self.check_param_controllable(source_node, node):

                new_method_name = source_node[16:]
                new_source_node = 'Method-' + new_method_name

                # 跟入method
                unserchain.append(node)
                logger.debug('[PhpUnSerChain] call new method {}{}'.format(source_node, sink_node))

                # 如果出现$this->a->b 那么可以触发制定的__call和任意类的b方法
                if self.check_dynamic_class_var_exist(source_node, node):
                    # 有两条途径，1是可以调用其他类的b方法，2是可以调用任意类的_call
                    method_name = source_node.split('->')[-1]
                    call_params = sink_node

                    status = self.get_any_methodcall(method_name, call_params, unserchain=unserchain, define_param=define_param, deepth=deepth)

                    if status:
                        return True

                    # 可以触发_call
                    new_target_method = 'Method-__call'
                    status = self.get___call(method_name, call_params, unserchain=unserchain, define_param=define_param, deepth=deepth)

                    if status:
                        return True

                nm = self.dataflow_db.objects.filter(node_locate=class_locate, source_node=new_source_node, node_type='newMethod').first()

                if nm:
                    new_method_locate = class_locate + '.' + new_source_node

                    nmnodes = self.dataflow_db.objects.filter(node_locate__startswith=new_method_locate, node_sort__gte=1)

                    if nmnodes:
                        # 递归进去子方法
                        status = self.deep_search_chain(nmnodes, class_locate, unserchain, define_param=define_param, deepth=deepth)

                        if status:
                            return True

                    else:
                        return False
                else:
                    logger.debug('[PhpUnSerChain] Found Method {} Failed in {}'.format(new_source_node, class_locate))

                    # 先寻找当前类__call
                    call_source_node = 'Method-__call'
                    nm = self.dataflow_db.objects.filter(node_locate=class_locate, source_node=call_source_node,
                                                         node_type='newMethod').first()

                    if nm:
                        new_method_locate = class_locate + '.' + call_source_node
                        new_unserchain = [node]

                        nmnodes = self.dataflow_db.objects.filter(node_locate__startswith=new_method_locate,
                                                                  node_sort__gte=1)

                        if nmnodes:
                            # 递归进去子方法
                            status = self.deep_search_chain(nmnodes, class_locate, unserchain,
                                                            define_param=define_param, deepth=deepth)

                            if status:
                                unserchain.extend(new_unserchain)
                                return True

                    # 去找当前class节点，寻找继承类
                    now_class = class_locate.split('.')[-1]
                    find_method_name = new_source_node

                    self.find_prototype_class(now_class, find_method_name, unserchain, define_param=define_param, deepth=deepth)

                    continue

            elif node_type == 'StaticMethodCall':
                pass

            elif node_type in self.switch_node:
                # switchnode 主要检查sink_node
                # 这里最容易出的是 $this->a->b 这个可以触发很多
                if self.check_dynamic_class_var_exist(sink_node, node):
                    # 对sink_node做字符串检查
                    # 至少需要判断可以执行__get __call
                    if self.follow_call_from_sink_node(sink_node, unserchain=unserchain, define_param=define_param,
                                                       deepth=deepth):
                        return True

            elif node_type == 'Assignment':
                node_left = source_node
                node_right = sink_node

                if self.check_dynamic_class_var_exist(node_left, node):
                    # 可以触发_set
                    new_target_method = 'Method-__set'
                    method_name = node_left.split('->')[-1]
                    new_target_method_value = node_right

                    if self.get___set(method_name, new_target_method_value, unserchain=unserchain, define_param=define_param, deepth=deepth):
                        return True

                if self.check_dynamic_class_var_exist(node_right, node):
                    # 可以触发__get，__call
                    new_target_method = 'Method-__get'
                    method_name = node_right.split('->')[-1]

                    if self.follow_call_from_sink_node(node_right, unserchain=unserchain, define_param=define_param, deepth=deepth):
                        return True

            elif node_type in ['FunctionCall', 'newMethodparams', 'MethodCall']:
                pass

            else:
                print(source_node, node_type, sink_node)

        return False

    def find_prototype_class(self, now_class, find_method_name, unserchain, define_param=(), deepth=0):
        """
        寻找原型类并继续递归
        :param find_method_name:    要寻找的method名
        :param now_class:   当前类名
        :param unserchain:  全局反序列化链变量
        :return:
        """

        nc = self.dataflow_db.objects.filter(source_node=now_class, node_type='newClass').first()
        deepth += 1

        if nc:
            now_class_extend_classs = eval(nc.sink_node)
            if len(now_class_extend_classs) > 0:
                # len > 0代表当前类存在原型类，所以向上寻找类的方法

                now_class_extend_class = now_class_extend_classs[0]

                new_class_name = 'Class-' + now_class_extend_class

                ncs = self.dataflow_db.objects.filter(source_node=new_class_name, node_type='newClass')

                for nc in ncs:
                    if nc:
                        # 跟到新的class中寻找method
                        logger.debug('[PhpUnSerChain] Found Prototype Class {} in {}. '.format(now_class_extend_class, nc.node_locate))

                        # 寻找对应新class中的method
                        new_class_locate = nc.node_locate + '.' + new_class_name

                        # 先检查新的class中是否存在该method
                        new_class_method = self.dataflow_db.objects.filter(node_locate=new_class_locate, source_node=find_method_name, node_type='newMethod').first()

                        if new_class_method:
                            # 原型类存在该方法，储存
                            new_unserchain = [nc]

                            new_class_method_locate = new_class_locate + '.' + find_method_name

                            new_class_method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_class_method_locate,
                                                                                     node_sort__gte=1)

                            if new_class_method_nodes:
                                # 递归进去子方法
                                status = self.deep_search_chain(new_class_method_nodes, new_class_locate, unserchain, define_param=define_param, deepth=deepth)

                                if status:
                                    unserchain.extend(new_unserchain)
                                    return True
                        else:
                            logger.debug('[PhpUnSerChain] Found Method {} Failed in Prototype Class {}.'.format(find_method_name, now_class_extend_class))

                            continue

        return False

    # 下面为生成code db函数
    def load_dataflow(self):
        target = self.target

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
                        df = self.dataflow_db(node_locate=dataflow[0], node_sort=dataflow[1], source_node=dataflow[2], node_type=dataflow[3], sink_node=dataflow[4])
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

        elif isinstance(node, php.FunctionCall) or isinstance(node, php.MethodCall) or isinstance(node, php.StaticMethodCall):
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
            return 'Constant-{}@{}'.format(self.get_node_name(node.name),self.get_node_name(node.value))

        elif isinstance(node, php.PostIncDecOp) or isinstance(node, php.PreIncDecOp):
            return str(self.get_node_name(node.op))

        elif isinstance(node, php.FunctionCall):
            return 'FunctionCall-{}{}'.format(self.get_node_name(node.name), self.get_node_name(self.get_node_params(node)))

        elif isinstance(node, php.MethodCall) or isinstance(node, php.StaticProperty):
            return '{}->MethodCall-{}{}'.format(self.get_node_name(node.node), self.get_node_name(node.name), self.get_node_name(self.get_node_params(node)))

        elif isinstance(node, php.StaticMethodCall):
            return '{}::StaticMethodCall-{}{}'.format(self.get_node_name(node.class_), self.get_node_name(node.name), self.get_node_name(self.get_node_params(node)))

        elif isinstance(node, php.BinaryOp):
            return '{}{}{}'.format(self.get_node_name(node.left), node.op, self.get_node_name(node.right))

        elif isinstance(node, php.TernaryOp):
            return '{}?{}:{}'.format(self.get_node_name(node.expr), self.get_node_name(node.iftrue), self.get_node_name(node.iffalse))

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

                            self.dataflows.append((new_locate, 0, param_name, 'new'+node_typename+'params', self.get_node_name(param.default)))

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

                            self.dataflows.append((new_locate, 0, node_for_start_source, node_for_start_flow_type, node_for_start_sink))

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
                                    node_for_count_sink = '{} {} {}'.format(self.get_node_name(node_for_count.left), self.get_node_name(node_for_count.op),
                                                                            self.get_node_name(node_for_count.right))

                                elif node_for_count_type in ['Assignment']:
                                    node_for_count_source = self.get_node_name(node_for_count.node)
                                    node_for_count_sink = self.get_node_name(node_for_count.expr)

                                else:
                                    node_for_count_source = self.get_node_name(node_for_count)
                                    node_for_count_sink = self.get_node_name(node_for_count)

                                node_for_count_flow_type += '-{}'.format(node_for_count_type)

                                self.dataflows.append(
                                    (new_locate, 0, node_for_count_source, node_for_count_flow_type, node_for_count_sink))

                        self.base_dataflow_generate(node_nodes, new_locate)
                        continue

                    elif isinstance(node, php.Foreach):
                        node_sink = (self.get_node_name(node.expr), self.get_node_name(node.keyvar), self.get_node_name(node.valvar))
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
                        node_sink = '{} {} {}'.format(self.get_node_name(node.left), self.get_node_name(node.op), self.get_node_name(node.right))

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