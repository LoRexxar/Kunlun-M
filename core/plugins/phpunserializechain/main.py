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

from utils.log import logger, logger_console

from .dataflowgenerate import DataflowGenerate
from core.plugins.baseplugin import BasePluginClass


class PhpUnSerChain(BasePluginClass):
    """
    生成PHP反序列化链
    """
    def __init__(self, *args, **kwargs):
        super(PhpUnSerChain, self).__init__(*args)

        self.plugin_name = 'php_unserialize_chain_tools'

        self.parser_group_plugin.add_argument('-r', '--renew', dest='renew', action='store_true', default=False,
                                              help='renew DataFlow DB')

        # 参数列表
        self.required_arguments_list = ['target']
        self.arguments_list = ['target', 'debug', 'renew']

        # 检查参数
        self.check_args()

        # 赋值
        self.eval_args()

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
        self.dataflow_db = DataflowGenerate().main(self.target, self.renew)

        # core
        self.main()

    def main(self):

        self.get_destruct()

    def get_destruct(self):

        destruct_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__destruct')

        for node in destruct_nodes:

            unserchain = [node]
            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            # for mnode in method_nodes:
            #     print
            logger.info("[PhpUnSerChain] New Chain Start in __destruct in {}".format(node.node_locate))
            status = self.deep_search_chain(method_nodes, class_locate, unserchain)

            if status:
                logger.info("[PhpUnSerChain] New Source __destruct{} in {}".format(node.sink_node, node.node_locate))

                for unsernode in unserchain:
                    logger.info("{}".format(unsernode.node_locate.ljust(100,' ')))
                    logger_console.warn("{}   {}{}".format(unsernode.node_type.ljust(30,' '), unsernode.source_node,
                                                           self.deep_get_node_name(unsernode.sink_node)))
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
            newunserchain = [node]

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param, deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get___tostring(self, var_name, unserchain=[], define_param=(), deepth=0):
        """
        获取所有内置__toString方法
        :return:
        """
        deepth += 1
        define_param = (var_name, *define_param)
        get_nodes = self.dataflow_db.objects.filter(node_type='newMethod', source_node__startswith='Method-__toString')
        logger.debug("[PhpUnSerChain] trigger __tostring('{}'). try to found it.".format(var_name))

        for node in get_nodes:
            logger.debug("[PhpUnSerChain] Found New __tostring{} in {}".format(node.sink_node, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = [node]

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
            newunserchain = [node]

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
            newunserchain = [node]

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
            newunserchain = [node]

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
            logger.debug("[PhpUnSerChain] Found New {} in {}".format(method_node_name, node.node_locate))

            # 为了不影响数据，要先生成新的
            newunserchain = [node]

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)

            status = self.deep_search_chain(method_nodes, class_locate, newunserchain, define_param=define_param,
                                            deepth=deepth)

            if status:
                unserchain.extend(newunserchain)
                return True

        return False

    def get_any_class_methodcall(self, method_name, call_params, unserchain=[], define_param=(), deepth=0):
        """
        可以调用任意类的任意个方法，跟踪分析
        :param method_name:
        :param call_params:
        :param unserchain:
        :param define_param:
        :param deepth:
        :return:
        """
        deepth += 1
        define_param = (*call_params, *define_param)
        call_nodes = self.dataflow_db.objects.filter(node_type='newMethod')

        logger.debug("[PhpUnSerChain] trigger any class method. try to found all method in class with {}.".format(call_params))
        for node in call_nodes:

            # 为了不影响数据，要先生成新的
            newunserchain = [node]

            class_locate = node.node_locate

            new_locate = node.node_locate + '.' + node.source_node

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=new_locate)
            params_count = self.dataflow_db.objects.filter(node_locate__startswith=new_locate, node_type='newMethodparams')

            if params_count != len(define_param):
                continue

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
                                'call_user_func_array': [0, 1],
                                'eval': [0],
                                'system': [0],
                                'file_put_contents': [0, 1],
                                'create_function': [0, 1],
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

    def deep_get_node_name(self, node):
        """
        递归寻址获取最终node name
        :param node:
        :return:
        """
        if re.search(r'&[0-9]+', node, re.I):
            address_list = re.findall(r'&[0-9]+', node, re.I)
            for address in address_list:
                address_id = address[1:]

                chlid_node = self.dataflow_db.objects.filter(id=address_id).first()

                final_name = ""

                node_left = self.deep_get_node_name(chlid_node.source_node)
                node_right = self.deep_get_node_name(chlid_node.sink_node)

                if chlid_node.node_type.split('-')[0] in self.op_node:
                    node_type = chlid_node.node_type.split('-')[0]
                    node_op = chlid_node.node_type.split('-')[1]

                    if node_type in ['BinaryOp', 'AssignOp', 'TernaryOp']:
                        final_name = "{} {} {}".format(node_left, node_op, node_right)

                    elif node_type in ['PostIncDecOp', 'PreIncDecOp']:
                        final_name = "{} {}".format(node_left, node_op)

                    elif node_type == 'UnaryOp':
                        final_name = "{} {}".format(node_op, node_left)

                elif chlid_node.node_type in ['FunctionCall', 'MethodCall', 'NewClass']:
                    final_name = "{}-{}{}".format(chlid_node.node_type, node_left, node_right)

                elif chlid_node.node_type in ['ObjectProperty', 'StaticProperty', 'StaticMethodCall']:
                    final_name = node_left

                elif chlid_node.node_type in self.switch_node or chlid_node.node_type in self.import_node:
                    pass

                elif chlid_node.node_type in ['Assignment']:
                    final_name = "{} = {}".format(node_left, node_right)

                else:
                    print('---error-node---')
                    print(chlid_node)

                # replace
                node = node.replace(address, final_name)

            return node
        else:
            return node

    def deep_get_function_back(self, nodes):
        """
        用于获取某个函数的返回值
        :param return_node:
        :param nodes:
        :return:
        """
        return_node = False

        for node in nodes[::-1]:
            if node.source_node == 'return':
                return_node = self.deep_get_node_name(node.sink_node)
                now_node = node

                # if not return_node.startswith('Variable-'):
                #     return_node = False
                #     continue

        if return_node:

            if self.check_param_controllable(return_node, now_node):
                return True

            else:
                return return_node


            # now_node = nodes.pop()
            # now_source_node = self.deep_get_node_name(now_node.source_node)
            # now_sink_node = self.deep_get_node_name(now_node.sink_node)
            #
            # if now_node.node_type == 'Assignment' and now_source_node == return_node:
            #     return self.deep_get_function_back(nodes, now_sink_node)
            #
            #
            # return return_node
        else:
            return False

    def check_param_controllable(self, param_name, now_node):
        """
        用于检查当前参数是否可控
        :param param_name: 参数 格式一般为Variable-$a
        :param now_node: 参数所在的node
        :return:
        """
        parent_node_list = [param_name]

        if '->' in param_name:
            parent_node = self.deep_get_node_name(param_name.split('->')[0])
            child_node = self.deep_get_node_name(param_name.split('->')[1])

            param_name = "{}->{}".format(parent_node, child_node)
            parent_node_list.append(parent_node)

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

        if 'Method-' in now_locate:
            base_locate = "{}.{}.{}".format(now_locate.split('.')[0], now_locate.split('.')[1],
                                            now_locate.split('.')[2])
        else:
            base_locate = "{}.{}".format(now_locate.split('.')[0], now_locate.split('.')[1])

        # check 赋值语句
        back_nodes = self.dataflow_db.objects.filter(id__lt=now_id, node_locate__startswith=base_locate, node_type='Assignment').order_by('-id')

        for back_node in back_nodes:
            if back_node.source_node in parent_node_list:
                # 找到参数赋值
                new_param_name = self.deep_get_node_name(back_node.sink_node)

                # 递归继续
                return self.check_param_controllable(new_param_name, back_node)

        # foreach 语句，没有找到很好的办法...
        back_nodes = self.dataflow_db.objects.filter(id__lt=now_id, node_locate__startswith=base_locate,
                                                     node_type='Foreach').order_by('-id')

        for back_node in back_nodes:
            if param_name == eval(back_node.sink_node)[-1]:
                # 找到参数赋值
                new_param_name = self.deep_get_node_name(eval(back_node.sink_node)[0])

                # 递归继续
                return self.check_param_controllable(new_param_name, back_node)

        # check 当param_name为方法调用
        if param_name.split('-')[0] in ['MethodCall', 'StaticMethodCall']:
            method_name = param_name.split('-')[1].split('(')[0]
            base_locate = "{}.{}".format(now_locate.split('.')[0], now_locate.split('.')[1])

            method_nodes = self.dataflow_db.objects.filter(node_locate__startswith=base_locate, node_type='newMethod',
                                                           source_node=method_name)
            if method_nodes:
                return self.deep_get_function_back(method_nodes)

        # check 在参数里
        if param_name.startswith('Variable-'):
            base_locate = "{}.{}.{}".format(now_locate.split('.')[0], now_locate.split('.')[1], now_locate.split('.')[2])

            back_nodes = self.dataflow_db.objects.filter(id__lt=now_id, node_locate__startswith=base_locate,
                                                         node_type='newMethodparams').order_by('-id')

            for back_node in back_nodes:
                if 'Variable-{}'.format(back_node.source_node) == param_name:
                    return True

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

    def deep_search_chain(self, nodes, class_locate, unserchain=[], define_param=(), deepth=0, parent_method=False):
        """
        递归深入反序列化链
        :param deepth: 递归深度
        :param define_param: 确定的参数列表
        :param class_locate: 当前class的locate
        :param nodes:   当前class下的nods
        :param unserchain:  全局变量反序列化链
        :param parent_method:  父方法
        :return:
        """

        if deepth > 10:
            logger.warn("[PhpUnSerChain] Too much deepth. return.")
            return False

        deepth += 1

        for node in nodes:
            node_locate = node.node_locate
            node_sort = node.node_sort
            source_node = self.deep_get_node_name(node.source_node)
            node_type = node.node_type.split('-')[0]
            sink_node = self.deep_get_node_name(node.sink_node)

            if self.check_danger_sink(node):
                unserchain.append(node)
                return True

            if node_type == 'MethodCall' and self.check_param_controllable(source_node, node):

                new_method_name = source_node[16:]
                new_source_node = 'Method-' + new_method_name

                # 如果call的方法和父方法相同，则跳出
                if new_source_node == parent_method:
                    continue

                # 跟入method
                unserchain.append(node)
                logger.debug('[PhpUnSerChain] call new method {}{}'.format(source_node, sink_node))

                # 如果出现$this->a->b 那么可以触发制定的__call和任意类的b方法
                if self.check_dynamic_class_var_exist(source_node, node):
                    # 有两条途径，1是可以调用其他类的b方法，2是可以调用任意类的_call
                    method_name = source_node.split('->')[-1]
                    call_params = self.deep_get_node_name(sink_node)

                    # 检查 $this->a->$b这种特殊情况
                    if method_name.startswith('Variable-$'):

                        if self.check_param_controllable(method_name, node):
                            logger.debug('[PhpUnSerChain] Found Dynamic call in {}'.format(source_node))
                            status = self.get_any_class_methodcall(method_name, call_params, unserchain=unserchain,
                                                                   define_param=define_param, deepth=deepth)
                            if status:
                                return True
                            else:
                                unserchain.pop()
                                continue
                        else:
                            # 这里 $b不为方法参数的情况太复杂了，所以这里直接跳出，忽略
                            logger.warn('[PhpUnSerChain] Dynamic call in {} un control. continue.'.format(source_node))
                            unserchain.pop()
                            continue

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
                        status = self.deep_search_chain(nmnodes, class_locate, unserchain, define_param=define_param, deepth=deepth, parent_method=new_source_node)

                        if status:
                            return True

                        else:
                            unserchain.pop()
                    else:
                        unserchain.pop()
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

                    # 去找当前class节点，寻找继承类/子类
                    now_class = class_locate.split('.')[-1]
                    find_method_name = new_source_node

                    status = self.find_prototype_class(now_class, find_method_name, unserchain, define_param=define_param, deepth=deepth)

                    if status:
                        return True

                    continue

            elif node_type == 'StaticMethodCall':
                # 一般来说，涉及到staticmethodcall 都是外部调用，不适用于大部分反序列化调用链追溯的情况，暂不考虑优化
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

            elif node_type in ['FunctionCall', 'newMethodparams', 'MethodCall', 'NewClass']:
                pass

            elif node_type in self.op_node:
                pass

            elif node_type in ['ObjectProperty']:
                # 表示内部变量调用，如$this->d
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
                                status = self.deep_search_chain(new_class_method_nodes, new_class_locate, new_unserchain, define_param=define_param, deepth=deepth)

                                if status:
                                    unserchain.extend(new_unserchain)
                                    return True
                        else:
                            logger.debug('[PhpUnSerChain] Found Method {} Failed in Prototype Class {}.'.format(find_method_name, now_class_extend_class))

                            continue

        # 如果向原型类寻找没有结果，那么尝试向子类寻找
        now_class_name = now_class.split('-')[1]

        nc2s = self.dataflow_db.objects.filter(node_type='newClass', sink_node__contains=now_class_name)

        for nc2 in nc2s:
            now_class_extend_classs = eval(nc2.sink_node)
            if len(now_class_extend_classs) > 0 and now_class_name in now_class_extend_classs:
                child_class = self.deep_get_node_name(nc2.source_node)
                new_child_class_name = child_class

                # 找到子类寻找对应方法
                logger.debug('[PhpUnSerChain] Found Child Class {} in {}. '.format(child_class, nc2.node_locate))

                # 向下寻找方法
                new_class_locate = nc2.node_locate + '.' + new_child_class_name

                # 先检查新的class中是否存在该method
                new_class_method = self.dataflow_db.objects.filter(node_locate=new_class_locate,
                                                                   source_node=find_method_name,
                                                                   node_type='newMethod').first()

                if new_class_method:
                    # 子类中存在这个方法，递归分析
                    new_unserchain = [nc]

                    new_class_method_locate = new_class_locate + '.' + find_method_name

                    new_class_method_nodes = self.dataflow_db.objects.filter(
                        node_locate__startswith=new_class_method_locate,
                        node_sort__gte=1)

                    if new_class_method_nodes:
                        # 递归进去子方法
                        status = self.deep_search_chain(new_class_method_nodes, new_class_locate, new_unserchain,
                                                        define_param=define_param, deepth=deepth)

                        if status:
                            unserchain.extend(new_unserchain)
                            return True
                else:
                    logger.debug(
                        '[PhpUnSerChain] Found Method {} Failed in Child Class {}.'.format(find_method_name,
                                                                                               child_class))

                    continue

        return False
