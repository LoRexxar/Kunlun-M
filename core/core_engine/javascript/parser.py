#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/7/5 17:37
# @Author  : LoRexxar
# @File    : parser.py
# @Contact : lorexxar@gmail.com


import os
import traceback

from esprima import nodes as jsnodes
from esprima.parser import SourceLocation, Position

from utils.log import logger
from core.pretreatment import ast_object

from core.internal_defines.javascript.functions import function_dict, string_function

default_controlled_params = [
    'location.hash',
    'document.cookie',
    'location.search',
    'location.href',
    'window.name',

    # for chrome ext
    'chrome.tabs.query',
    'chrome.tabs.get',
    'chrome.tabs.getCurrent',
    'chrome.tabs.getSelected',
    'chrome.tabs.getAllInWindow',
    'chrome.runtime.onMessage.addListener',
    'chrome.runtime.onConnect.addListener',
    'chrome.runtime.onMessageExternal.addListener',
    'chrome.runtime.onConnectExternal.addListener',

    # for chrome
    'chrome.cookies.get',
    'chrome.cookies.getAll',

    # new api
    '.addEventListener',
    # 'location',
]

special_eval_function = [
    "eval",
    "setTimeout",
]

scan_results = []  # 结果存放列表初始化
is_repair_functions = []  # 修复函数初始化
is_controlled_params = []
scan_chain = []  # 回溯链变量


def get_member_data(node, check=False, isparam=False, isclean_prototype=False, isreverse=False):
    if hasattr(node, "type"):
        type = node.type
        value = node

        if type == "Identifier":
            value = node.name
            # if check:
            #     value = 1

        if type == "Literal":  # 数组位移
            value = node.value
            if check:
                value = "1"

            if isreverse:
                value = node.value[::-1]

        elif type == "MemberExpression":
            data_object = get_member_data(node.object, isclean_prototype=isclean_prototype)
            data_property = get_member_data(node.property, isclean_prototype=isclean_prototype)

            if isparam:
                value = data_object
            else:
                value = "{}.{}".format(data_object, data_property)

            if isclean_prototype:
                if data_property == "prototype":
                    value = ""

        elif type == "AssignmentExpression":
            data_left = get_member_data(node.left, isclean_prototype=isclean_prototype)
            data_right = get_member_data(node.right, isclean_prototype=isclean_prototype)

            if isparam:
                value = data_left
            else:
                value = str(data_left) + "." + str(data_right)

        elif type == "CallExpression":
            value = get_member_data(node.callee, isclean_prototype=isclean_prototype)

        elif type == "ThisExpression":
            value = "this"

        elif type == "ObjectExpression":
            value = " { "
            for i in node.properties:
                value += get_member_data(i.key, isclean_prototype=isclean_prototype)
                value += ", "

            value += " } "

        elif type == "BinaryExpression":
            value = ""

            if node.operator == "+":
                data_left = get_member_data(node.left, check=True, isclean_prototype=isclean_prototype)
                data_right = get_member_data(node.right, check=True, isclean_prototype=isclean_prototype)

                if data_left != "1":
                    value = data_left
                if data_right != "1" and value:
                    value = str(value) + " + " + str(data_right)
                if data_right != "1" and not value:
                    value = data_right

        elif type == "NewExpression":
            callee_name = get_member_data(node.callee)

            value = "New {}".format(callee_name)

            if isparam:
                value = callee_name

        elif type == "FunctionExpression":
            function_name = get_member_data(node.id) if node.id else "tmpfunc"

            value = "{}()".format(function_name)

    elif isinstance(node, list):
        valuelist = []

        for i in node:
            valuelist.append(get_member_data(i, isclean_prototype=isclean_prototype))

        value = valuelist
    else:
        value = node

    return value


def get_param(param, is_eval=False, is_function_regex=False):
    param_list = []
    type = param.type

    if type == "Identifier":
        param_list.append(param.name)

    elif type == "Literal":
        if is_eval:
            param_list.append(param.value)

    elif type == "BinaryExpression":
        left = get_param(param.left, is_eval)
        right = get_param(param.right, is_eval)

        param_list.extend(left)
        param_list.extend(right)

    elif type == "CallExpression":
        call_function = get_member_data(param.callee, isparam=True)

        if is_function_regex:
            params = [param.callee]

        else:
            if call_function in special_eval_function:
                params = get_param_list(param.arguments, is_eval=True)
            else:
                params = get_param_list(param.arguments, is_eval)

        param_list.extend(params)

    elif type == "MemberExpression":
        data_object = get_member_data(param.object)
        data_property = get_member_data(param.property)

        value = str(data_object) + "." + str(data_property)
        param_list.append(value)

    return param_list


def get_param_list(params, is_eval=False, is_function_regex=False):
    param_list = []

    for param in params:
        param_list.extend(get_param(param, is_eval, is_function_regex))

    return param_list


def get_original_object(node):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            return get_original_object(node.object)

        return node
    return get_member_data(node)


def get_property_object(node):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            return get_property_object(node.property)

    return get_member_data(node)


def set_original_object(node, object_name):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            node.object = object_name
            return node

    node = object_name
    return node


def set_property_object(node, object_name):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            node.property = object_name
            return node

        if node.type == "AssignmentExpression":
            node.right = object_name
            return node

    node = object_name
    return node


def generate_memberexp(object, property, vul_lineno=0):
    if hasattr(object, "type"):
        new_member_object = object
    else:
        new_member_object = jsnodes.Identifier(object)
        new_member_object.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    if hasattr(property, "type"):
        new_member_property = property
    else:
        new_member_property = jsnodes.Identifier(property)
        new_member_property.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    new_param = jsnodes.ComputedMemberExpression(new_member_object, new_member_property)
    new_param.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    return new_param


def is_memberexp(node):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            return True


def is_thisexp(node):
    if hasattr(node.object, "type"):
        # member的this
        if node.object.type == "ThisExpression":
            return True


def is_vul_function(node, vul_function):
    """
    判断该调用是否为目标漏洞函数
    :param node: 
    :param vul_function: 
    :return: 
    """
    node_type = node.type

    if node_type == "MemberExpression":
        return get_member_data(node) == vul_function

    if node_type == "CallExpression":
        return get_member_data(node) == vul_function


def is_eval_function(node):
    eval_functions = ['eval', 'setTimeout']

    if hasattr(node, "type") and node.type == "CallExpression":
        return get_member_data(node) in eval_functions

    return False


def is_controllable(param):
    """
    判断参数是否为可控
    
    -1 为不可控
    1 为可控
    2 为已修复
    3 为未知，即仍未变量
    4 为新函数规则生成
    
    :param param: 
    :return: 
    """
    global is_controlled_params

    is_co = 3
    real_param = get_member_data(param, True)

    # 首先需要合并下
    controlled_params = is_controlled_params + default_controlled_params

    # 检查常量
    if real_param == 1:
        is_co = -1
        real_param = param

    for controlled_param in controlled_params:
        if controlled_param in str(real_param):
            is_co = 1

    return is_co, param


def check_param(param, vul_lineno=0):
    """
    检查自定义匹配的变量类型，想办法生成相应的结构
    :param vul_lineno: 
    :param param: 
    :return: 
    """
    new_param = param

    if "." in param:
        # Member in param
        logger.debug("New MemberExpression from {}".format(param))
        params = param.split('.')
        param_object = params[0]
        param_property = ".".join(params[1:])

        new_param_object = jsnodes.Identifier(param_object)
        new_param_object.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

        new_param_property = check_param(param_property)

        new_param = jsnodes.ComputedMemberExpression(new_param_object, new_param_property)
        new_param.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    elif not hasattr(param, "type"):
        new_param = jsnodes.Identifier(param)
        new_param.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    return new_param


def function_back(function_node, function_params, back_nodes=None, file_path=None, isback=False, vul_function=None, method_name=None,
                  iscall=False):
    """
    用于回溯参数为函数变量的时候
    :param function_params:
    :param back_nodes:
    :param iscall:
    :param method_name: 
    :param vul_function: 
    :param function_node: 
    :param file_path: 
    :param isback: 
    :return: 
    """
    function_body = function_node.body.body
    function_name = get_member_data(function_node.id) if get_member_data(function_node.id) else "tmpfunc"
    function_lineno = function_node.loc.start.line
    function_params = function_params if function_params else function_node.params

    is_co = 3
    cp = "Function()"
    expr_lineno = 0

    logger.debug("[AST] Sounds like found a new function define {}".format(function_name))

    param = vul_function
    nodes = function_body

    for node in function_body[::-1]:

        if hasattr(node, "type") and node.type == "ReturnStatement":
            param = node.argument

            # 当返回包含this时，继续分析已经没有意义了
            if get_member_data(get_original_object(param)) == "this":
                logger.debug("[AST] Function return self.method {}, back to ast object.".format(get_member_data(param)))

                is_co = 3
                cp = param
                expr_lineno = node.loc.start.line
                return is_co, cp, expr_lineno

            break

    is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                             vul_function=vul_function, method_name=method_name)

    if is_co == 3:
        # 一个特殊情况
        # 如果函数中有函数调用，但是函数定义不一定在函数里，那么就没办法分析了，
        # 这里引入back_nodes来处理call函数

        if hasattr(cp, "type") and cp.type == "CallExpression":
            is_co, cp, expr_lineno = parameters_back(cp, back_nodes, function_params, file_path=file_path, isback=isback,
                                                     vul_function=vul_function, method_name=method_name)

        if is_co == 3:
            # 进params获取判断参数是否和目标参数一致
            for p in function_params:
                if p == cp or get_member_data(p) == get_member_data(get_original_object(cp)):
                    if iscall:
                        # 来自于call的function分析需要进一步分析
                        is_co = 4

                        logger.debug("[AST] back to function call ast analysis...")
                        return is_co, cp, expr_lineno

                    logger.debug("[AST] New Function {} rules to regex".format(function_name))

                    file_path = os.path.normpath(file_path)
                    code = "param {} in NewFunction {}".format(cp, function_name)
                    scan_chain.append(('NewFunction', code, file_path, function_lineno))

                    is_co = 4
                    cp = tuple([function_node.id, cp, vul_function])
                    return is_co, cp, 0

    return is_co, cp, expr_lineno


def member_back(param, nodes, function_params, file_path=None, isback=False, vul_function=None, method_name=None):
    """
    用于回溯参数为类变量时，需要保留类方法并回溯类获取方法函数返回
    :param method_name: 
    :param vul_function: 
    :param param: 
    :param nodes: 
    :param function_params: 
    :param file_path: 
    :param isback: 
    :return: 
    """
    global scan_chain

    param_name = get_member_data(param)
    expr_lineno = param.loc.start.line
    param_object = get_original_object(param)
    param_property = get_property_object(param)

    # 由于涉及到私有变量，暂时还没别的办法，先把this返回了吧
    if param_object == "this":
        is_co = 3
        cp = param
        expr_lineno = param.loc.start.line

        return is_co, cp, expr_lineno

    # 首先把类变量名作为正常的分析过程置入parameters_back
    is_co, cp, expr_lineno = parameters_back(param_object, nodes, function_params, file_path=file_path, isback=True,
                                             vul_function=vul_function, method_name=param_property)

    if is_co == 3 and hasattr(cp, "type") and cp.type == "ObjectExpression":
        # 获取的右值为类变量的声明（暂写死
        properties = cp.properties

        for property in properties:
            property_key = get_member_data(property.key)

            if property_key == param_property:
                property_value = property.value

                logger.debug("[AST] AST into Object and find method {}".format(param_property))

                file_path = os.path.normpath(file_path)
                code = "find object method {} define".format(param_property)
                scan_chain.append(('ObjectProperty', code, file_path, property.key.loc.start.line))

                is_co, cp = is_controllable(property_value)

                # 这里干脆单独处理下function好咯
                if property_value.type == "FunctionExpression":
                    function_params = property_value.params

                    is_co, cp, expr_lineno = function_back(property_value, function_params, back_nodes=nodes, file_path=file_path,
                                                           isback=isback, vul_function=vul_function,
                                                           method_name=method_name)

                    if is_co == 3:
                        property_value = cp

                if property_value.type == "MemberExpression" and get_member_data(get_original_object(property_value)) == "this":
                    # 如果是this则回去找找看
                    param_self_key = get_property_object(property_value)

                    for property2 in properties:
                        property2_key = get_member_data(property2.key)

                        if property2_key == param_self_key:
                            property2_value = property2.value

                            logger.debug("[AST] Find object self var {}={}".format(property2_key,
                                                                                   get_member_data(property2_value)))

                            file_path = os.path.normpath(file_path)
                            code = "Find object self var {}={}".format(property2_key, get_member_data(property2_value))
                            scan_chain.append(('ObjectSelfAss', code, file_path, property.key.loc.start.line))

                            is_co, cp = is_controllable(property2_value)
                            return is_co, cp, expr_lineno

    if isback:
        cp = param

    return is_co, cp, expr_lineno


def new_back(param, nodes, function_params, file_path=None, isback=False, vul_function=None, method_name=None):
    """
    用于解决右值为new时，
    :param param: 
    :param nodes: 
    :param function_params: 
    :param file_path: 
    :param isback: 
    :param vul_function: 
    :param method_name: 
    :return: 
    """
    object_name = get_member_data(param, isparam=True)
    evil_method = method_name

    is_co = 3
    cp = param
    expr_lineno = param.loc.start.line

    # new 只要回溯寻找两种可能
    # function x(){}
    # x.evil_method =
    for node in nodes[::-1]:
        if node.type == "FunctionDeclaration" and get_member_data(node.id) == object_name:
            function_body = node.body.body

            # function 不会将属性映射出来
            # is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, file_path=file_path, isback=isback,
            #                                          vul_function=vul_function, method_name=method_name)

        if node.type == "ExpressionStatement":  # 赋值操作
            expression = node.expression

            if expression.type == "AssignmentExpression" and expression.operator == "=":
                if expression.left.type == "MemberExpression":
                    # 左值为object.prototype
                    member_object = expression.left.object
                    member_property = expression.left.property
                    member_right = expression.right

                    if get_member_data(expression.left) == "{}.prototype".format(object_name):
                        # 对象重载
                        logger.debug(
                            "[AST] object {} parent class transfer to object {}...".format(object_name, get_member_data(
                                member_right)))

                        logger.debug(
                            "[AST] Find {}={} in line {}".format(get_member_data(expression.left),
                                                                 get_member_data(member_right),
                                                                 expression.loc.start.line))

                        file_path = os.path.normpath(file_path)
                        code = "{}={}".format(get_member_data(expression.left), get_member_data(member_right))
                        scan_chain.append(('Assignment', code, file_path, expression.loc.start.line))

                        param = member_right

                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params,
                                                                 vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)

                        return is_co, cp, expr_lineno

                    if get_member_data(member_object) == "{}.prototype".format(object_name) and get_member_data(
                            member_property) == evil_method:
                        # 对象父类属性修改

                        logger.debug(
                            "[AST] object {} parent class method {} is modified...".format(object_name, evil_method))

                        logger.debug(
                            "[AST] Find {}={} in line {}".format(get_member_data(expression.left),
                                                                 get_member_data(member_right),
                                                                 expression.loc.start.line))

                        file_path = os.path.normpath(file_path)
                        code = "{}={}".format(get_member_data(expression.left), get_member_data(member_right))
                        scan_chain.append(('Assignment', code, file_path, expression.loc.start.line))

                        param = member_right

                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params,
                                                                 vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)

                        return is_co, cp, expr_lineno

    return is_co, cp, expr_lineno


def function_call_back(param, nodes, function_params, file_path=None, isback=False, vul_function=None,
                       method_name=None):
    """
    CallExpression back analysize
    :param method_name: 
    :param param: 
    :param nodes: 
    :param function_params: 
    :param file_path: 
    :param isback: 
    :param vul_function: 
    :return: 
    """
    is_co, cp = is_controllable(param)
    expr_lineno = param.loc.start.line

    callee_name = get_member_data(param.callee)
    lineno = param.loc.start.line
    expression = param.callee

    # 额外处理一种神奇的调用思路
    # function (a) {return self.b(a)}

    if callee_name == vul_function or callee_name == "this.{}".format(vul_function) or (callee_name.split(".")[-1] == vul_function.split(".")[-1]):
        callee_params = param.arguments

        logger.debug("[AST] call param from self object method {}".format(callee_name))

        # 恶意函数调用
        for param in callee_params:
            is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                     function_flag=0, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=True, method_name=method_name)
            return is_co, cp, expr_lineno

    elif expression.type == "FunctionExpression":
        # 这个分支代表处理在js中特有的一种常见语义结构
        # (function(a){return a})(c)
        # 闭包
        callee = expression
        callee_body = callee.body.body
        callee_params = callee.params

        logger.debug("[AST] param is Closure FunctionCall in line {}".format(callee.loc.start.line))

        file_path = os.path.normpath(file_path)
        code = "param in Closure FunctionCall"
        scan_chain.append(('TmpFunctionCall', code, file_path, callee.loc.start.line))

        for callee_node in callee_body:

            if callee_node.type == "ReturnStatement":
                param = callee_node.argument

                is_co, cp, expr_lineno = parameters_back(param, callee_body, function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=True, method_name=method_name)

                if is_co == 3:

                    for callee_param in callee_params:
                        if get_member_data(callee_param) == cp:
                            expression_arguments = expression.arguments
                            param = expression_arguments[callee_params.index(callee_param)]

                            logger.debug(
                                "[AST] param {} line {} in function params, param transfer to param of Closure Function {}".format(
                                    get_member_data(cp), expr_lineno, get_member_data(param)))

                            file_path = os.path.normpath(file_path)
                            code = "New param {} out from Closure function".format(get_member_data(param))
                            scan_chain.append(('TmpFunction', code, file_path, callee.loc.start.line))

                            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                     function_flag=0, vul_function=vul_function,
                                                                     file_path=file_path,
                                                                     isback=isback, method_name=method_name)
                            return is_co, cp, expr_lineno

                is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=True, method_name=method_name)

                return is_co, cp, expr_lineno

    elif expression.type == "MemberExpression":
        # call 后为member目前是特殊语法
        # 原理为调用了某个对象的属性函数，目前只见过"a".split()
        expression_object = expression.object
        expression_property = expression.property

        method_name = get_member_data(expression_property)

        if method_name in string_function:
            logger.debug(
                "[AST] param {} use internal function {}, pass".format(get_member_data(expression), method_name))

            # 特殊处理
            if method_name == "reverse":
                logger.debug("[AST] param {} use special internal function {}, continue found param.".format(get_member_data(expression), method_name))

                is_co, cp, expr_lineno = parameters_back(expression_object, nodes, function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=True, method_name=method_name)

                cp = get_member_data(cp, isreverse=True)
                logger.debug(
                    "[AST] param {} use special internal function {}, reverse result is {}...".format(get_member_data(expression),
                                                                                                      method_name, cp))

                file_path = os.path.normpath(file_path)
                code = "param reverse result is {}".format(cp)
                scan_chain.append(('ReverseParam', code, file_path, lineno))

                is_co, cp = is_controllable(cp)

                return is_co, cp, expr_lineno

        is_co, cp, expr_lineno = parameters_back(expression_object, nodes, function_params, lineno,
                                                 function_flag=0, vul_function=vul_function,
                                                 file_path=file_path,
                                                 isback=True, method_name=method_name)

        return is_co, cp, expr_lineno

    elif callee_name in function_dict:

        logger.debug("[AST] function {} from internal defines, pass".format(callee_name))

        arguments = param.arguments

        for arg in arguments:
            param = arg

            is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                     function_flag=0, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=True, method_name=method_name)

            if is_co == 1:
                return is_co, cp, expr_lineno

    else:
        # 处理当参数传递到function call时，需要回溯寻找函数定义

        for node in nodes[::-1]:
            if node.type == "FunctionDeclaration" and get_member_data(node.id) == callee_name:

                logger.debug("[AST] Back to found function {} define".format(callee_name))

                file_path = os.path.normpath(file_path)
                code = "param from function {}".format(callee_name)
                scan_chain.append(('Function Define', code, file_path, expression.loc.start.line))

                function_params = node.params

                is_co, cp, expr_lineno = function_back(node, function_params, back_nodes=nodes, file_path=file_path,
                                                       isback=True, vul_function=vul_function, iscall=True)

                if is_co == 4:
                    # 代表返回变量来自于参数
                    return_method = get_property_object(cp)
                    callee_params = param.arguments

                    for callee_param in callee_params:
                        param = callee_param
                        is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)

                    if return_method:
                        cp = generate_memberexp(cp, return_method, expr_lineno)

                    is_co, cp = is_controllable(cp)

                return is_co, cp, expr_lineno

    return is_co, cp, expr_lineno


def parameters_back(param, nodes, function_params=None, lineno=0,
                    function_flag=0, vul_function=None, file_path=None,
                    isback=None, method_name=None):  # 用来得到回溯过程中的被赋值的变量是否与敏感函数变量相等,param是当前需要跟踪的污点
    """
    递归回溯敏感函数的赋值流程，param为跟踪的污点，当找到param来源时-->分析复制表达式-->获取新污点；否则递归下一个节点
    :param method_name: 恶意属性名，针对对member型的回溯拓展
    :param file_path: 
    :param vul_function: 
    :param param:
    :param nodes:
    :param function_params:
    :param lineno
    :param function_flag: 是否在函数、方法内的标志位
    :param isback: 是否需要返回该值
    :return:
    """
    global scan_chain

    expr_lineno = 0  # source所在行号
    is_co, cp = is_controllable(param)
    param_name = get_member_data(param)

    if is_co == 3 and hasattr(param, "type") and param.type == "MemberExpression":

        # 为了能适应正反向两种搜索方式，加入新的限制条件使搜索可能为顺序
        if param_name == vul_function:
            logger.debug("new eval function {} into sequential analysis".format(param_name))

        else:
            logger.debug(
                "[AST] AST analysis for MemberExpression {} in line {}".format(param_name, param.loc.start.line))
            is_co, cp, expr_lineno = member_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                                 vul_function=vul_function, method_name=method_name)
            return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(param, "type") and param.type == "NewExpression":
        logger.debug("[AST] AST analysis for NewExpression {} in line {}".format(param_name, param.loc.start.line))
        is_co, cp, expr_lineno = new_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                          vul_function=vul_function, method_name=method_name)
        return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(param, "type") and param.type == "CallExpression":
        is_co, cp, expr_lineno = function_call_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                                    vul_function=vul_function, method_name=method_name)
        return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(param, "type") and param.type == "ExpressionStatement":

        if param.expression.type == "CallExpression":
            is_co, cp, expr_lineno = function_call_back(param.expression, nodes, function_params, file_path=file_path,
                                                        isback=isback,
                                                        vul_function=vul_function, method_name=method_name)
            return is_co, cp, expr_lineno

    if isback and hasattr(param, "type") and param.type == "ObjectExpression":
        logger.debug("[AST] AST analysis found param ObjectExpression {}".format(param_name))
        return is_co, param, expr_lineno

    if is_co == 3 and hasattr(nodes, "type") and nodes.type == "ReturnStatement":
        # 仔细思考之后我觉得问题的核心还是在这里，当一个函数的返回函数为关键字，那么这种情况则需要特殊处理
        if get_property_object(nodes.argument) == param_name:
            # <del>return x.innerHTML<del>
            # <del>返回为特殊的属性，那么应该为对象传递，我们的目标转为顺序分析敏感对象<del>
            #  之前关于这部分的理解是错误的，在javascript中，不是所有情况下都会传递对象
            # 这里操作符号赋值为5
            logger.debug("[AST] evalobject in return, will not cause problem.")

            is_co = -1
            cp = get_property_object(nodes.argument)
            expr_lineno = nodes.loc.start.line

        return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(nodes, "type") and nodes.type == "BlockStatement":
        # block 块简单处理
        nodes = nodes.body

    if is_co == 3 and hasattr(nodes, "type") and nodes.type == "BreakStatement":
        return is_co, cp, expr_lineno

    if type(nodes) == list and len(nodes) != 0 and is_co != 1 and is_co != -1:
        node = nodes[len(nodes) - 1]

        if node.type == "VariableDeclaration":  # 变量定义
            expr_nodes = node.declarations

            for expr_node in expr_nodes:
                if param_name == get_member_data(expr_node.id) or param_name == get_member_data(expr_node.init):
                    node = expr_node

        if node.type == "VariableDeclarator":  # 变量赋值
            if param_name == get_member_data(node.id):
                # 获取右值
                param_expr = node.init
                param_expr_name = get_member_data(param_expr)
                expr_lineno = node.init.loc.start.line if param_expr else 0

                # log
                logger.debug(
                    "[AST] Find {}={} in line {}".format(param_name, param_expr_name, expr_lineno))

                file_path = os.path.normpath(file_path)
                code = "{}={}".format(param_name, param_expr_name)
                scan_chain.append(('Assignment', code, file_path, expr_lineno))

                is_co, cp = is_controllable(param_expr)

                if is_co == 1:
                    return is_co, cp, expr_lineno

                if isback is True:
                    return is_co, cp, expr_lineno

                if is_memberexp(param_expr):
                    # 尝试isback获取
                    param = get_original_object(param_expr)
                    is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                             function_flag=0, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=True, method_name=method_name)

                    # 暂时还没想好，暂时设置为对象修改
                    param = set_original_object(param_expr, cp)

                    logger.debug(
                        "[AST] merge object param {} in line {}".format(get_member_data(param), expr_lineno))

                    file_path = os.path.normpath(file_path)
                    code = "new merge param {}".format(get_member_data(param))
                    scan_chain.append(('NewParam', code, file_path, expr_lineno))

                    is_co, cp = is_controllable(param)
                else:

                    param = get_original_object(param_expr)

            # 这里是一个新的问题，js中涉及到对象传递，所以引入新的思路
            elif param_name == get_member_data(node.init):
                new_function_name = get_member_data(node.id)

                # 如果右值为函数名，则传递生成新的函数对象
                logger.debug(
                    "[AST] function {} line {} declarator new function {}".format(param_name, lineno,
                                                                                  new_function_name))

                file_path = os.path.normpath(file_path)
                code = "New function object passing to {}".format(new_function_name)
                scan_chain.append(('NewFunction', code, file_path, lineno))

                is_co = 4
                cp = tuple([node.id, param, vul_function])
                return is_co, cp, 0

        elif node.type == "ExpressionStatement":  # 赋值操作
            expression = node.expression

            if expression.type == "AssignmentExpression" and expression.operator == "=":

                if get_member_data(expression.right, isparam=True) == vul_function:
                    # 这里面向对象传递操作
                    new_function_name = get_member_data(expression.left)

                    logger.debug("[Deep AST] New eval object transfer to object {}".format(new_function_name))

                    file_path = os.path.normpath(file_path)
                    code = "New function object transfer to {}".format(new_function_name)
                    scan_chain.append(('NewFunction', code, file_path, lineno))

                    # 处理"prototype"问题

                    is_co = 4
                    cp = tuple([get_member_data(expression.left, isclean_prototype=True), "evalobject", vul_function])
                    return is_co, cp, 0

                if get_member_data(expression.left, isparam=True) == param_name:
                    param_expr = expression.right
                    param_expr_name = get_member_data(param_expr)
                    expr_lineno = expression.loc.start.line

                    # log
                    logger.debug(
                        "[AST] Find {}={} in line {}".format(param_name, param_expr_name, expr_lineno))

                    file_path = os.path.normpath(file_path)
                    code = "{}={}".format(param_name, param_expr_name)
                    scan_chain.append(('Assignment', code, file_path, expr_lineno))

                    is_co, cp = is_controllable(param_expr_name)

                    if is_co == 1:
                        return is_co, cp, expr_lineno

                    if is_co == -1 and isback is True:
                        cp = param_expr_name

                    if is_memberexp(param_expr):
                        # 当右值为memberexp
                        # 尝试isback获取
                        param = get_original_object(param_expr)
                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)

                        # 暂时还没想好，暂时设置为对象修改
                        param = set_original_object(param_expr, cp)

                        logger.debug(
                            "[AST] merge object param {} in line {}".format(get_member_data(param), expr_lineno))

                        file_path = os.path.normpath(file_path)
                        code = "new merge param {}".format(get_member_data(param))
                        scan_chain.append(('NewParam', code, file_path, expr_lineno))

                        is_co, cp = is_controllable(param)

                    elif hasattr(param_expr,
                                 "type") and param_expr.type == "BinaryExpression" and param_expr.operator == "+":
                        # 即右值为列表
                        param_list = get_param(param_expr)

                        for param in param_list:
                            logger.debug("[AST] new param {} ast".format(get_member_data(param)))

                            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                     function_flag=function_flag,
                                                                     vul_function=vul_function,
                                                                     file_path=file_path,
                                                                     isback=isback, method_name=method_name)

                            if is_co != 3:
                                return is_co, cp, expr_lineno

                        return is_co, cp, expr_lineno

                    elif is_memberexp(expression.left):
                        # 当左值为memberexp
                        # 也同样需要isback来想办法处理
                        is_co, cp, expr_lineno = parameters_back(param_expr, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)

                        logger.debug("[AST] New object method modify {}={}".format(get_member_data(expression.left),
                                                                                   get_member_data(cp)))

                        if is_thisexp(cp):
                            param = set_property_object(expression.left, cp.property)

                            logger.debug(
                                "[AST] New object method merge {}".format(get_member_data(param)))

                            file_path = os.path.normpath(file_path)
                            code = "new merge Object method {}".format(get_member_data(param))
                            scan_chain.append(('NewParam', code, file_path, expr_lineno))

                            is_co, cp = is_controllable(param)

                    elif param_expr.type == "CallExpression":
                        callee = param_expr.callee
                        callee_name = get_member_data(callee, isparam=True)

                        # 检查是不是内置函数
                        if callee_name in function_dict:

                            logger.debug(
                                "[AST] Assignment right is default function {}, continue...".format(callee_name))
                            param = param

                        else:
                            param = get_original_object(param_expr)

                    else:

                        param = get_original_object(param_expr)

                elif get_member_data(expression.right) == param_name and vul_function == param_name:
                    # 遇到了新的问题，自定义匹配的时候遇到对象传递，当前规则匹配到右值的时候
                    # 需要获取左值来作为新的规则
                    new_function_name = get_member_data(expression.left)

                    logger.debug(
                        "[AST] function {} line {} declarator new function {}".format(param_name, lineno,
                                                                                      new_function_name))

                    file_path = os.path.normpath(file_path)
                    code = "New function object transfer to {}".format(new_function_name)
                    scan_chain.append(('NewFunction', code, file_path, lineno))

                    is_co = 4
                    cp = tuple([expression.left.name, "evalobject", vul_function])
                    return is_co, cp, 0

                elif expression.right.type == "ObjectExpression":
                    # 当右值为对象时，需要跟进去分析
                    objectexpression = expression.right
                    object_properties = objectexpression.properties

                    for property in object_properties:
                        property_key = property.key
                        property_value = property.value

                        # 在这里打个断点，思考一个问题，如果敏感对象类右值是什么的时候可能会有问题
                        # 在这里我们暂且认为右值为functioncall

                        if property_value.type == "FunctionExpression":
                            is_co, cp, expr_lineno = function_back(property_value, function_params, nodes, file_path, isback,
                                                                   vul_function=vul_function, method_name=method_name)

                            if is_co == 4:
                                logger.debug("[AST] object.method transfer found {}".format(vul_function))

                                object_name = get_member_data(expression.left)

                                new_eval_function = str(object_name) + "." + str(get_member_data(property_key))

                                logger.debug("[AST] new eval function {}".format(new_eval_function))
                                file_path = os.path.normpath(file_path)
                                code = "New vustomize-Function {}".format(new_eval_function)
                                scan_chain.append(('NewFunction', code, file_path, property.loc.start.line))

                                cp = tuple([new_eval_function, "evalmethod"])

                        if is_co != 3:
                            return is_co, cp, expr_lineno

            elif expression.type == "CallExpression":
                callee_name = get_member_data(expression.callee)
                expr_lineno = expression.loc.start.line

                if callee_name and callee_name == vul_function or callee_name == "this." + vul_function.split(".")[-1]:
                    callee_params = expression.arguments
                    param_name = get_member_data(callee_params)

                    logger.debug("[AST] call param from self object method {}".format(callee_name))
                    logger.debug(
                        "[AST] Find {} in {} param in line {}".format(param_name, callee_name, expr_lineno))

                    file_path = os.path.normpath(file_path)
                    code = "{} in function {} param".format(param_name, callee_name)
                    scan_chain.append(('NewParam', code, file_path, expr_lineno))

                    # 恶意函数调用
                    for param in callee_params:
                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)
                        return is_co, cp, expr_lineno

                elif expression.callee and expression.callee.type == "FunctionExpression":
                    # 这个分支代表处理在js中特有的一种常见语义结构
                    # (function(a){return a})(c)
                    # 闭包
                    callee = expression.callee
                    callee_body = callee.body.body
                    callee_params = callee.params

                    if node.loc.end.line < int(lineno):
                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)
                        return is_co, cp, expr_lineno

                    logger.debug("[AST] param {} line {} in Closure Function in line {}".format(param, lineno,
                                                                                                callee.loc.start.line))

                    file_path = os.path.normpath(file_path)
                    code = "param {} in Closure function".format(param_name)
                    scan_chain.append(('TmpFunction', code, file_path, callee.loc.start.line))

                    vul_nodes = []

                    for vul_node in callee_body:
                        if vul_node is not None and vul_node.loc.start.line < int(lineno):
                            vul_nodes.append(vul_node)

                    is_co, cp, expr_lineno = parameters_back(param, vul_nodes, function_params, lineno,
                                                             function_flag=0, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=True, method_name=method_name)

                    if is_co == 3:

                        for callee_param in callee_params:
                            if get_member_data(callee_param) == cp:
                                expression_arguments = expression.arguments
                                param = expression_arguments[callee_params.index(callee_param)]

                                logger.debug(
                                    "[AST] param {} line {} in function params, param transfer to param of Closure Function {}".format(
                                        get_member_data(cp), expr_lineno, get_member_data(param)))

                                file_path = os.path.normpath(file_path)
                                code = "New param {} out from Closure function".format(get_member_data(param))
                                scan_chain.append(('TmpFunction', code, file_path, callee.loc.start.line))

                                is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                         function_flag=0, vul_function=vul_function,
                                                                         file_path=file_path,
                                                                         isback=isback, method_name=method_name)
                                return is_co, cp, expr_lineno

        elif node.type == "FunctionDeclaration":  # 函数定义
            function_expression = node.expression
            function_isAsync = node.isAsync
            function_name = get_member_data(node.id)
            function_params = get_param_list(node.params)
            function_body = node.body.body  # blockstatement
            function_lineno = node.loc.start.line

            vul_nodes = []

            # 遇到了一个令人难受的问题
            # client js 有严重的动态类型问题，所有的变量、函数等都是对象
            # 为了解决这个问题，现在尝试把逻辑设置为name相同时即同一个对象
            if param_name == function_name:
                is_co, cp, expr_lineno = function_back(node, function_params, back_nodes=nodes, file_path=file_path,
                                                       isback=isback, method_name=method_name)

                # 由于从函数内部出来的很有可能是类的私有变量，所以如果私有变量为this的时候
                return is_co, cp, expr_lineno

            # 这是一个优化，无关的变量跳过
            if node.loc.end.line < int(lineno):
                is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)
                return is_co, cp, expr_lineno

            logger.debug(
                "[AST] param {} line {} in function {} line {}, start ast in function".format(param_name,
                                                                                              lineno,
                                                                                              function_name,
                                                                                              function_lineno))

            file_path = os.path.normpath(file_path)
            code = "param {} in function {}".format(param_name, function_name)
            scan_chain.append(('Function', code, file_path, function_lineno))

            for function_node in function_body:
                if function_node is not None and function_node.loc.end.line <= int(lineno):
                    vul_nodes.append(function_node)

            if len(vul_nodes) > 0:
                is_co, cp, expr_lineno = parameters_back(param, vul_nodes, function_params, function_lineno,
                                                         function_flag=1, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)
                function_flag = 0

            if is_co == 3:  # 出现新的敏感函数，重新生成新的漏洞结构，进入新的遍历结构
                for function_param in function_params:
                    if function_param == cp:
                        logger.debug(
                            "[AST] param {} line {} in function_params, start new rule for function {}".format(
                                param_name, function_lineno, function_name))

                        file_path = os.path.normpath(file_path)
                        code = "param {} in NewFunction {}".format(param_name, function_name)
                        scan_chain.append(('NewFunction', code, file_path, function_lineno))

                        if vul_function is None or function_name != vul_function:
                            logger.info(
                                "[Deep AST] Now vulnerability function from function {}() param ({})".format(
                                    function_name,
                                    cp))

                            is_co = 4
                            cp = tuple([node, param, vul_function])
                            return is_co, cp, 0
                        else:
                            logger.info(
                                "[Deep AST] Recursive problems may exist in the code, exit the new rules generated..."
                            )
                            # 无法解决递归，直接退出
                            is_co = -1
                            return is_co, cp, 0

            elif is_co == 5:  # 出现函数返回值为敏感参数的情况需要对象传递
                eval_method = cp

                logger.debug("[Deep AST] eval method {} return from function {}".format(eval_method, function_name))

                file_path = os.path.normpath(file_path)
                code = "NewEvalObject {} with {}".format(function_name, eval_method)
                scan_chain.append(('NewEvalObject', code, file_path, function_lineno))

                is_co = 4
                cp = tuple([function_name, "evalobject", vul_function])

                return is_co, cp, 0

        elif node.type == "IfStatement":
            logger.debug(
                "[AST] param {} line {} in if/else, start ast in if/else".format(param_name, node.loc.start.line))

            if_condition = node.test
            if_body = node.consequent

            if if_body.type != "BlockStatement":
                if_body = [if_body]

            is_co, cp, expr_lineno = parameters_back(param, if_body, function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)

            if is_co != 1 and node.alternate:
                else_body = node.alternate

                if hasattr(else_body, "type") and else_body.type == "IfStatement":
                    else_body = [else_body]

                is_co, cp, expr_lineno = parameters_back(param, else_body, function_params, lineno,
                                                         function_flag=function_flag, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)

        elif node.type == "WhileStatement":
            logger.debug("[AST] Param {} line {} in while, start ast in while".format(param_name, node.loc.start.line))

            while_body = node.body.body

            is_co, cp, expr_lineno = parameters_back(param, while_body, function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)

        if is_co == 3:
            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)  # 找到可控的输入时，停止递归

    return is_co, cp, expr_lineno


def deep_parameters_back(param, back_node, function_params, count, file_path, lineno=0, vul_function=None,
                         isback=False):
    """
    深层递归分析外层逻辑，主要是部分初始化条件和新递归的确定
    :param isback: 
    :param lineno: 
    :param vul_function: 
    :param param: 
    :param back_node: 
    :param function_params: 
    :param count: 
    :param file_path: 
    :return: 
    """
    count += 1
    padding = {}

    is_co, cp, expr_lineno = parameters_back(param, back_node, function_params, lineno, vul_function=vul_function,
                                             file_path=file_path, isback=isback)

    if count > 20:
        logger.warning("[Deep AST] depth too big, auto exit...")
        return is_co, cp, expr_lineno

    return is_co, cp, expr_lineno


def analysis_params(expression, back_node, vul_function, vul_lineno, file_path, repair_functions=None,
                    controlled_params=None, isexternal=False, is_eval=False, is_function=False):
    """
    当分析到具体的参数时
    :param is_function: 真是出现了新的问题，常规函数式匹配，右值为function时
    :param is_eval: 
    :param controlled_params: 
    :param repair_functions: 
    :param isexternal: 
    :param vul_function: 
    :param expression: 
    :param back_node: 这是一个设计问题，这里函数可能有很多入口，所以这里不应该为直接传node
    :param vul_lineno: 
    :param file_path: 
    :return: 
    """
    global scan_chain, is_repair_functions, is_controlled_params

    function_params = None
    is_co = -1
    cp = get_member_data(expression)
    expr_lineno = vul_lineno

    if repair_functions is not None:
        is_repair_functions = repair_functions

    if controlled_params is not None:
        is_controlled_params = controlled_params

    if isexternal:
        scan_chain = ['start']
        param_list = [check_param(expression, vul_lineno=vul_lineno)]

        if type(ast_object.get_nodes(file_path, vul_lineno=vul_lineno, lan='javascript')) is list:
            back_node = ast_object.get_nodes(file_path, vul_lineno=vul_lineno, lan='javascript')
        else:
            back_node = ast_object.get_nodes(file_path, vul_lineno=vul_lineno, lan='javascript').body

    elif is_function:
        param_list = [check_param(expression, vul_lineno=vul_lineno)]

    else:
        arguments = expression.arguments
        param_list = get_param_list(arguments, is_eval=is_eval, is_function_regex=True)

    logger.debug("[AST] AST to find param {}".format(get_member_data(param_list)))
    logger.debug("[AST] AST for Vul function {}".format(vul_function))

    code = "find param {}".format(get_member_data(param_list))
    scan_chain.append(('NewFind', code, file_path, vul_lineno))

    for param in param_list:
        count = 0
        is_co, cp, expr_lineno = deep_parameters_back(param, back_node, function_params, count, file_path, vul_lineno,
                                                      vul_function=vul_function)

        if isexternal:
            if is_co != 3:
                return is_co, cp, expr_lineno, scan_chain
        set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)

    return is_co, cp, expr_lineno, scan_chain


def analysis_If(node, vul_function, back_node, vul_lineno, file_path, function_params):
    """
    if 语句
    :param node: 
    :param vul_function: 
    :param back_node: 
    :param vul_lineno: 
    :param file_path: 
    :param function_params: 
    :return: 
    """
    if_condition = node.test
    if_body = node.consequent
    if node.loc.start.line <= vul_lineno <= node.loc.end.line:
        analysis([if_body], vul_function, back_node, vul_lineno, file_path, function_params)

        if node.alternate:
            else_body = node.alternate
            analysis([else_body], vul_function, back_node, vul_lineno, file_path, function_params)


def analysis_while(node, vul_function, back_node, vul_lineno, file_path, function_params):
    """
    while 语句
    :param node:
    :param vul_function:
    :param back_node:
    :param vul_lineno:
    :param file_path:
    :param function_params:
    :return:
    """
    while_body = node.body.body
    if node.loc.start.line <= vul_lineno <= node.loc.end.line:
        analysis(while_body, vul_function, back_node, vul_lineno, file_path, function_params)


def analysis_callexpression(node, vul_function, back_node, vul_lineno, file_path, function_params):
    if vul_lineno == node.loc.start.line:
        call_arguments = node.arguments
        call_callee = node.callee

        for arg in call_arguments:
            if arg.type == "CallExpression":
                analysis_callexpression(arg, vul_function, back_node, vul_lineno, file_path, function_params)

        if is_eval_function(node):
            analysis_params(node, back_node, vul_function, vul_lineno, file_path, function_params, is_eval=True)

        elif call_callee.type == "FunctionExpression":
            child_nodes = call_callee.body.body
            function_params = call_callee.arguments

            analysis(child_nodes, vul_function, back_node, int(vul_lineno), file_path, function_params=function_params,
                     in_funtion=True)

        else:
            analysis_params(node, back_node, vul_function, vul_lineno, file_path, function_params)

    elif node.loc.start.line < vul_lineno <= node.loc.end.line:
        if node.callee.type == "FunctionExpression":
            nodes = node.callee.body.body
            function_params = node.callee.params

            analysis(nodes, vul_function, back_node, int(vul_lineno), file_path, function_params=function_params,
                     in_funtion=True)


def analysis_objectexpression(node, vul_function, back_node, vul_lineno, file_path, function_params, object_name):
    """
    这是一个神奇的函数，js才有可能出现，即右值为对象，其中方法为恶意函数
    :param node: 
    :param vul_function: 
    :param back_node: 
    :param vul_lineno: 
    :param file_path: 
    :param function_params: 
    :return: 
    """
    # object_name = get_member_data(node.id)
    object_expr_node = node
    object_properties = object_expr_node.properties

    for property in object_properties:
        property_key = property.key
        property_value = property.value

        if get_member_data(property_value) == vul_function and property_value.loc.start.line == vul_lineno:
            logger.debug("[AST] object.method transfer found {}".format(vul_function))

            new_eval_function = str(object_name) + "." + str(get_member_data(property_key))

            logger.debug("[AST] new eval function {}".format(new_eval_function))
            file_path = os.path.normpath(file_path)
            code = "New vustomize-Function {}".format(new_eval_function)
            scan_chain.append(('NewFunction', code, file_path, vul_lineno))

            is_co = 4
            cp = tuple([new_eval_function, "evalmethod", vul_function])
            set_scan_results(is_co, cp, 1, vul_function, "", vul_lineno)


def analysis_expression(node, vul_function, back_node, vul_lineno, file_path, function_params):
    expression = node.expression
    expression_loc = node.loc

    expr_type = expression.type

    if expr_type == "CallExpression":
        analysis_callexpression(expression, vul_function, back_node, vul_lineno, file_path, function_params)

    elif expr_type == "AssignmentExpression":
        expression_node = get_member_data(expression.right)

        # 这里需要更精细的处理方式
        if expression.right.type == "ObjectExpression":
            # 仔细想了下，由于这应该是一个可以称之为evalmethod的问题，应该在参数回溯的时候分析，所以不在这里处理
            # param = get_member_data(set_property_object(expression, key))
            object_name = get_member_data(expression.left)
            analysis_objectexpression(expression.right, vul_function, back_node, vul_lineno, file_path, function_params,
                                      object_name=object_name)

        elif expression.right.type == "NewExpression":
            # 右值为new object
            pass

        # else:
        #     analysis_params(expression_node, back_node, vul_function, vul_lineno, file_path, is_function=True)


def set_scan_results(is_co, cp, expr_lineno, sink, param, vul_lineno):
    """
    获取结果信息-->输出结果
    :param is_co:
    :param cp:
    :param expr_lineno:
    :param sink:
    :param param:
    :param vul_lineno:
    :return:
    """
    results = []
    global scan_results, scan_chain

    result = {
        'code': is_co,
        'source': get_member_data(cp),
        'source_lineno': expr_lineno,
        'sink': sink,
        'sink_param:': get_member_data(param),
        'sink_lineno': vul_lineno,
        "chain": scan_chain,
    }
    if result['code'] > 0:  # 查出来漏洞结果添加到结果信息中
        results.append(result)
        scan_results += results


def analysis(all_nodes, vul_function, back_node, vul_lineno, file_path, function_params, in_funtion=False):
    global scan_results

    for node in all_nodes:

        # 检查line范围，以快速锁定参数
        if vul_lineno < node.loc.start.line:
            break

        if not in_funtion:
            back_node.append(node)

        if node.type == "ExpressionStatement":  # 函数调用
            analysis_expression(node, vul_function, back_node, vul_lineno, file_path, function_params)

        if node.type == "FunctionDeclaration":  # 函数声明
            # analysis_functiondec(node, vul_function, back_node, vul_lineno, file_path, function_params)
            function_params = get_param_list(node.params)

            # 递归进函数
            if node.body.type == "BlockStatement":
                analysis(node.body.body, vul_function, back_node, vul_lineno, file_path,
                         function_params=function_params, in_funtion=True)

        if node.type == "BlockStatement":  # 函数块？
            analysis(node.body, vul_function, back_node, vul_lineno, file_path, function_params=function_params)

        if node.type == "IfStatement":
            analysis_If(node, vul_function, back_node, vul_lineno, file_path, function_params)

        if node.type == "VariableDeclaration":  # 函数赋值表达式
            for child_node in node.declarations:

                if child_node.init:
                    if child_node.init.type == "CallExpression":
                        analysis_callexpression(child_node.init, vul_function, back_node, vul_lineno, file_path,
                                                function_params)

                    elif child_node.init.type == "ObjectExpression":
                        object_name = get_member_data(child_node.id)
                        analysis_objectexpression(child_node.init, vul_function, back_node, vul_lineno, file_path,
                                                  function_params, object_name)

        if node.type == "WhileStatement":
            analysis_while(node, vul_function, back_node, vul_lineno, file_path, function_params)

    return scan_results


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[]):
    """
    开始检测函数
    :param controlled_params: 
    :param repair_functions: 
    :param sensitive_func: 要检测的敏感函数,传入的为函数列表
    :param vul_lineno: 漏洞函数所在行号
    :param file_path: 文件路径
    :return:
    """
    try:
        global scan_results, is_repair_functions, is_controlled_params, scan_chain

        scan_chain = ['start']
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params.copy()

        if type(ast_object.get_nodes(file_path)) is list:
            all_nodes = []
        else:
            all_nodes = ast_object.get_nodes(file_path).body

        for func in sensitive_func:  # 循环判断代码中是否存在敏感函数，若存在，递归判断参数是否可控;对文件内容循环判断多次
            back_node = []
            analysis(all_nodes, func, back_node, int(vul_lineno), file_path, function_params=None)

            # 如果检测到一次，那么就可以退出了
            if len(scan_results) > 0:
                logger.debug("[AST] Scan parser end for {}".format(str(scan_results)))
                break

    except SyntaxError as e:
        logger.warning('[AST] [ERROR]:{e}'.format(e=traceback.format_exc()))

    return scan_results
