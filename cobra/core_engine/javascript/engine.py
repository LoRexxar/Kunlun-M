#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/7/18 14:40
# @Author  : LoRexxar
# @File    : engine.py
# @Contact : lorexxar@gmail.com


import re
import traceback
from cobra.log import logger

from .parser import get_param_list, get_member_data


def init_match_rule(data):
    """
    处理新生成规则初始化正则匹配
    :param data: 
    :return: 
    """

    try:
        if not hasattr(data[0], "type"):
            object = re.escape(data[0])
        else:
            object = data[0]

        type = data[1]
        match = ""

        # for evalobject
        if type == "evalobject":
            object_name = object
            index = -1

            match = "(?:\A|\s|\\b)(\w+\s*\=\s*{}\\b)|({}\s*\([^\)]*\))"

            match = match.format(object_name, object_name)

            match2 = "function\s+{}\\b".format(object_name)
            vul_function = object_name

        elif type == "evalmethod":
            object_name = object
            index = 1

            object_name = object.split('.')[0]
            method_name = object.split('.')[-1]

            match = "((?:\A|\s|\\b|\=)(({}.{})|(this\.{}))\s*(\([^\)]*\))?)"

            match = match.format(object_name, method_name, method_name)

            match2 = "function\s+{}\\b".format(object_name)
            vul_function = "{}.{}".format(object_name.strip("\\"), method_name)

        elif hasattr(object, "type") and object.type == "FunctionDeclaration":
            function_params = get_param_list(object.params)
            function_name = get_member_data(object.id)
            param = data[1]
            index = 0
            for function_param in function_params:
                if function_param == param:
                    break
                index += 1

            # curl_setopt\s*\(.*,\s*CURLOPT_URL\s*,(.*)\)
            match_header = "(?:\A|\s|\\b|\=)"
            match = "\s*\("
            for i in range(len(function_params)):
                if i != 0:
                    match += ","

                    if function_params is not None:
                        match += "?"

                if i == index:
                    match += "([^,\)]*)"
                else:
                    match += "[^,\)]*"

            match += "\)"

            # js除了函数调用以外，还存在对象传递
            # var check=timeMsg
            match = "({}\s*{}\s*(({})|\\b))".format(match_header, function_name, match)

            # 去除定义函数
            match2 = "function\s+" + function_name
            vul_function = function_name

        elif hasattr(object, "type") and object.type == "Identifier":
            # 针对函数传递
            function_name = get_member_data(object)
            index = 0

            match_header = "(?:\A|\s|\\b|\=)"
            match = "\([^\)]*\)"

            # js除了函数调用以外，还存在对象传递
            # var check=timeMsg
            match = "({}\s*{}\s*(({})|\\b))".format(match_header, function_name, match)

            # 去除定义函数
            match2 = "function\s+" + function_name
            vul_function = function_name

        else:
            index = 0

            match = "(?:\A|\s|\\b)" + object + "\s*\([^\)]*\)"

            match2 = "function\s+" + object
            vul_function = object

        # elif isinstance(object, php.Class):
        #     class_params = data[2]
        #     class_name = object.name
        #     param = data[1]
        #     index = 0
        #
        #     for class_param in class_params:
        #         if class_param.name == param.name:
        #             break
        #         index += 1
        #
        #     # $A = new a($x, $y);
        #     match = "new\s*" + class_name + "\s*\("
        #
        #     for i in range(len(class_params)):
        #         if i != 0:
        #             match += ","
        #
        #             if class_params[i].default is not None:
        #                 match += "?"
        #
        #         if i == index:
        #             match += "([^,\)]*)"
        #         else:
        #             match += "[^,\)]*"
        #
        #     match += "\)"
        #
        #     # 去除定义类，类定义和调用方式不一样，但是为了不影响结构，依然赋值
        #     match2 = "class\s+" + class_name + "\s*{"
        #     vul_function = class_name

    except:
        logger.error('[New Rule] Error to unpack function param, Something error')
        traceback.print_exc()
        match = None
        match2 = None
        index = 0

    return match, match2, vul_function, index
