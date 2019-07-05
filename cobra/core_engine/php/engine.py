#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/7/5 15:34
# @Author  : LoRexxar
# @File    : engine.py
# @Contact : lorexxar@gmail.com


import traceback
from phply import phpast as php
from cobra.log import logger


def init_match_rule(data):
    """
    处理新生成规则初始化正则匹配
    :param data: 
    :return: 
    """

    try:
        object = data[0]
        match = ""

        if isinstance(object, php.Method) or isinstance(object, php.Function):
            function_params = object.params
            function_name = object.name
            param = data[1]
            index = 0
            for function_param in function_params:
                if function_param.name == param.name:
                    break
                index += 1

            # curl_setopt\s*\(.*,\s*CURLOPT_URL\s*,(.*)\)
            match = "(?:\A|\s|\\b)" + function_name + "\s*\("
            for i in range(len(function_params)):
                if i != 0:
                    match += ","

                    if function_params[i].default is not None:
                        match += "?"

                if i == index:
                    match += "([^,\)]*)"
                else:
                    match += "[^,\)]*"

            match += "\)"

            # 去除定义函数
            match2 = "function\s+" + function_name
            vul_function = function_name

        elif isinstance(object, php.Class):
            class_params = data[2]
            class_name = object.name
            param = data[1]
            index = 0

            for class_param in class_params:
                if class_param.name == param.name:
                    break
                index += 1

            # $A = new a($x, $y);
            match = "new\s*" + class_name + "\s*\("

            for i in range(len(class_params)):
                if i != 0:
                    match += ","

                    if class_params[i].default is not None:
                        match += "?"

                if i == index:
                    match += "([^,\)]*)"
                else:
                    match += "[^,\)]*"

            match += "\)"

            # 去除定义类，类定义和调用方式不一样，但是为了不影响结构，依然赋值
            match2 = "class\s+" + class_name + "\s*{"
            vul_function = class_name

    except:
        logger.error('[New Rule] Error to unpack function param, Something error')
        traceback.print_exc()
        match = None
        match2 = None
        index = 0

    return match, match2, vul_function, index