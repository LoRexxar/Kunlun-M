#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Python Engine — Python 自动规则生成引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    为 Python 的 NewFunction (code=4) 信号生成 match/match2 正则，
    使 NewCore 二次扫描链路能够回溯自定义函数的调用方。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import ast
import re
import traceback

from utils.log import logger


def _get_function_params(func_def):
    """从 ast.FunctionDef / ast.AsyncFunctionDef 提取参数名列表"""
    args = func_def.args
    params = []
    for arg in args.args:
        params.append(arg.arg)
    return params


def _get_init_params(class_def):
    """从 ast.ClassDef 的 __init__ 方法中提取参数名列表（排除 self）"""
    for node in class_def.body:
        if isinstance(node, ast.FunctionDef) and node.name == "__init__":
            params = _get_function_params(node)
            if params and params[0] == "self":
                params = params[1:]
            return params
    return []


def init_match_rule(data):
    """
    处理 Python 新生成规则初始化正则匹配

    :param data: [AST节点或字符串, 参数名字符串, 原始sink函数名(可选)]
    :return: (match, match2, vul_function, index, origin_func_name)
    """
    try:
        obj = data[0]
        param = data[1]
        origin_func_name = data[2] if len(data) > 2 and data[2] else ""

        # 字符串 fallback
        if isinstance(obj, str):
            function_name = re.escape(obj)
            match = r"(?:\A|\s|\b)" + function_name + r"\s*\([^\)]*\)"
            match2 = r"def\s+" + function_name + r"\b"
            return match, match2, obj, 0, origin_func_name

        # 普通函数定义
        if isinstance(obj, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_name = obj.name
            function_params = _get_function_params(obj)

            index = 0
            for i, p in enumerate(function_params):
                if p == param:
                    index = i
                    break

            # 生成 match: funcName(arg1,([^,)]*),arg3)
            match = r"(?:\A|\s|\b)" + re.escape(function_name) + r"\s*\("
            for i in range(len(function_params)):
                if i != 0:
                    match += ","
                if i == index:
                    match += r"([^,\)]*)"
                else:
                    match += r"[^,\)]*"
            match += r"\)"

            match2 = r"def\s+" + re.escape(function_name) + r"\b"
            vul_function = function_name
            return match, match2, vul_function, index, origin_func_name

        # 类定义（构造参数）
        if isinstance(obj, ast.ClassDef):
            class_name = obj.name
            function_params = _get_init_params(obj)

            index = 0
            for i, p in enumerate(function_params):
                if p == param:
                    index = i
                    break

            # 生成 match: ClassName(arg1,([^,)]*),arg2)
            match = r"(?:\A|\s|\b)" + re.escape(class_name) + r"\s*\("
            for i in range(len(function_params)):
                if i != 0:
                    match += ","
                if i == index:
                    match += r"([^,\)]*)"
                else:
                    match += r"[^,\)]*"
            match += r"\)"

            match2 = r"class\s+" + re.escape(class_name) + r"\b"
            vul_function = class_name
            return match, match2, vul_function, index, origin_func_name

        # 未知类型 fallback
        logger.warning("[New Rule] Unknown Python AST node type for init_match_rule")
        match = None
        match2 = None
        vul_function = None
        index = 0

    except Exception:
        logger.error('[New Rule] Error to unpack function param, Something error')
        traceback.print_exc()
        match = None
        match2 = None
        vul_function = None
        index = 0
        origin_func_name = ""

    return match, match2, vul_function, index, origin_func_name
