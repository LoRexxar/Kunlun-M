#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Kotlin Engine — Kotlin 自动规则生成引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
import re
from utils.log import logger


def init_match_rule(data):
    """
    处理 Kotlin 新生成规则初始化正则匹配
    """
    obj = data[0]

    if isinstance(obj, str):
        # NewCore 二次扫描：data = (func_name, param_name, vul_function)
        function_name = obj
        origin_func_name = function_name
        # strip package prefix: package.Func → Func
        if '.' in function_name:
            function_name = function_name.split('.')[-1]

        # 匹配 package.Func(...) 和 Func(...)
        # Kotlin 函数调用可以是：func(), Type.func(), obj.method(), Companion.func()
        match = (r"(?:^|[\s=,;.])\w+\." + re.escape(function_name) + r"\s*\([^)]*\)" +
                 r"|" +
                 r"(?:^|[\s=,;.])" + re.escape(function_name) + r"\s*\([^)]*\)")
        # 匹配函数定义
        match2 = r"fun\s+" + re.escape(function_name) + r"\b"
        logger.debug("[New Rule] Kotlin match: {}".format(match))
        return match, match2, function_name, 0, origin_func_name

    # AST 节点输入（预留）
    if hasattr(obj, 'type'):
        pass

    logger.debug("[New Rule] Kotlin auto rule generation: unsupported data type")
    return None, None, None, 0, "None"
