#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Lua Engine — Lua 自动规则生成引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
import re
from utils.log import logger


def init_match_rule(data):
    """
    处理 Lua 新生成规则初始化正则匹配
    """
    obj = data[0]

    if isinstance(obj, str):
        # NewCore 二次扫描：data = (func_name, param_name, vul_function)
        function_name = obj
        origin_func_name = function_name

        # Lua 函数调用可以是：func(), obj:method(), module.func()
        match = (r"(?:^|[\s=,;.])" + re.escape(function_name) + r"\s*\([^)]*\)" +
                 r"|" +
                 r"(?:^|[\s=,;.])" + re.escape(function_name) + r"\s*:" +
                 re.escape(function_name) + r"\s*\([^)]*\)")
        # 匹配函数定义
        match2 = r"(?:local\s+)?function\s+" + re.escape(function_name) + r"\b"
        logger.debug("[New Rule] Lua match: {}".format(match))
        return match, match2, function_name, 0, origin_func_name

    # AST 节点输入（预留）
    if hasattr(obj, 'type'):
        pass

    logger.debug("[New Rule] Lua auto rule generation: unsupported data type")
    return None, None, None, 0, "None"
