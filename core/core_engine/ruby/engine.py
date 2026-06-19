#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Ruby Engine — Ruby 自动规则生成引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
import re
from utils.log import logger


def init_match_rule(data):
    """
    处理 Ruby 新生成规则初始化正则匹配
    """
    obj = data[0]

    if isinstance(obj, str):
        function_name = obj
        origin_func_name = function_name
        # strip module prefix: Module::Func → Func
        if '::' in function_name:
            function_name = function_name.split('::')[-1]
        # strip receiver prefix: obj.method → method
        if '.' in function_name:
            function_name = function_name.split('.')[-1]

        # 匹配 Module::Func(...)、obj.func(...) 和 func(...)
        # Ruby 函数调用可以是：func(), obj.func(), Module.func(), Module::func()
        match = (r"(?:^|[\s=,;.])\w+::" + re.escape(function_name) + r"\s*\([^)]*\)" +
                 r"|" +
                 r"(?:^|[\s=,;.])\w+\." + re.escape(function_name) + r"\s*\([^)]*\)" +
                 r"|" +
                 r"(?:^|[\s=,;.])" + re.escape(function_name) + r"\s*\([^)]*\)")
        # 匹配方法定义
        match2 = r"def\s+" + re.escape(function_name) + r"\b"
        logger.debug("[New Rule] Ruby match: {}".format(match))
        return match, match2, function_name, 0, origin_func_name

    # AST 节点输入（预留）
    if hasattr(obj, 'type'):
        pass

    logger.debug("[New Rule] Ruby auto rule generation: unsupported data type")
    return None, None, None, 0, "None"
