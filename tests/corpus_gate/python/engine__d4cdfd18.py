# -*- coding: utf-8 -*-
# @Time    : 2025
# @Author  : KunLun-M
# @File    : engine.py

"""
    C/C++ NewFunction 正则生成引擎
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.log import logger


def init_match_rule(data):
    """
    处理 C/C++ 新生成规则初始化正则匹配

    :param data: NewFunction chain 中的 source tuple (func_name, param_name, vul_function)
    :return: (match, match2, vul_function, index, origin_func_name)
    """
    obj = data[0]

    # code=5: data[0] 是 dict {'code': 5, 'source': ('func_name', 'param_name', 'vul_function'), ...}
    if isinstance(obj, dict) and 'source' in obj:
        source = obj['source']
        function_name = source[0]  # 封装函数名
        origin_func_name = function_name
        if '::' in function_name:
            function_name = function_name.split('::')[-1]

        match = r"(?:^|[\s=,.])\w+\." + re.escape(function_name) + r"\s*\([^)]*\)" + \
               r"|" + \
               r"(?:^|[\s=,])" + re.escape(function_name) + r"\s*\([^)]*\)"
        match2 = r"(?:void|int|char|long|float|double|short|unsigned|static|extern|struct\s+\w+)\s*\*?\s*" + re.escape(function_name) + r"\s*\("
        logger.debug("[New Rule] C match (from code=5): {}".format(match))
        return match, match2, function_name, 0, origin_func_name

    if isinstance(obj, str):
        # NewCore 二次扫描：data = (func_name, param_name, vul_function)
        function_name = obj
        origin_func_name = function_name
        # strip namespace prefix: ns::Func → Func
        if '::' in function_name:
            function_name = function_name.split('::')[-1]

        match = r"(?:^|[\s=,.])\w+\." + re.escape(function_name) + r"\s*\([^)]*\)" + \
               r"|" + \
               r"(?:^|[\s=,])" + re.escape(function_name) + r"\s*\([^)]*\)"
        # match2 排除函数定义/声明行（带返回类型前缀），保留调用行
        match2 = r"(?:void|int|char|long|float|double|short|unsigned|static|extern|struct\s+\w+)\s*\*?\s*" + re.escape(function_name) + r"\s*\("
        logger.debug("[New Rule] C match: {}".format(match))
        return match, match2, function_name, 0, origin_func_name

    logger.debug("[New Rule] C auto rule generation: unsupported data type")
    return None, None, None, 0, "None"
