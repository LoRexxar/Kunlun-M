# -*- coding: utf-8 -*-
"""
Python 跨文件 benchmark: utils 模块
被 main.py import 后调用，内部包含 os.system 危险调用
"""


def process_command(cmd):
    """处理命令字符串并执行"""
    return os.system(cmd)


def evaluate_expression(expr):
    """评估表达式并执行"""
    return eval(expr)
