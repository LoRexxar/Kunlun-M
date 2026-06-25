"""
Case 39: Python 跨作用域 — 函数参数传递函数引用
将 os.system 作为参数传入 executor，executor 通过参数调用
预期: 检出 CVI-7000
"""
import os
import sys

def executor(op, arg):
    op(arg)

if __name__ == '__main__':
    user_input = sys.argv[1]
    executor(os.system, user_input)
