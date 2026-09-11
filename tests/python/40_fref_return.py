"""
Case 40: Python 跨作用域 — 函数返回函数引用
get_func 返回 os.system，外部接收后调用
预期: 检出 CVI-7000
"""
import os
import sys

def get_func():
    return os.system

if __name__ == '__main__':
    user_input = sys.argv[1]
    func = get_func()
    func(user_input)
