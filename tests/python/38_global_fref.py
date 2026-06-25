"""
Case 38: Python 跨作用域 — 全局函数引用在函数内调用
模块级 func = os.system，在 handle 中调用 func
预期: 检出 CVI-7000
"""
import os
import sys

func = os.system

def handle_request(user_input):
    func(user_input)

if __name__ == '__main__':
    handle_request(sys.argv[1])
