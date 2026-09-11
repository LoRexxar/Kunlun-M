"""
Case 41: Python 跨作用域 — 同名遮蔽（安全）
全局 func = os.system，函数内局部 func = print 遮蔽
预期: 不应检出
"""
import os
import sys

func = os.system

def handle_request(user_input):
    func = print
    func(user_input)

if __name__ == '__main__':
    handle_request(sys.argv[1])
