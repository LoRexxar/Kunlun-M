"""
Case 44: C 跨作用域 — 同名遮蔽（安全）
函数内局部 func 遮蔽全局 func，局部 func 是 printf（安全）
预期: 不应检出
"""
#include <stdlib.h>
#include <stdio.h>

int (*global_func)(const char *) = system;

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    char *cmd = argv[1];
    int (*func)(const char *) = (int (*)(const char *))printf;
    func(cmd);
    return 0;
}
