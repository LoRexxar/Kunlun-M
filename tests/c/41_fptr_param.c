"""
Case 41: C 跨作用域 — 函数参数是函数指针
外部将 system 传给 wrapper 函数，wrapper 通过函数指针调用
预期: 检出 CVI-9001
"""
#include <stdlib.h>

void executor(int (*op)(const char *), char *arg) {
    op(arg);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    executor(system, argv[1]);
    return 0;
}
