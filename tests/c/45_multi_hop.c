"""
Case 45: C 跨作用域 — 多层函数指针传递
global_func = system → main 内赋值给 local_func → 传给 wrapper → wrapper 调用
预期: 检出 CVI-9001
"""
#include <stdlib.h>

int (*global_func)(const char *) = system;

void wrapper(int (*op)(const char *), char *arg) {
    op(arg);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    int (*local_func)(const char *) = global_func;
    wrapper(local_func, argv[1]);
    return 0;
}
