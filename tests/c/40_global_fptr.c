"""
Case 36: C 跨作用域 — 全局函数指针在函数内调用
全局声明函数指针，在 main 中调用
预期: 检出 CVI-9001
"""
#include <stdlib.h>

int (*global_func)(const char *) = system;

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    global_func(argv[1]);
    return 0;
}
