"""
Case 42: C 跨作用域 — 函数返回函数指针
get_func 返回 system，main 接收后调用
预期: 检出 CVI-9001
"""
#include <stdlib.h>

int (*get_func(void))(const char *) {
    return system;
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    int (*func)(const char *) = get_func();
    func(argv[1]);
    return 0;
}
