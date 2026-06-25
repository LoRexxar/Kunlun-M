"""
Case 43: C 跨作用域 — 全局变量（非函数指针）在函数内引用
全局 cmd 变量赋值为 argv[1]，函数内通过参数传递使用
预期: 检出 CVI-9001
"""
#include <stdlib.h>

char *global_cmd;

void execute(char *command) {
    system(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    global_cmd = argv[1];
    execute(global_cmd);
    return 0;
}
