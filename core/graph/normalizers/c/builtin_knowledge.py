"""C 语言内置函数数据流知识库。

格式与 PHP builtin_knowledge 相同：
{"函数名": {"passthrough": [参数位置列表], "safe": bool, "param_flow": dict}}

param_flow: {输出参数索引: [输入参数索引列表]}
  - 表示数据从哪些输入参数流入指定的输出参数
  - 值可以是 int（单参数）或 list（多参数合并）
  - 例如 snprintf: arg[3+] 的值通过 format 写入 arg[0]
"""

C_BUILTIN_KNOWLEDGE: dict = {
    # === 格式化输出到缓冲区 ===
    # snprintf(buf, size, fmt, ...) → format args 流入 buf
    "snprintf":   {"passthrough": [], "safe": False, "param_flow": {0: [2, 3]}},
    "sprintf":    {"passthrough": [], "safe": False, "param_flow": {0: [1, 2]}},
    # vsnprintf/vsprintf — va_list 版本，暂不处理

    # === 字符串拷贝 ===
    # strcpy(dst, src) → src 流入 dst
    "strcpy":     {"passthrough": [], "safe": False, "param_flow": {0: 1}},
    "strncpy":    {"passthrough": [], "safe": False, "param_flow": {0: 1}},
    "strcat":     {"passthrough": [], "safe": False, "param_flow": {0: [0, 1]}},
    "strncat":    {"passthrough": [], "safe": False, "param_flow": {0: [0, 1]}},

    # === 内存操作 ===
    # memcpy(dst, src, n) → src 流入 dst
    "memcpy":     {"passthrough": [], "safe": False, "param_flow": {0: 1}},
    "memmove":    {"passthrough": [], "safe": False, "param_flow": {0: 1}},
    "memset":     {"passthrough": [], "safe": True, "param_flow": {0: 1}},

    # === 字符串转换 ===
    # atoi(str) → 返回值依赖 str
    "atoi":       {"passthrough": [0], "safe": True},
    "atol":       {"passthrough": [0], "safe": True},
    "atof":       {"passthrough": [0], "safe": True},
    "strtol":     {"passthrough": [0], "safe": True},
    "strtoul":    {"passthrough": [0], "safe": True},
    "strtof":     {"passthrough": [0], "safe": True},

    # === 文件操作 ===
    # fopen(path, mode) → path 流入返回的 FILE*
    "fopen":      {"passthrough": [0], "safe": False},

    # === 系统命令 ===
    # system(cmd) → cmd 直接作为 sink 参数
    "system":     {"passthrough": [0], "safe": False},
    "popen":      {"passthrough": [0], "safe": False},

    # === 安全过滤函数 ===
    "strlen":     {"passthrough": [], "safe": True},
    "strcmp":     {"passthrough": [], "safe": True},
    "strncmp":    {"passthrough": [], "safe": True},
}
