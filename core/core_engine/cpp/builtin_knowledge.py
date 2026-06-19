# -*- coding: utf-8 -*-
# @Time    : 2025
# @Author  : KunLun-M
# @File    : builtin_knowledge.py

"""
    C/C++ 内置函数知识库
    ~~~~
    字段说明:
    - passthrough: list[int]  返回值依赖哪些参数位置（0-indexed）
                               [] = 返回值与输入无关
    - safe: bool              函数是否做了安全过滤，返回值不再构成威胁
    - param_flow: dict        参数间数据流，{输出参数索引: 输入参数索引}
                               值可以是 int（参数位置）或 str（隐式源如 "stdin"/"network"）
                               表示调用后，输出参数获得了输入参数的数据
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

KNOWLEDGE = {
    # ============ 字符串处理 ============
    # 返回值透传
    "strlen":  {"passthrough": [], "safe": True},
    "strdup":  {"passthrough": [0], "safe": False},
    "strndup": {"passthrough": [0], "safe": False},
    "strstr":  {"passthrough": [0, 1], "safe": False},
    "strtok":  {"passthrough": [0], "safe": False},
    "strsep":  {"passthrough": [0], "safe": False},
    "strchr":  {"passthrough": [0], "safe": False},
    "strrchr": {"passthrough": [0], "safe": False},
    "strpbrk": {"passthrough": [0, 1], "safe": False},
    "strcmp":  {"passthrough": [], "safe": True},
    "strncmp": {"passthrough": [], "safe": True},
    "strcasecmp": {"passthrough": [], "safe": True},
    "strncasecmp": {"passthrough": [], "safe": True},
    "strspn":  {"passthrough": [], "safe": True},
    "strcspn": {"passthrough": [], "safe": True},
    "strtok_r": {"passthrough": [0], "safe": False},
    "memchr":  {"passthrough": [0], "safe": False},

    # 参数间数据流
    "strcpy":  {"passthrough": [0], "safe": False, "param_flow": {0: 1}},
    "strncpy": {"passthrough": [0], "safe": False, "param_flow": {0: 1}},
    "strcat":  {"passthrough": [0], "safe": False, "param_flow": {0: 1}},
    "strncat": {"passthrough": [0], "safe": False, "param_flow": {0: 1}},
    "memcpy":  {"passthrough": [0], "safe": False, "param_flow": {0: 1}},
    "memmove": {"passthrough": [0], "safe": False, "param_flow": {0: 1}},
    "memset":  {"passthrough": [], "safe": True},
    "memcmp":  {"passthrough": [], "safe": True},

    # ============ 格式化输出/输入 ============
    "sprintf":  {"passthrough": [], "safe": False, "param_flow": {0: 1}},
    "snprintf": {"passthrough": [], "safe": False, "param_flow": {0: 1}},
    "printf":   {"passthrough": [], "safe": True},
    "fprintf":  {"passthrough": [], "safe": True},
    "scanf":  {"passthrough": [], "safe": False, "param_flow": {1: "stdin", 2: "stdin", 3: "stdin"}},
    "fscanf": {"passthrough": [], "safe": False, "param_flow": {2: 0}},
    "sscanf": {"passthrough": [], "safe": False, "param_flow": {2: 0}},

    # ============ 类型转换 ============
    "atoi":     {"passthrough": [0], "safe": False},
    "atol":     {"passthrough": [0], "safe": False},
    "atof":     {"passthrough": [0], "safe": False},
    "strtol":   {"passthrough": [0], "safe": False},
    "strtoul":  {"passthrough": [0], "safe": False},
    "strtod":   {"passthrough": [0], "safe": False},
    "strtof":   {"passthrough": [0], "safe": False},
    "strtoll":  {"passthrough": [0], "safe": False},
    "strtoull": {"passthrough": [0], "safe": False},
    "strtoq":   {"passthrough": [0], "safe": False},
    "strtouq":  {"passthrough": [0], "safe": False},

    # ============ 内存分配 ============
    "malloc":  {"passthrough": [], "safe": True},
    "calloc":  {"passthrough": [], "safe": True},
    "realloc": {"passthrough": [], "safe": True},
    "free":    {"passthrough": [], "safe": True},
    "alloca":  {"passthrough": [], "safe": True},

    # ============ 安全/修复函数 ============
    "mysql_real_escape_string": {"passthrough": [], "safe": True, "param_flow": {0: 1}},
    "PQescapeString":     {"passthrough": [], "safe": True, "param_flow": {0: 1}},
    "PQescapeLiteral":    {"passthrough": [], "safe": True, "param_flow": {0: 1}},
    "PQescapeByteaConn":  {"passthrough": [], "safe": True, "param_flow": {0: 1}},
    "sqlite3_bind_text":  {"passthrough": [], "safe": True},
    "sqlite3_bind_parameter_index": {"passthrough": [], "safe": True},
    "sqlite3_mprintf":   {"passthrough": [], "safe": True},
    "sqlite3_vmprintf":  {"passthrough": [], "safe": True},
    "sqlite3_snprintf":  {"passthrough": [], "safe": True, "param_flow": {0: 1}},
    "addslashes":         {"passthrough": [], "safe": True},
    "mysql_escape_string": {"passthrough": [], "safe": True},
    "pg_escape_string":   {"passthrough": [], "safe": True},
    "sqlite3_escape":      {"passthrough": [], "safe": True},

    # ============ 终止函数 ============
    "exit":      {"passthrough": [], "safe": True},
    "abort":     {"passthrough": [], "safe": True},
    "_exit":     {"passthrough": [], "safe": True},
    "quick_exit":{"passthrough": [], "safe": True},

    # ============ I/O 函数 ============
    "fgets":   {"passthrough": [], "safe": False, "param_flow": {0: 2}},
    "gets":    {"passthrough": [], "safe": False, "param_flow": {0: "stdin"}},
    "getline": {"passthrough": [], "safe": False, "param_flow": {0: 2}},
    "fread":   {"passthrough": [], "safe": False, "param_flow": {0: 3}},
    "fwrite":  {"passthrough": [], "safe": True},
    "fputs":   {"passthrough": [], "safe": True},
    "puts":    {"passthrough": [], "safe": True},
    "fputc":   {"passthrough": [], "safe": True},
    "putchar": {"passthrough": [], "safe": True},
    "fgetc":   {"passthrough": [], "safe": True},
    "getc":    {"passthrough": [], "safe": True},
    "getchar": {"passthrough": [], "safe": True},
    "ungetc":  {"passthrough": [], "safe": True},
    "read":    {"passthrough": [], "safe": False, "param_flow": {1: 0}},
    "write":   {"passthrough": [], "safe": True},
    "close":   {"passthrough": [], "safe": True},
    "recv":     {"passthrough": [], "safe": False, "param_flow": {1: 0}},
    "recvfrom": {"passthrough": [], "safe": False, "param_flow": {1: 0}},
    "send":     {"passthrough": [], "safe": True},
    "sendto":   {"passthrough": [], "safe": True},

    # ============ stdio.h 其他 ============
    "fopen":     {"passthrough": [], "safe": True},
    "fclose":    {"passthrough": [], "safe": True},
    "fseek":     {"passthrough": [], "safe": True},
    "ftell":     {"passthrough": [], "safe": True},
    "rewind":    {"passthrough": [], "safe": True},
    "feof":      {"passthrough": [], "safe": True},
    "ferror":    {"passthrough": [], "safe": True},
    "clearerr":  {"passthrough": [], "safe": True},
    "fflush":    {"passthrough": [], "safe": True},
    "setbuf":    {"passthrough": [], "safe": True},
    "setvbuf":   {"passthrough": [], "safe": True},
    "popen":     {"passthrough": [], "safe": True},
    "pclose":    {"passthrough": [], "safe": True},
    "tmpfile":   {"passthrough": [], "safe": True},
    "tmpnam":    {"passthrough": [], "safe": True},
    "remove":    {"passthrough": [], "safe": True},
    "rename":    {"passthrough": [], "safe": True},
    "getline_r": {"passthrough": [], "safe": False, "param_flow": {0: 2}},

    # ============ stdlib.h 其他 ============
    "atexit":  {"passthrough": [], "safe": True},
    "rand":    {"passthrough": [], "safe": True},
    "srand":   {"passthrough": [], "safe": True},
    "abs":     {"passthrough": [], "safe": True},
    "labs":    {"passthrough": [], "safe": True},
    "div":     {"passthrough": [], "safe": True},
    "ldiv":    {"passthrough": [], "safe": True},
    "qsort":   {"passthrough": [], "safe": True},
    "bsearch": {"passthrough": [], "safe": True},
    "getenv":  {"passthrough": [], "safe": False},
    "system":  {"passthrough": [], "safe": False},

    # ============ ctype.h ============
    "isalpha":   {"passthrough": [], "safe": True},
    "isdigit":   {"passthrough": [], "safe": True},
    "isalnum":   {"passthrough": [], "safe": True},
    "isspace":   {"passthrough": [], "safe": True},
    "isupper":   {"passthrough": [], "safe": True},
    "islower":   {"passthrough": [], "safe": True},
    "ispunct":   {"passthrough": [], "safe": True},
    "isprint":   {"passthrough": [], "safe": True},
    "isgraph":   {"passthrough": [], "safe": True},
    "iscntrl":   {"passthrough": [], "safe": True},
    "isxdigit":  {"passthrough": [], "safe": True},
    "toupper":   {"passthrough": [0], "safe": True},
    "tolower":   {"passthrough": [0], "safe": True},

    # ============ math.h ============
    "sin":    {"passthrough": [], "safe": True},
    "cos":    {"passthrough": [], "safe": True},
    "tan":    {"passthrough": [], "safe": True},
    "asin":   {"passthrough": [], "safe": True},
    "acos":   {"passthrough": [], "safe": True},
    "atan":   {"passthrough": [], "safe": True},
    "atan2":  {"passthrough": [], "safe": True},
    "sqrt":   {"passthrough": [], "safe": True},
    "pow":    {"passthrough": [], "safe": True},
    "exp":    {"passthrough": [], "safe": True},
    "log":    {"passthrough": [], "safe": True},
    "log10":  {"passthrough": [], "safe": True},
    "ceil":   {"passthrough": [], "safe": True},
    "floor":  {"passthrough": [], "safe": True},
    "fabs":   {"passthrough": [], "safe": True},
    "fmod":   {"passthrough": [], "safe": True},

    # ============ unistd.h (POSIX) ============
    "dup":       {"passthrough": [], "safe": True},
    "dup2":      {"passthrough": [], "safe": True},
    "pipe":      {"passthrough": [], "safe": True},
    "fork":      {"passthrough": [], "safe": True},
    "execvp":    {"passthrough": [], "safe": False},
    "execv":     {"passthrough": [], "safe": False},
    "execl":     {"passthrough": [], "safe": False},
    "execlp":    {"passthrough": [], "safe": False},
    "execle":    {"passthrough": [], "safe": False},
    "execvpe":   {"passthrough": [], "safe": False},
    "fexecve":   {"passthrough": [], "safe": False},
    "execve":    {"passthrough": [], "safe": False},
    "getpid":    {"passthrough": [], "safe": True},
    "getppid":   {"passthrough": [], "safe": True},
    "getuid":    {"passthrough": [], "safe": True},
    "getgid":    {"passthrough": [], "safe": True},
    "chdir":     {"passthrough": [], "safe": True},
    "getcwd":    {"passthrough": [0], "safe": True},
    "sleep":     {"passthrough": [], "safe": True},
    "usleep":    {"passthrough": [], "safe": True},
    "alarm":     {"passthrough": [], "safe": True},
    "access":    {"passthrough": [], "safe": False},
    "posix_spawn":  {"passthrough": [], "safe": True},
    "posix_spawnp": {"passthrough": [], "safe": True},

    # ============ signal.h ============
    "signal": {"passthrough": [], "safe": True},
    "raise":  {"passthrough": [], "safe": True},
    "kill":   {"passthrough": [], "safe": True},

    # ============ socket ============
    "socket":     {"passthrough": [], "safe": True},
    "bind":       {"passthrough": [], "safe": True},
    "listen":     {"passthrough": [], "safe": True},
    "accept":     {"passthrough": [], "safe": True},
    "connect":    {"passthrough": [], "safe": True},
    "shutdown":   {"passthrough": [], "safe": True},
    "setsockopt": {"passthrough": [], "safe": True},
    "getsockopt": {"passthrough": [], "safe": True},

    # ============ netdb.h ============
    "gethostbyname":  {"passthrough": [], "safe": True},
    "gethostbyaddr":  {"passthrough": [], "safe": True},
    "getaddrinfo":    {"passthrough": [], "safe": True},
    "freeaddrinfo":   {"passthrough": [], "safe": True},
    "getnameinfo":    {"passthrough": [], "safe": True},

    # ============ pthread ============
    "pthread_create":         {"passthrough": [], "safe": True},
    "pthread_join":            {"passthrough": [], "safe": True},
    "pthread_detach":          {"passthrough": [], "safe": True},
    "pthread_mutex_lock":      {"passthrough": [], "safe": True},
    "pthread_mutex_unlock":    {"passthrough": [], "safe": True},
    "pthread_mutex_init":      {"passthrough": [], "safe": True},
    "pthread_cond_wait":       {"passthrough": [], "safe": True},
    "pthread_cond_signal":     {"passthrough": [], "safe": True},
    "pthread_cond_broadcast":  {"passthrough": [], "safe": True},

    # ============ time.h ============
    "time":      {"passthrough": [], "safe": True},
    "clock":     {"passthrough": [], "safe": True},
    "difftime":  {"passthrough": [], "safe": True},
    "mktime":    {"passthrough": [], "safe": True},
    "strftime":  {"passthrough": [], "safe": True},
    "localtime": {"passthrough": [], "safe": True},
    "gmtime":    {"passthrough": [], "safe": True},
    "asctime":   {"passthrough": [], "safe": True},
    "ctime":     {"passthrough": [], "safe": True},
}


def lookup(func_name: str):
    """查询 C/C++ 内置函数知识库。

    支持精确匹配和 C++ :: 短名匹配。

    :param func_name: 函数/方法名（如 "strcpy" 或 "std::strcpy"）
    :returns: dict or None
    """
    if func_name in KNOWLEDGE:
        return KNOWLEDGE[func_name]
    # C++ 命名空间短名匹配
    if "::" in func_name:
        short_name = func_name.split("::")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]
    return None
