"""
KOTLIN 内置函数/方法可控性知识库

为静态分析引擎提供 Kotlin 内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
      [] 表示返回值与输入参数无关（如 length() 返回整数）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
    - param_flow: 参数间数据流映射 {输出参数索引: 输入参数索引}（可选）。
"""
from typing import Dict, List, Optional, Union

KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {

    # ================================================================
    #  SOURCES — 用户可控输入（返回值不安全，透传参数）
    # ================================================================

    # ===== 命令行/标准输入 Sources =====
    "readLine":                   {"passthrough": [], "safe": False},
    "readln":                    {"passthrough": [], "safe": False},
    "readlnOrNull":              {"passthrough": [], "safe": False},

    # ===== System Sources =====
    "System.getenv":             {"passthrough": [0], "safe": False},
    "System.getProperty":         {"passthrough": [0], "safe": False},

    # ===== Java IO Sources =====
    "java.io.BufferedReader.readLine":     {"passthrough": [0], "safe": False},
    "java.io.FileReader":                  {"passthrough": [0], "safe": False},
    "java.io.FileInputStream":             {"passthrough": [0], "safe": False},
    "java.util.Scanner.nextLine":          {"passthrough": [0], "safe": False},
    "Scanner.nextLine":                    {"passthrough": [0], "safe": False},

    # ===== 网络 Sources =====
    "java.net.URL":              {"passthrough": [0], "safe": False},
    "java.net.HttpURLConnection": {"passthrough": [0], "safe": False},

    # ===== 编码解析 Sources =====
    "org.json.JSONObject":        {"passthrough": [0], "safe": False},
    "com.google.gson.Gson":       {"passthrough": [0], "safe": False},

    # ================================================================
    #  Ktor 框架 Sources
    # ================================================================
    "call.receive":               {"passthrough": [0], "safe": False},
    "call.receiveText":           {"passthrough": [0], "safe": False},
    "call.receiveParameters":     {"passthrough": [0], "safe": False},
    "call.parameters":            {"passthrough": [0], "safe": False},
    "call.request":               {"passthrough": [0], "safe": False},

    # ================================================================
    #  Spring Boot 框架 Sources
    # ================================================================
    "HttpServletRequest.getParameter":     {"passthrough": [0], "safe": False},
    "HttpServletRequest.getHeader":        {"passthrough": [0], "safe": False},
    "HttpServletRequest.getInputStream":  {"passthrough": [0], "safe": False},
    "HttpServletRequest.getReader":       {"passthrough": [0], "safe": False},

    # ================================================================
    #  SINKS — 危险操作（标记为不安全）
    # ================================================================

    # ===== 命令注入 =====
    "Runtime.getRuntime":         {"passthrough": [0], "safe": False},
    "Runtime.exec":               {"passthrough": [0], "safe": False},
    "ProcessBuilder":             {"passthrough": [0], "safe": False},
    "ProcessBuilder.command":     {"passthrough": [0], "safe": False},
    "ProcessBuilder.start":       {"passthrough": [0], "safe": False},

    # ===== 文件操作 — 路径遍历 =====
    "java.io.File":               {"passthrough": [0], "safe": False},
    "java.io.FileOutputStream":   {"passthrough": [0], "safe": False},
    "java.io.FileWriter":          {"passthrough": [0], "safe": False},

    # ===== 网络 SSRF =====
    "java.net.URL":               {"passthrough": [0], "safe": False},
    "java.net.HttpURLConnection":  {"passthrough": [0], "safe": False},
    "java.net.Socket":            {"passthrough": [0], "safe": False},

    # ===== 反射 =====
    "java.lang.reflect.Method.invoke":  {"passthrough": [0], "safe": False},
    "Class.forName":              {"passthrough": [0], "safe": False},

    # ===== SQL 注入 =====
    "java.sql.Statement.executeQuery":   {"passthrough": [0], "safe": False},
    "java.sql.Statement.executeUpdate":  {"passthrough": [0], "safe": False},
    "java.sql.Connection.prepareStatement": {"passthrough": [0], "safe": False},
    "createQuery":                {"passthrough": [0], "safe": False},

    # ===== 输出（可能 XSS）=====
    "println":                    {"passthrough": [0], "safe": False},
    "print":                      {"passthrough": [0], "safe": False},

    # ================================================================
    #  字符串操作（透传，不安全）
    # ================================================================

    # ===== String 方法 =====
    "String.trim":                {"passthrough": [0], "safe": False},
    "String.trimStart":           {"passthrough": [0], "safe": False},
    "String.trimEnd":             {"passthrough": [0], "safe": False},
    "String.replace":             {"passthrough": [0, 1], "safe": False},
    "String.substring":           {"passthrough": [0], "safe": False},
    "String.lowercase":           {"passthrough": [0], "safe": False},
    "String.uppercase":           {"passthrough": [0], "safe": False},
    "String.plus":                {"passthrough": [0], "safe": False},
    "String.toString":            {"passthrough": [0], "safe": False},

    # ===== Kotlin 扩展 =====
    "trim":                       {"passthrough": [0], "safe": False},
    "trimStart":                  {"passthrough": [0], "safe": False},
    "trimEnd":                    {"passthrough": [0], "safe": False},
    "replace":                    {"passthrough": [0, 1], "safe": False},
    "substring":                  {"passthrough": [0], "safe": False},
    "lowercase":                  {"passthrough": [0], "safe": False},
    "uppercase":                  {"passthrough": [0], "safe": False},
    "capitalize":                 {"passthrough": [0], "safe": False},
    "decapitalize":               {"passthrough": [0], "safe": False},
    "reversed":                   {"passthrough": [0], "safe": False},
    "split":                      {"passthrough": [0], "safe": False},
    "toList":                     {"passthrough": [0], "safe": False},
    "toByteArray":               {"passthrough": [0], "safe": False},
    "toCharArray":               {"passthrough": [0], "safe": False},
    "toInt":                      {"passthrough": [], "safe": True},
    "toLong":                     {"passthrough": [], "safe": True},
    "toDouble":                   {"passthrough": [], "safe": True},
    "toFloat":                    {"passthrough": [], "safe": True},
    "toBoolean":                  {"passthrough": [], "safe": True},
    "toIntOrNull":               {"passthrough": [], "safe": True},
    "toLongOrNull":              {"passthrough": [], "safe": True},

    # ================================================================
    #  安全函数（safe=True）
    # ================================================================

    "length":                     {"passthrough": [], "safe": True},
    "count":                      {"passthrough": [], "safe": True},
    "isEmpty":                    {"passthrough": [], "safe": True},
    "isBlank":                    {"passthrough": [], "safe": True},
    "isNotEmpty":                 {"passthrough": [], "safe": True},
    "isNotBlank":                 {"passthrough": [], "safe": True},
    "contains":                   {"passthrough": [], "safe": True},
    "startsWith":                 {"passthrough": [], "safe": True},
    "endsWith":                   {"passthrough": [], "safe": True},
    "matches":                    {"passthrough": [], "safe": True},
    "equals":                     {"passthrough": [], "safe": True},
    "hashCode":                   {"passthrough": [], "safe": True},
    "toInt":                      {"passthrough": [], "safe": True},
    "toLong":                     {"passthrough": [], "safe": True},
    "toDouble":                   {"passthrough": [], "safe": True},
    "toFloat":                    {"passthrough": [], "safe": True},
    "toBoolean":                  {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """查询函数可控性知识。

    尝试精确匹配，然后按简短名称匹配。

    :param func_name: 函数名（可以带包前缀如 java.io.File）
    :return: 知识字典或 None
    """
    if not func_name:
        return None

    # 精确匹配
    result = KNOWLEDGE.get(func_name)
    if result:
        return result

    # 短名称匹配（取最后一个 . 之后的部分）
    if '.' in func_name:
        short_name = func_name.split('.')[-1]
        result = KNOWLEDGE.get(short_name)
        if result:
            return result

    return None


def is_safe(func_name: str) -> bool:
    """检查函数是否安全（返回值经过有效过滤）。"""
    knowledge = lookup(func_name)
    if knowledge:
        return knowledge.get('safe', False)
    return False


def get_passthrough(func_name: str) -> List[int]:
    """获取函数的 passthrough 参数位置列表。"""
    knowledge = lookup(func_name)
    if knowledge:
        pts = knowledge.get('passthrough', [])
        return pts if pts else []
    return []
