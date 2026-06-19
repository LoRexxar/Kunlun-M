"""
LUA 内置函数/方法可控性知识库

为静态分析引擎提供 Lua 内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
      [] 表示返回值与输入参数无关（如 len() 返回整数）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
    - param_flow: 参数间数据流映射 {输出参数索引: 输入参数索引}（可选）。
"""
from typing import Dict, List, Optional, Union

KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {

    # ================================================================
    #  SOURCES — 用户可控输入（返回值不安全，透传参数）
    # ================================================================

    # ===== os / io Sources =====
    "os.getenv":                 {"passthrough": [0], "safe": False},
    "os.clock":                  {"passthrough": [], "safe": True},
    "os.time":                   {"passthrough": [], "safe": True},
    "os.date":                   {"passthrough": [], "safe": True},
    "os.tmpname":                {"passthrough": [], "safe": False},

    "io.read":                   {"passthrough": [0], "safe": False},
    "io.lines":                  {"passthrough": [0], "safe": False},
    "io.stdin":                  {"passthrough": [], "safe": False},
    "io.open":                   {"passthrough": [0], "safe": False},
    "io.input":                  {"passthrough": [0], "safe": False},
    "io.output":                 {"passthrough": [0], "safe": False},

    # ===== 网络请求 Sources =====
    "http.request":              {"passthrough": [0], "safe": False},
    "socket.tcp":                {"passthrough": [0], "safe": False},
    "socket.udp":                {"passthrough": [0], "safe": False},
    "socket.connect":            {"passthrough": [0], "safe": False},

    # ===== JSON 解码 =====
    "json.decode":               {"passthrough": [0], "safe": False},
    "json.encode":               {"passthrough": [0], "safe": False},
    "cjson.decode":              {"passthrough": [0], "safe": False},
    "cjson.encode":              {"passthrough": [0], "safe": False},

    # ================================================================
    #  SINKS — 危险操作（标记为不安全）
    # ================================================================

    # ===== os.execute / io.popen — 命令注入 =====
    "os.execute":                {"passthrough": [0], "safe": False},
    "io.popen":                  {"passthrough": [0], "safe": False},

    # ===== io.open — 路径遍历 =====
    "io.open":                   {"passthrough": [0], "safe": False},

    # ===== os.remove / os.rename — 文件操作 =====
    "os.remove":                 {"passthrough": [0], "safe": False},
    "os.rename":                 {"passthrough": [0], "safe": False},

    # ================================================================
    #  字符串操作（透传，不安全）
    # ================================================================

    "string.format":             {"passthrough": [0, 1], "safe": False},
    "string.sub":                {"passthrough": [0], "safe": False},
    "string.rep":                {"passthrough": [0], "safe": False},
    "string.reverse":            {"passthrough": [0], "safe": False},
    "string.upper":              {"passthrough": [0], "safe": False},
    "string.lower":              {"passthrough": [0], "safe": False},
    "string.len":                {"passthrough": [0], "safe": True},
    "string.gsub":               {"passthrough": [0, 1], "safe": False},
    "string.find":               {"passthrough": [], "safe": True},
    "string.match":              {"passthrough": [], "safe": True},
    "string.gmatch":             {"passthrough": [], "safe": True},
    "string.gfind":              {"passthrough": [], "safe": True},
    "string.byte":               {"passthrough": [0], "safe": False},
    "string.char":               {"passthrough": [0], "safe": False},
    "string.dump":               {"passthrough": [0], "safe": False},
    "string.trim":               {"passthrough": [0], "safe": False},

    # ================================================================
    #  Table 操作
    # ================================================================

    "table.insert":             {"passthrough": [0, 1], "safe": False},
    "table.remove":             {"passthrough": [0], "safe": False},
    "table.concat":             {"passthrough": [0], "safe": False},
    "table.sort":                {"passthrough": [0], "safe": False},
    "table.unpack":             {"passthrough": [0], "safe": False},
    "table.move":                {"passthrough": [0], "safe": False},

    # ================================================================
    #  数学操作（安全）
    # ================================================================

    "math.abs":                  {"passthrough": [], "safe": True},
    "math.ceil":                 {"passthrough": [], "safe": True},
    "math.floor":                {"passthrough": [], "safe": True},
    "math.max":                  {"passthrough": [], "safe": True},
    "math.min":                  {"passthrough": [], "safe": True},
    "math.sqrt":                 {"passthrough": [], "safe": True},
    "math.tointeger":            {"passthrough": [], "safe": True},
    "math.type":                 {"passthrough": [], "safe": True},
    "tonumber":                  {"passthrough": [], "safe": True},
    "tostring":                  {"passthrough": [0], "safe": False},
    "type":                      {"passthrough": [], "safe": True},
    "print":                     {"passthrough": [0], "safe": False},
    "error":                     {"passthrough": [0], "safe": False},
    "assert":                    {"passthrough": [0], "safe": False},
    "pcall":                     {"passthrough": [0], "safe": False},
    "xpcall":                    {"passthrough": [0], "safe": False},
    "select":                    {"passthrough": [0], "safe": False},
    "unpack":                    {"passthrough": [0], "safe": False},
    "pairs":                     {"passthrough": [], "safe": True},
    "ipairs":                    {"passthrough": [], "safe": True},
    "next":                      {"passthrough": [], "safe": True},
    "rawget":                    {"passthrough": [0], "safe": False},
    "rawset":                    {"passthrough": [0], "safe": False},
    "require":                   {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """查询函数可控性知识。

    尝试精确匹配，然后按简短名称匹配。

    :param func_name: 函数名（可以带模块前缀如 string.format）
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
