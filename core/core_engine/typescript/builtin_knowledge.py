"""
TypeScript 内置函数/方法可控性知识库

为静态分析引擎提供 TypeScript 内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

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

    # ===== Node.js / DOM Sources =====
    "process.env":          {"passthrough": [0], "safe": False},
    "process.argv":         {"passthrough": [], "safe": False},

    # ===== Express / Connect Framework =====
    "req.query":            {"passthrough": [0], "safe": False},
    "req.body":             {"passthrough": [0], "safe": False},
    "req.params":           {"passthrough": [0], "safe": False},
    "req.headers":           {"passthrough": [0], "safe": False},
    "req.cookies":          {"passthrough": [0], "safe": False},
    "req.url":              {"passthrough": [0], "safe": False},
    "req.get":              {"passthrough": [0], "safe": False},
    "req.param":            {"passthrough": [0], "safe": False},
    "req.header":           {"passthrough": [0], "safe": False},
    "req.cookie":           {"passthrough": [0], "safe": False},
    "request.query":        {"passthrough": [0], "safe": False},
    "request.body":         {"passthrough": [0], "safe": False},
    "request.params":       {"passthrough": [0], "safe": False},
    "request.headers":       {"passthrough": [0], "safe": False},

    # ===== Koa Framework =====
    "ctx.query":            {"passthrough": [0], "safe": False},
    "ctx.querystring":      {"passthrough": [0], "safe": False},
    "ctx.params":           {"passthrough": [0], "safe": False},
    "ctx.request.body":     {"passthrough": [0], "safe": False},
    "ctx.request.query":    {"passthrough": [0], "safe": False},
    "ctx.get":              {"passthrough": [0], "safe": False},

    # ===== NestJS / Fastify =====
    "@Body":                {"passthrough": [0], "safe": False},
    "@Query":               {"passthrough": [0], "safe": False},
    "@Param":               {"passthrough": [0], "safe": False},
    "@Headers":             {"passthrough": [0], "safe": False},

    # ===== Browser DOM =====
    "document.cookie":      {"passthrough": [0], "safe": False},
    "location.hash":        {"passthrough": [0], "safe": False},
    "location.search":      {"passthrough": [0], "safe": False},
    "location.href":        {"passthrough": [0], "safe": False},
    "window.name":          {"passthrough": [0], "safe": False},
    "window.location":      {"passthrough": [0], "safe": False},

    # ===== URL 解析 =====
    "URL":                  {"passthrough": [0], "safe": False},
    "URLSearchParams":       {"passthrough": [0], "safe": False},
    "url.parse":            {"passthrough": [0], "safe": False},
    "url.format":           {"passthrough": [0], "safe": False},
    "new URL":              {"passthrough": [0], "safe": False},

    # ===== HTTP 请求 =====
    "fetch":                {"passthrough": [0], "safe": False},
    "axios.get":            {"passthrough": [0], "safe": False},
    "axios.post":           {"passthrough": [0, 1], "safe": False},
    "axios.request":        {"passthrough": [0], "safe": False},
    "http.request":         {"passthrough": [0], "safe": False},
    "https.request":        {"passthrough": [0], "safe": False},
    "XMLHttpRequest.open":  {"passthrough": [0], "safe": False},

    # ================================================================
    #  SINKS — 危险操作（标记为不安全）
    # ================================================================

    # ===== XSS 相关 =====
    "eval":                 {"passthrough": [0], "safe": False},
    "Function":             {"passthrough": [0], "safe": False},
    "setTimeout":           {"passthrough": [0], "safe": False},
    "setInterval":          {"passthrough": [0], "safe": False},
    "innerHTML":            {"passthrough": [0], "safe": False},
    "outerHTML":            {"passthrough": [0], "safe": False},
    "document.write":       {"passthrough": [0], "safe": False},
    "document.writeln":     {"passthrough": [0], "safe": False},
    "insertAdjacentHTML":   {"passthrough": [1], "safe": False},
    "document.createElement": {"passthrough": [0], "safe": False},
    "element.setAttribute": {"passthrough": [1], "safe": False},
    "$":                    {"passthrough": [0], "safe": False},
    "jQuery":               {"passthrough": [0], "safe": False},
    ".html":                {"passthrough": [0], "safe": False},
    ".append":              {"passthrough": [0], "safe": False},
    ".prepend":             {"passthrough": [0], "safe": False},
    ".after":               {"passthrough": [0], "safe": False},
    ".before":              {"passthrough": [0], "safe": False},
    ".replaceWith":         {"passthrough": [0], "safe": False},

    # ===== 命令注入 =====
    "child_process.exec":       {"passthrough": [0], "safe": False},
    "child_process.spawn":     {"passthrough": [0], "safe": False},
    "child_process.execSync":   {"passthrough": [0], "safe": False},
    "child_process.spawnSync":  {"passthrough": [0], "safe": False},
    "child_process.execFile":  {"passthrough": [0], "safe": False},
    "exec":                 {"passthrough": [0], "safe": False},
    "execSync":             {"passthrough": [0], "safe": False},
    "spawn":                {"passthrough": [0], "safe": False},
    "spawnSync":            {"passthrough": [0], "safe": False},

    # ===== 文件操作 — 路径遍历 =====
    "fs.readFile":          {"passthrough": [0], "safe": False},
    "fs.readFileSync":      {"passthrough": [0], "safe": False},
    "fs.writeFile":         {"passthrough": [0], "safe": False},
    "fs.writeFileSync":     {"passthrough": [0], "safe": False},
    "fs.unlink":             {"passthrough": [0], "safe": False},
    "fs.unlinkSync":         {"passthrough": [0], "safe": False},
    "fs.mkdir":              {"passthrough": [0], "safe": False},
    "fs.rmdir":              {"passthrough": [0], "safe": False},
    "fs.readdir":             {"passthrough": [0], "safe": False},
    "fs.stat":               {"passthrough": [0], "safe": False},
    "fs.createReadStream":   {"passthrough": [0], "safe": False},
    "fs.createWriteStream":  {"passthrough": [0], "safe": False},
    "fs.access":             {"passthrough": [0], "safe": False},
    "fs.appendFile":         {"passthrough": [0], "safe": False},

    # ===== SQL 注入 =====
    "sequelize.query":      {"passthrough": [0], "safe": False},
    "knex.raw":             {"passthrough": [0], "safe": False},
    "mongoose.find":        {"passthrough": [0], "safe": False},
    "prisma.$queryRaw":      {"passthrough": [0], "safe": False},
    "pool.query":            {"passthrough": [0], "safe": False},
    "client.query":         {"passthrough": [0], "safe": False},
    "connection.query":      {"passthrough": [0], "safe": False},

    # ===== SSRF =====
    "axios.get":            {"passthrough": [0], "safe": False},
    "axios.post":           {"passthrough": [0, 1], "safe": False},
    "http.request":         {"passthrough": [0], "safe": False},
    "https.request":        {"passthrough": [0], "safe": False},
    "request":              {"passthrough": [0], "safe": False},
    "got":                  {"passthrough": [0], "safe": False},
    "node-fetch":           {"passthrough": [0], "safe": False},
    "superagent.get":       {"passthrough": [0], "safe": False},
    "superagent.post":      {"passthrough": [0, 1], "safe": False},

    # ===== Prototype Pollution =====
    "Object.assign":        {"passthrough": [0, 1], "safe": False},
    "lodash.merge":         {"passthrough": [0, 1], "safe": False},
    "lodash.set":           {"passthrough": [0, 1], "safe": False},
    "deepMerge":            {"passthrough": [0, 1], "safe": False},
    "_.merge":              {"passthrough": [0, 1], "safe": False},
    "_.set":                {"passthrough": [0, 1], "safe": False},

    # ===== 日志输出 =====
    "console.log":          {"passthrough": [0], "safe": False},
    "console.error":        {"passthrough": [0], "safe": False},
    "console.warn":         {"passthrough": [0], "safe": False},
    "console.info":         {"passthrough": [0], "safe": False},
    "console.debug":        {"passthrough": [0], "safe": False},
    "process.stdout.write": {"passthrough": [0], "safe": False},
    "process.stderr.write": {"passthrough": [0], "safe": False},

    # ===== Express 响应 =====
    "res.send":             {"passthrough": [0], "safe": False},
    "res.json":             {"passthrough": [0], "safe": False},
    "res.render":           {"passthrough": [0, 1], "safe": False},
    "res.redirect":         {"passthrough": [0], "safe": False},
    "response.send":        {"passthrough": [0], "safe": False},
    "response.json":        {"passthrough": [0], "safe": False},

    # ================================================================
    #  字符串操作（透传，不安全）
    # ================================================================

    # ===== String 方法 =====
    "String":               {"passthrough": [0], "safe": False},
    "String.trim":          {"passthrough": [0], "safe": False},
    "String.toLowerCase":    {"passthrough": [0], "safe": False},
    "String.toUpperCase":    {"passthrough": [0], "safe": False},
    "String.replace":       {"passthrough": [0, 1], "safe": False},
    "String.substring":      {"passthrough": [0], "safe": False},
    "String.slice":          {"passthrough": [0], "safe": False},
    "String.split":          {"passthrough": [0], "safe": False},
    "String.charAt":         {"passthrough": [0], "safe": False},
    "String.charCodeAt":     {"passthrough": [0], "safe": False},
    "String.concat":         {"passthrough": [0], "safe": False},
    "String.repeat":         {"passthrough": [0], "safe": False},
    "String.padStart":       {"passthrough": [0], "safe": False},
    "String.padEnd":         {"passthrough": [0], "safe": False},
    "String.includes":       {"passthrough": [0], "safe": False},
    "String.indexOf":        {"passthrough": [0], "safe": False},
    "String.match":          {"passthrough": [0], "safe": False},
    "String.search":         {"passthrough": [0], "safe": False},
    "String.valueOf":        {"passthrough": [0], "safe": False},
    "toString":              {"passthrough": [0], "safe": False},
    "trim":                  {"passthrough": [0], "safe": False},
    "trimStart":             {"passthrough": [0], "safe": False},
    "trimEnd":               {"passthrough": [0], "safe": False},
    "toLowerCase":           {"passthrough": [0], "safe": False},
    "toUpperCase":           {"passthrough": [0], "safe": False},
    "replace":               {"passthrough": [0, 1], "safe": False},
    "replaceAll":            {"passthrough": [0, 1], "safe": False},
    "substring":             {"passthrough": [0], "safe": False},
    "slice":                 {"passthrough": [0], "safe": False},
    "split":                 {"passthrough": [0], "safe": False},
    "concat":                {"passthrough": [0], "safe": False},
    "includes":              {"passthrough": [0], "safe": False},
    "indexOf":               {"passthrough": [0], "safe": False},
    "match":                 {"passthrough": [0], "safe": False},
    "search":                {"passthrough": [0], "safe": False},
    "padStart":              {"passthrough": [0], "safe": False},
    "padEnd":                {"passthrough": [0], "safe": False},

    # ===== Array 方法 =====
    "Array.from":           {"passthrough": [0], "safe": False},
    "Array.of":             {"passthrough": [], "safe": True},
    "Array.isArray":        {"passthrough": [0], "safe": True},
    "Array.join":           {"passthrough": [0], "safe": False},
    "map":                   {"passthrough": [0], "safe": False},
    "filter":                {"passthrough": [0], "safe": False},
    "reduce":                {"passthrough": [0], "safe": False},
    "forEach":               {"passthrough": [0], "safe": False},
    "find":                  {"passthrough": [0], "safe": False},
    "flat":                  {"passthrough": [0], "safe": False},
    "flatMap":               {"passthrough": [0], "safe": False},
    "concat":                {"passthrough": [0], "safe": False},
    "slice":                 {"passthrough": [0], "safe": False},
    "join":                  {"passthrough": [0], "safe": False},
    "push":                  {"passthrough": [0], "safe": False},
    "pop":                   {"passthrough": [], "safe": True},
    "shift":                 {"passthrough": [], "safe": True},
    "unshift":              {"passthrough": [0], "safe": False},
    "splice":               {"passthrough": [0], "safe": False},
    "reverse":              {"passthrough": [0], "safe": False},
    "sort":                 {"passthrough": [0], "safe": False},

    # ===== JSON =====
    "JSON.parse":           {"passthrough": [0], "safe": False},
    "JSON.stringify":       {"passthrough": [0], "safe": False},
    "JSON.stringify":       {"passthrough": [0], "safe": False},

    # ===== 编解码 =====
    "Buffer.from":          {"passthrough": [0], "safe": False},
    "Buffer.toString":      {"passthrough": [0], "safe": False},
    "btoa":                 {"passthrough": [0], "safe": False},
    "atob":                 {"passthrough": [0], "safe": False},
    "encodeURIComponent":  {"passthrough": [0], "safe": False},
    "decodeURIComponent":  {"passthrough": [0], "safe": False},
    "encodeURI":            {"passthrough": [0], "safe": False},
    "decodeURI":            {"passthrough": [0], "safe": False},

    # ===== 路径操作 =====
    "path.join":            {"passthrough": [0, 1], "safe": False},
    "path.resolve":         {"passthrough": [0], "safe": False},
    "path.normalize":       {"passthrough": [0], "safe": False},
    "path.extname":         {"passthrough": [0], "safe": False},
    "path.dirname":         {"passthrough": [0], "safe": False},
    "path.basename":        {"passthrough": [0], "safe": False},

    # ================================================================
    #  安全函数（safe=True）
    # ================================================================

    "parseInt":             {"passthrough": [], "safe": True},
    "parseFloat":           {"passthrough": [], "safe": True},
    "Number":               {"passthrough": [], "safe": True},
    "isNaN":                {"passthrough": [], "safe": True},
    "isFinite":             {"passthrough": [], "safe": True},
    "Number.isInteger":     {"passthrough": [], "safe": True},
    "Number.isFinite":      {"passthrough": [], "safe": True},
    "Number.isNaN":         {"passthrough": [], "safe": True},
    "String.length":        {"passthrough": [], "safe": True},
    "Array.isArray":        {"passthrough": [], "safe": True},
    "typeof":               {"passthrough": [], "safe": True},
    "Array.length":         {"passthrough": [], "safe": True},
    "Buffer.isBuffer":      {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """查询函数可控性知识。

    尝试精确匹配，然后按简短名称匹配。

    :param func_name: 函数名（可以带模块前缀如 req.query）
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
