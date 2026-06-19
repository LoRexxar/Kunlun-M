"""
RUBY 内置函数/方法可控性知识库

为静态分析引擎提供 Ruby 内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
      [] 表示返回值与输入参数无关（如 .length 返回整数）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
    - param_flow: 参数间数据流映射 {输出参数索引: 输入参数索引}（可选）。
"""
from typing import Dict, List, Optional, Union

KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {

    # ================================================================
    #  SOURCES — 用户可控输入（返回值不安全，透传参数）
    # ================================================================

    # ===== ENV / ARGV / STDIN Sources =====
    "ENV":                  {"passthrough": [], "safe": False},
    "gets":                 {"passthrough": [], "safe": False},
    "gets.chomp":          {"passthrough": [], "safe": False},
    "readline":            {"passthrough": [], "safe": False},
    "ARGV":                 {"passthrough": [], "safe": False},

    # ===== Web 框架 Sources =====
    "params":               {"passthrough": [], "safe": False},
    "request":              {"passthrough": [], "safe": False},
    "request.body":         {"passthrough": [], "safe": False},
    "cookies":              {"passthrough": [], "safe": False},
    "session":              {"passthrough": [], "safe": False},
    "flash":                {"passthrough": [], "safe": False},

    # ===== 文件读取 Sources =====
    "File.read":            {"passthrough": [0], "safe": False},
    "File.open":            {"passthrough": [0], "safe": False},
    "File.write":           {"passthrough": [0], "safe": False},
    "File.delete":          {"passthrough": [0], "safe": False},
    "IO.read":              {"passthrough": [0], "safe": False},
    "IO.write":             {"passthrough": [0], "safe": False},
    "IO.popen":             {"passthrough": [0], "safe": False},
    "open":                 {"passthrough": [0], "safe": False},
    "readlines":            {"passthrough": [0], "safe": False},

    # ===== 编码解析 Sources =====
    "JSON.parse":           {"passthrough": [0], "safe": False, "param_flow": {0: 0}},
    "YAML.load":            {"passthrough": [0], "safe": False},
    "YAML.safe_load":       {"passthrough": [0], "safe": True},
    "CSV.parse":            {"passthrough": [0], "safe": False},
    "Base64.decode64":      {"passthrough": [0], "safe": False},
    "Base64.encode64":      {"passthrough": [0], "safe": False},
    "ERB.new":              {"passthrough": [0], "safe": False},
    "ERB.result":           {"passthrough": [0], "safe": False},

    # ===== 网络读取 Sources =====
    "URI.parse":            {"passthrough": [0], "safe": False},
    "URI.open":             {"passthrough": [0], "safe": False},
    "Net::HTTP.get":        {"passthrough": [0], "safe": False},
    "Net::HTTP.post":       {"passthrough": [0], "safe": False},
    "open-uri":             {"passthrough": [0], "safe": False},

    # ================================================================
    #  SINKS — 危险操作（标记为不安全）
    # ================================================================

    # ===== eval 系列代码执行 =====
    "eval":                 {"passthrough": [0], "safe": False},
    "binding.eval":         {"passthrough": [0], "safe": False},
    "instance_eval":        {"passthrough": [0], "safe": False},
    "class_eval":           {"passthrough": [0], "safe": False},
    "module_eval":          {"passthrough": [0], "safe": False},
    "Kernel.eval":          {"passthrough": [0], "safe": False},

    # ===== 命令执行 =====
    "system":               {"passthrough": [0], "safe": False},
    "exec":                 {"passthrough": [0], "safe": False},
    "spawn":                {"passthrough": [0], "safe": False},
    "IO.popen":             {"passthrough": [0], "safe": False},
    "Open3.popen3":         {"passthrough": [0], "safe": False},
    "Open3.capture3":       {"passthrough": [0], "safe": False},
    "Open3.pipeline":       {"passthrough": [0], "safe": False},
    "Kernel.system":        {"passthrough": [0], "safe": False},
    "Kernel.exec":          {"passthrough": [0], "safe": False},
    "Kernel.spawn":         {"passthrough": [0], "safe": False},
    "Kernel.open":          {"passthrough": [0], "safe": False},

    # ===== 文件操作 =====
    "File.open":            {"passthrough": [0], "safe": False},
    "File.write":           {"passthrough": [0], "safe": False},
    "File.delete":          {"passthrough": [0], "safe": False},
    "FileUtils.rm":         {"passthrough": [0], "safe": False},
    "FileUtils.cp":         {"passthrough": [0, 1], "safe": False},
    "FileUtils.mv":         {"passthrough": [0, 1], "safe": False},
    "FileUtils.mkdir":      {"passthrough": [0], "safe": False},
    "FileUtils.touch":      {"passthrough": [0], "safe": False},
    "Dir.glob":             {"passthrough": [0], "safe": False},
    "Dir.chdir":            {"passthrough": [0], "safe": False},

    # ===== SQL 注入 =====
    "ActiveRecord::Base.connection.execute": {"passthrough": [0], "safe": False},
    "find_by_sql":          {"passthrough": [0], "safe": False},

    # ===== 输出（可能 XSS）=====
    "puts":                 {"passthrough": [0], "safe": False},
    "print":                {"passthrough": [0], "safe": False},
    "printf":               {"passthrough": [0], "safe": False},
    "p":                    {"passthrough": [0], "safe": False},
    "Kernel.puts":          {"passthrough": [0], "safe": False},
    "Kernel.print":         {"passthrough": [0], "safe": False},
    "Kernel.printf":        {"passthrough": [0], "safe": False},

    # ===== 序列化 =====
    "Marshal.dump":         {"passthrough": [0], "safe": False},
    "Marshal.load":         {"passthrough": [0], "safe": False},
    "YAML.dump":            {"passthrough": [0], "safe": False},
    "YAML.load":            {"passthrough": [0], "safe": False},

    # ================================================================
    #  字符串操作（透传，不安全）
    # ================================================================

    # ===== String 方法 =====
    "String":               {"passthrough": [0], "safe": False},
    "to_s":                 {"passthrough": [0], "safe": False},
    "to_str":               {"passthrough": [0], "safe": False},
    "strip":                {"passthrough": [0], "safe": False},
    "strip!":               {"passthrough": [0], "safe": False},
    "chomp":                {"passthrough": [0], "safe": False},
    "chomp!":               {"passthrough": [0], "safe": False},
    "chop":                 {"passthrough": [0], "safe": False},
    "gsub":                 {"passthrough": [0, 1], "safe": False},
    "gsub!":                {"passthrough": [0, 1], "safe": False},
    "sub":                  {"passthrough": [0, 1], "safe": False},
    "sub!":                 {"passthrough": [0, 1], "safe": False},
    "replace":              {"passthrough": [1], "safe": False},
    "upcase":               {"passthrough": [0], "safe": False},
    "downcase":             {"passthrough": [0], "safe": False},
    "capitalize":           {"passthrough": [0], "safe": False},
    "reverse":              {"passthrough": [0], "safe": False},
    "split":                {"passthrough": [0], "safe": False},
    "clone":                {"passthrough": [0], "safe": False},
    "dup":                  {"passthrough": [0], "safe": False},
    "freeze":               {"passthrough": [0], "safe": False},
    "encode":               {"passthrough": [0], "safe": False},
    "force_encoding":       {"passthrough": [0], "safe": False},
    "bytes":                {"passthrough": [0], "safe": False},
    "chars":                {"passthrough": [0], "safe": False},
    "b":                    {"passthrough": [0], "safe": False},

    # ===== CGI/HTML 转义 =====
    "CGI.escapeHTML":       {"passthrough": [0], "safe": True},
    "ERB::Util.html_escape": {"passthrough": [0], "safe": True},
    "ERB::Util.url_encode": {"passthrough": [0], "safe": True},
    "ERB::Util.json_escape": {"passthrough": [0], "safe": True},
    "h":                    {"passthrough": [0], "safe": True},
    "html_escape":          {"passthrough": [0], "safe": True},

    # ================================================================
    #  安全函数（safe=True）
    # ================================================================

    "length":               {"passthrough": [], "safe": True},
    "size":                 {"passthrough": [], "safe": True},
    "empty?":               {"passthrough": [], "safe": True},
    "nil?":                 {"passthrough": [], "safe": True},
    "blank?":               {"passthrough": [], "safe": True},
    "present?":             {"passthrough": [], "safe": True},
    "is_a?":                {"passthrough": [], "safe": True},
    "kind_of?":             {"passthrough": [], "safe": True},
    "respond_to?":          {"passthrough": [], "safe": True},
    "to_i":                 {"passthrough": [], "safe": True},
    "to_f":                 {"passthrough": [], "safe": True},
    "to_a":                 {"passthrough": [0], "safe": False},
    "to_h":                 {"passthrough": [0], "safe": False},
    "Integer":              {"passthrough": [], "safe": True},
    "Float":                {"passthrough": [], "safe": True},
    "match?":               {"passthrough": [], "safe": True},
    "include?":             {"passthrough": [], "safe": True},
    "start_with?":          {"passthrough": [], "safe": True},
    "end_with?":            {"passthrough": [], "safe": True},
    "count":                {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """查询函数可控性知识。

    尝试精确匹配，然后按简短名称匹配。

    :param func_name: 函数名（可以带 receiver 如 CGI.escapeHTML）
    :return: 知识字典或 None
    """
    if not func_name:
        return None

    # 精确匹配
    result = KNOWLEDGE.get(func_name)
    if result:
        return result

    # 短名称匹配（取最后一个 :: 或 . 之后的部分）
    short_name = func_name.split('::')[-1].split('.')[-1]
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
