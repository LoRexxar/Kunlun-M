"""
RUST 内置函数/方法可控性知识库

为静态分析引擎提供 Rust 内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

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

    # ===== std::env 环境变量/命令行 Sources =====
    "std::env::var":           {"passthrough": [0], "safe": False},
    "std::env::var_os":        {"passthrough": [0], "safe": False},
    "std::env::args":          {"passthrough": [], "safe": False},
    "std::env::args_os":       {"passthrough": [], "safe": False},

    # ===== std::fs 文件读取 Sources =====
    "std::fs::read_to_string": {"passthrough": [0], "safe": False},
    "std::fs::read":           {"passthrough": [0], "safe": False},
    "std::fs::read_dir":       {"passthrough": [0], "safe": False},
    "std::fs::metadata":       {"passthrough": [0], "safe": False},
    "std::fs::canonicalize":   {"passthrough": [0], "safe": False},

    # ===== std::io Sources =====
    "std::io::Read::read_to_string": {"passthrough": [0], "safe": False},
    "std::io::BufRead::lines":       {"passthrough": [0], "safe": False},
    "std::io::stdin":                 {"passthrough": [], "safe": False},

    # ===== serde_json 解码 =====
    "serde_json::from_str":     {"passthrough": [0], "safe": False, "param_flow": {0: 0}},
    "serde_json::from_value":   {"passthrough": [0], "safe": False},
    "serde_json::from_reader":  {"passthrough": [0], "safe": False},
    "serde_json::Value::get":   {"passthrough": [0], "safe": False},
    "serde_json::Value::as_str": {"passthrough": [0], "safe": False},

    # ===== serde_yaml 解码 =====
    "serde_yaml::from_str":     {"passthrough": [0], "safe": False},

    # ===== toml 解码 =====
    "toml::from_str":           {"passthrough": [0], "safe": False},

    # ===== std::net 解析 =====
    "std::net::TcpStream::connect":  {"passthrough": [0], "safe": False},
    "std::net::UdpSocket::bind":     {"passthrough": [0], "safe": False},

    # ================================================================
    #  Actix-web 框架 Sources
    # ================================================================
    "HttpRequest::query_string":     {"passthrough": [0], "safe": False},
    "HttpRequest::match_info":       {"passthrough": [0], "safe": False},
    "HttpRequest::headers":          {"passthrough": [0], "safe": False},
    "HttpRequest::payload":          {"passthrough": [0], "safe": False},
    "web::Query::into_inner":        {"passthrough": [0], "safe": False},
    "web::Path::into_inner":         {"passthrough": [0], "safe": False},
    "web::Form::into_inner":         {"passthrough": [0], "safe": False},
    "web::Json::into_inner":         {"passthrough": [0], "safe": False},
    "Query::into_inner":             {"passthrough": [0], "safe": False},
    "Path::into_inner":              {"passthrough": [0], "safe": False},

    # ================================================================
    #  Axum 框架 Sources
    # ================================================================
    "axum::extract::Query":     {"passthrough": [0], "safe": False},
    "axum::extract::Path":      {"passthrough": [0], "safe": False},
    "axum::extract::Form":      {"passthrough": [0], "safe": False},
    "axum::extract::Json":      {"passthrough": [0], "safe": False},
    "axum::extract::State":     {"passthrough": [0], "safe": False},
    "Query::0":                 {"passthrough": [0], "safe": False},
    "Path::0":                  {"passthrough": [0], "safe": False},

    # ================================================================
    #  SINKS — 危险操作（标记为不安全）
    # ================================================================

    # ===== std::process::Command — 命令注入 =====
    "std::process::Command::new":      {"passthrough": [0], "safe": False},
    "std::process::Command::arg":      {"passthrough": [0], "safe": False},
    "std::process::Command::args":     {"passthrough": [0], "safe": False},
    "std::process::Command::env":      {"passthrough": [0, 1], "safe": False},
    "std::process::Command::output":   {"passthrough": [0], "safe": False},
    "std::process::Command::status":   {"passthrough": [0], "safe": False},
    "Command::new":                     {"passthrough": [0], "safe": False},
    "Command::arg":                     {"passthrough": [0], "safe": False},

    # ===== std::fs 文件操作 — 路径遍历 =====
    "std::fs::File::open":              {"passthrough": [0], "safe": False},
    "std::fs::File::create":            {"passthrough": [0], "safe": False},
    "std::fs::create_dir":              {"passthrough": [0], "safe": False},
    "std::fs::create_dir_all":          {"passthrough": [0], "safe": False},
    "std::fs::remove_dir":              {"passthrough": [0], "safe": False},
    "std::fs::remove_dir_all":          {"passthrough": [0], "safe": False},
    "std::fs::remove_file":             {"passthrough": [0], "safe": False},
    "std::fs::copy":                    {"passthrough": [0, 1], "safe": False},
    "std::fs::rename":                  {"passthrough": [0, 1], "safe": False},
    "std::fs::write":                   {"passthrough": [0], "safe": False},
    "std::fs::OpenOptions::open":       {"passthrough": [0], "safe": False},
    "std::fs::symlink_metadata":        {"passthrough": [0], "safe": False},

    # ===== std::net::TcpStream::connect — SSRF =====
    "std::net::TcpStream::connect":     {"passthrough": [0], "safe": False},
    "std::net::TcpListener::bind":      {"passthrough": [0], "safe": False},
    "std::net::UdpSocket::bind":        {"passthrough": [0], "safe": False},
    "std::net::UdpSocket::send_to":     {"passthrough": [0], "safe": False},
    "std::net::UdpSocket::connect":     {"passthrough": [0], "safe": False},

    # ===== std::env 环境变量操作 =====
    "std::env::set_var":          {"passthrough": [0, 1], "safe": False},
    "std::env::remove_var":       {"passthrough": [0], "safe": False},

    # ===== std::thread — 竞态条件 =====
    "std::thread::spawn":         {"passthrough": [0], "safe": False},

    # ===== fmt — 输出（可能 XSS）=====
    "format":                     {"passthrough": [0], "safe": False},
    "println":                    {"passthrough": [0], "safe": False},
    "print":                      {"passthrough": [0], "safe": False},
    "eprintln":                   {"passthrough": [0], "safe": False},
    "eprint":                     {"passthrough": [0], "safe": False},

    # ===== unsafe =====
    "unsafe":                     {"passthrough": [], "safe": False},

    # ===== libc 系统调用 =====
    "libc::system":               {"passthrough": [0], "safe": False},
    "libc::exec":                 {"passthrough": [0], "safe": False},
    "libc::execl":                {"passthrough": [0], "safe": False},
    "libc::popen":                {"passthrough": [0], "safe": False},

    # ===== SQL 注入 =====
    "sqlx::query":                {"passthrough": [0], "safe": False},
    "sqlx::query_as":             {"passthrough": [0], "safe": False},
    "sqlx::query_scalar":         {"passthrough": [0], "safe": False},
    "diesel::insert_into":        {"passthrough": [0], "safe": False},
    "diesel::update":             {"passthrough": [0], "safe": False},
    "diesel::delete":             {"passthrough": [0], "safe": False},

    # ===== SSRF =====
    "reqwest::Client::get":               {"passthrough": [0], "safe": False},
    "reqwest::Client::post":              {"passthrough": [0], "safe": False},
    "reqwest::blocking::Client::get":     {"passthrough": [0], "safe": False},
    "reqwest::blocking::Client::post":    {"passthrough": [0], "safe": False},
    "reqwest::get":                      {"passthrough": [0], "safe": False},
    "reqwest::post":                     {"passthrough": [0], "safe": False},

    # ================================================================
    #  字符串操作（透传，不安全）
    # ================================================================

    # ===== String 方法 =====
    "String::from":               {"passthrough": [0], "safe": False},
    "String::to_string":          {"passthrough": [0], "safe": False},
    "String::as_str":             {"passthrough": [0], "safe": False},
    "String::trim":               {"passthrough": [0], "safe": False},
    "String::trim_start":         {"passthrough": [0], "safe": False},
    "String::trim_end":           {"passthrough": [0], "safe": False},
    "String::replace":            {"passthrough": [0, 1], "safe": False},
    "String::replacen":           {"passthrough": [0, 1], "safe": False},
    "String::to_lowercase":       {"passthrough": [0], "safe": False},
    "String::to_uppercase":       {"passthrough": [0], "safe": False},
    "String::clone":              {"passthrough": [0], "safe": False},
    "String::into_bytes":         {"passthrough": [0], "safe": False},

    # ===== str 方法 =====
    "str::trim":                  {"passthrough": [0], "safe": False},
    "str::to_string":             {"passthrough": [0], "safe": False},
    "str::replace":               {"passthrough": [0, 1], "safe": False},
    "str::parse":                 {"passthrough": [], "safe": True},
    "str::contains":              {"passthrough": [], "safe": True},
    "str::starts_with":           {"passthrough": [], "safe": True},
    "str::ends_with":             {"passthrough": [], "safe": True},
    "str::is_empty":              {"passthrough": [], "safe": True},
    "str::len":                   {"passthrough": [], "safe": True},

    # ===== Vec 方法 =====
    "Vec::new":                   {"passthrough": [], "safe": True},
    "Vec::push":                  {"passthrough": [0], "safe": False},
    "Vec::with_capacity":         {"passthrough": [], "safe": True},
    "vec":                        {"passthrough": [], "safe": True},

    # ===== 编解码 =====
    "serde_json::to_string":      {"passthrough": [0], "safe": False},
    "serde_json::to_string_pretty": {"passthrough": [0], "safe": False},
    "base64::encode":             {"passthrough": [0], "safe": False},
    "base64::decode":             {"passthrough": [0], "safe": False},
    "hex::encode":                {"passthrough": [0], "safe": False},
    "hex::decode":                {"passthrough": [0], "safe": False},

    # ===== 路径操作 =====
    "std::path::PathBuf::from":   {"passthrough": [0], "safe": False},
    "std::path::Path::new":       {"passthrough": [0], "safe": False},
    "std::path::Path::join":      {"passthrough": [0, 1], "safe": False},
    "std::path::Path::file_name": {"passthrough": [0], "safe": False},
    "std::path::Path::parent":    {"passthrough": [0], "safe": False},
    "std::path::Path::extension": {"passthrough": [0], "safe": False},
    "std::path::Path::canonicalize": {"passthrough": [0], "safe": False},
    "std::path::Path::clean":     {"passthrough": [0], "safe": False},
    "PathBuf::from":              {"passthrough": [0], "safe": False},
    "Path::new":                  {"passthrough": [0], "safe": False},
    "Path::join":                 {"passthrough": [0, 1], "safe": False},

    # ================================================================
    #  安全函数（safe=True）
    # ================================================================

    "str::len":                   {"passthrough": [], "safe": True},
    "str::is_empty":              {"passthrough": [], "safe": True},
    "str::parse::<i32>":          {"passthrough": [], "safe": True},
    "str::parse::<u32>":          {"passthrough": [], "safe": True},
    "str::parse::<f64>":          {"passthrough": [], "safe": True},
    "str::chars":                 {"passthrough": [0], "safe": False},
    "str::bytes":                 {"passthrough": [0], "safe": False},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """查询函数可控性知识。

    尝试精确匹配，然后按简短名称匹配。

    :param func_name: 函数名（可以带模块前缀如 std::env::var）
    :return: 知识字典或 None
    """
    if not func_name:
        return None

    # 精确匹配
    result = KNOWLEDGE.get(func_name)
    if result:
        return result

    # 短名称匹配（取最后一个 :: 之后的部分）
    if '::' in func_name:
        short_name = func_name.split('::')[-1]
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
