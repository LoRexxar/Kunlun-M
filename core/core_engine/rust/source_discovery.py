# -*- coding: utf-8 -*-
"""
    Rust Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    自动发现 Rust 项目中的 source（数据入口）：
    1. 内置 source：std::env::var, std::env::args, std::io::stdin 等
    2. 框架检测：从 Cargo.toml 检测 Web 框架（Actix/Axum/Rocket/Warp）
    3. 用户自定义 source producer：遍历 tree-sitter AST 找函数定义，
       检查函数体是否直接访问已知 source

    :author:    KunLun-M
    :license:   MIT
"""

import os
from utils.log import logger


class SourceInfo:
    """source 信息"""
    __slots__ = ('source_type', 'origin', 'is_safe', 'passthrough')

    def __init__(self, source_type='builtin', origin='', is_safe=False, passthrough=False):
        self.source_type = source_type
        self.origin = origin
        self.is_safe = is_safe
        self.passthrough = passthrough

    def __repr__(self):
        return '<SourceInfo type={} origin={}>'.format(self.source_type, self.origin)


class SourceRegistry:
    """Source 注册表"""

    def __init__(self):
        self.source_members = set()
        self.user_source_functions = {}

    def add_source_member(self, name):
        """注册一个 source 变量/表达式"""
        self.source_members.add(name)

    def is_source_member(self, expr_str):
        """检查表达式字符串是否包含已知 source 成员"""
        for sm in self.source_members:
            if sm == expr_str or expr_str.startswith(sm + '::') or expr_str.startswith(sm + '('):
                return True
        return False

    def is_source_producer(self, func_name):
        """检查函数是否是用户自定义 source producer"""
        return self.user_source_functions.get(func_name)

    def get_all_source_names(self):
        """获取所有 source 成员名称"""
        return list(self.source_members)


# ---------------------------------------------------------------------------
# 内置 source 定义
# ---------------------------------------------------------------------------

_BUILTIN_SOURCE_MEMBERS = {
    # 命令行参数
    'std::env::args',
    'std::env::args_os',
    'std::env::args().collect',
    # 环境变量
    'std::env::var',
    'std::env::var_os',
    # 文件读取
    'std::fs::read_to_string',
    'std::fs::read',
    'std::io::stdin',
    'std::io::BufReader',
    'std::io::Read::read_to_string',
    'std::io::Read::read',
    'std::io::BufRead::lines',
    # 网络
    'std::net::TcpStream::connect',
    'std::net::UdpSocket::bind',
    'std::net::TcpListener::accept',
    # 编码解析
    'serde_json::from_str',
    'serde_json::from_value',
    'serde_json::from_reader',
    'serde_yaml::from_str',
    'toml::from_str',
    # 进程
    'std::process::Command::output',
    'std::process::Command::status',
    'std::process::Stdio',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'actix': {
        'detect_crate': ['actix-web'],
        'source_members': {
            'HttpRequest',
            'HttpReq',
            'web::Query',
            'web::Path',
            'web::Form',
            'web::Json',
            'web::Data',
            'req.query_string',
            'req.match_info',
            'req.headers',
            'req.payload',
            'path.into_inner',
            'query.into_inner',
            'form.into_inner',
            'json.into_inner',
        },
    },
    'axum': {
        'detect_crate': ['axum'],
        'source_members': {
            'axum::extract::Query',
            'axum::extract::Path',
            'axum::extract::Form',
            'axum::extract::Json',
            'axum::extract::State',
            'axum::http::HeaderMap',
            'axum::body::Bytes',
            'Query',
            'Path',
            'Form',
            'Json',
            'Headers',
        },
    },
    'rocket': {
        'detect_crate': ['rocket'],
        'source_members': {
            'rocket::http::RawStr',
            'rocket::request::Request',
            'rocket::request::FromRequest',
            'rocket::request::FromParam',
            'rocket::data::Data',
            'rocket::http::ContentType',
            'RawStr',
            'Form',
            'Json',
            'Cookies',
        },
    },
    'warp': {
        'detect_crate': ['warp'],
        'source_members': {
            'warp::Filter',
            'warp::filters::query::query',
            'warp::filters::path::param',
            'warp::filters::body::json',
            'warp::filters::body::form',
            'warp::http::Headers',
            'query()',
            'path()',
            'body::json()',
        },
    },
    'tide': {
        'detect_crate': ['tide'],
        'source_members': {
            'tide::Request',
            'Request',
            'req.query_param',
            'req.body_json',
            'req.body_string',
            'req.header',
        },
    },
    'poem': {
        'detect_crate': ['poem'],
        'source_members': {
            'poem::Request',
            'poem::web::Path',
            'poem::web::Query',
            'poem::web::Json',
            'poem::web::Data',
            'Path',
            'Query',
            'Json',
            'Data',
        },
    },
}


# ---------------------------------------------------------------------------
# 框架检测
# ---------------------------------------------------------------------------

def detect_framework(project_dir):
    """从 Cargo.toml 检测 Rust Web 框架。

    向上遍历最多 5 级目录查找 Cargo.toml。
    返回 framework_name 或 None
    """
    search_dir = project_dir
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        cargo_toml = os.path.join(search_dir, 'Cargo.toml')
        if os.path.isfile(cargo_toml):
            try:
                with open(cargo_toml, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().lower()
                for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                    for crate_name in fw_config['detect_crate']:
                        if crate_name in content:
                            return fw_name
            except Exception:
                pass

        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent

    return None


# ---------------------------------------------------------------------------
# tree-sitter AST 遍历：source producer 发现
# ---------------------------------------------------------------------------

def _node_text(node):
    """将 tree-sitter 节点转为字符串"""
    if node is None:
        return None
    try:
        return node.text.decode('utf-8', errors='replace')
    except (AttributeError, UnicodeDecodeError):
        return None


def _node_contains_source(node, registry, _depth=0):
    """递归检查 tree-sitter 节点是否直接访问已知 source"""
    if node is None or _depth > 15:
        return False

    expr_str = _node_text(node)
    if expr_str:
        for sm in registry.source_members:
            if sm == expr_str or expr_str.startswith(sm + '::') or expr_str.startswith(sm + '('):
                return True

    node_type = node.type

    if node_type == 'scoped_identifier':
        full_str = _node_text(node)
        if full_str:
            for sm in registry.source_members:
                if sm in full_str:
                    return True

    if node_type in ('call_expression', 'method_call_expression'):
        for child in node.children:
            if child.type in ('identifier', 'scoped_identifier', 'field_expression'):
                func_str = _node_text(child)
                if func_str:
                    for sm in registry.source_members:
                        if func_str == sm or func_str.startswith(sm + '::'):
                            return True

    if hasattr(node, 'children') and node.children:
        for child in node.children:
            if hasattr(child, 'type'):
                if _node_contains_source(child, registry, _depth + 1):
                    return True

    return False


def _function_returns_source(func_node, registry):
    """检查 Rust 函数的 return 语句值是否包含已知 source"""
    if func_node is None:
        return False

    def _walk_return(node):
        if node is None or not hasattr(node, 'type'):
            return False
        if node.type == 'return_expression':
            for child in node.children:
                if hasattr(child, 'type') and child.type != 'return':
                    if _node_contains_source(child, registry):
                        return True
            return False
        if node.type == 'function_item':
            return False
        for child in node.children:
            if _walk_return(child):
                return True
        return False

    for child in func_node.children:
        if _walk_return(child):
            return True
    return False


def _walk_for_functions(root_node, file_path, registry):
    """遍历 tree-sitter AST 找函数定义，检查函数体是否直接访问已知 source"""
    if root_node is None:
        return

    for child in root_node.children:
        if child is None or not hasattr(child, 'type'):
            continue

        if child.type == 'function_item':
            func_name_node = None
            for c in child.children:
                if c.type == 'identifier':
                    func_name_node = c
                    break
            if not func_name_node:
                continue
            func_name = func_name_node.text.decode('utf-8', errors='replace')

            # 跳过私有函数和 main
            if func_name in ('main',):
                continue

            if not _function_returns_source(child, registry):
                continue

            if func_name not in registry.user_source_functions:
                lineno = child.start_point[0] + 1 if hasattr(child, 'start_point') else '?'
                source_info = SourceInfo(
                    source_type='user_defined',
                    origin='{}:{}'.format(os.path.basename(file_path), lineno),
                    is_safe=False,
                    passthrough=True,
                )
                registry.user_source_functions[func_name] = source_info
                logger.debug('[SourceDiscovery][Rust] User source producer: {} in {}'.format(
                    func_name, file_path))

        # 递归进入 impl_item
        if child.type == 'impl_item':
            for sub in child.children:
                if sub.type == 'function_item':
                    _walk_for_functions_single(sub, file_path, registry)

        # 递归进入 mod_item
        if child.type == 'mod_item':
            block = None
            for c in child.children:
                if c.type == 'block':
                    block = c
                    break
            if block:
                _walk_for_functions(block, file_path, registry)


def _walk_for_functions_single(func_node, file_path, registry):
    """检查单个函数节点"""
    func_name_node = None
    for c in func_node.children:
        if c.type == 'identifier':
            func_name_node = c
            break
    if not func_name_node:
        return
    func_name = func_name_node.text.decode('utf-8', errors='replace')

    if func_name in ('main',):
        return

    if not _function_returns_source(func_node, registry):
        return

    if func_name not in registry.user_source_functions:
        lineno = func_node.start_point[0] + 1 if hasattr(func_node, 'start_point') else '?'
        source_info = SourceInfo(
            source_type='user_defined',
            origin='{}:{}'.format(os.path.basename(file_path), lineno),
            is_safe=False,
            passthrough=True,
        )
        registry.user_source_functions[func_name] = source_info
        logger.debug('[SourceDiscovery][Rust] User source producer: {} in {}'.format(
            func_name, file_path))


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, extra_sources=None):
    """发现 Rust 项目中的 source

    :param project_dir: 项目目录路径
    :param tree: tree-sitter Tree 对象
    :param file_path: 当前文件路径
    :param extra_sources: 额外 source 列表，避免循环导入
    :return: SourceRegistry 实例
    """
    registry = SourceRegistry()

    # 1. 加载内置 source
    for sm in _BUILTIN_SOURCE_MEMBERS:
        registry.add_source_member(sm)
    # 1a. 注册短名（use 导入后代码用短名）
    # e.g. use std::env; → env::args(), env::var()
    for sm in _BUILTIN_SOURCE_MEMBERS:
        # std::env::args → env::args, std::fs::read → fs::read
        for prefix in ("std::", "std::process::", "std::io::", "std::net::"):
            if sm.startswith(prefix):
                short = sm[len(prefix):]
                registry.add_source_member(short)

    # 1b. 加载额外 source
    if extra_sources:
        for sm in extra_sources:
            registry.add_source_member(sm)

    # 2. 检测框架
    framework = detect_framework(project_dir)
    if framework and framework in _FRAMEWORK_CONFIGS:
        fw_config = _FRAMEWORK_CONFIGS[framework]
        for sm in fw_config['source_members']:
            registry.add_source_member(sm)
        logger.debug('[SourceDiscovery][Rust] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery][Rust] No Rust framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'root_node'):
        _walk_for_functions(tree.root_node, file_path or project_dir, registry)

    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery][Rust] User source producers ({}): {}'.format(
            len(names), names))

    return registry
