# -*- coding: utf-8 -*-
"""
    TypeScript Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    自动发现 TypeScript 项目中的 source（数据入口）：
    1. 内置 source：process.env, process.argv 等
    2. 框架检测：从 package.json 检测 Web 框架（Express/NestJS/Fastify/Koa）
    3. 用户自定义 source producer：遍历 tree-sitter AST 找函数定义，
       检查函数体是否直接访问已知 source

    :author:    KunLun-M
    :license:   MIT
"""

import os
import json
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
        self.source_variables = set()
        self.framework_request_methods = set()
        self.user_source_functions = {}

    def add_source_member(self, name):
        """注册一个 source 成员表达式"""
        self.source_members.add(name)

    def add_source_variable(self, name):
        """注册一个 source 变量名"""
        self.source_variables.add(name)

    def is_source_member(self, expr_str):
        """检查表达式字符串是否匹配已知 source 成员"""
        if expr_str in self.source_members:
            return True
        for sm in self.source_members:
            if expr_str.startswith(sm + '.') or expr_str.startswith(sm + '['):
                return True
        return False

    def is_source_variable(self, name):
        """检查变量名是否是已知 source"""
        return name in self.source_variables

    def is_source_producer(self, func_name):
        """检查函数是否是用户自定义 source producer"""
        return self.user_source_functions.get(func_name)

    def get_all_source_names(self):
        """获取所有 source 名称"""
        return list(self.source_members | self.source_variables)


# ---------------------------------------------------------------------------
# 内置 source 定义
# ---------------------------------------------------------------------------

_BUILTIN_SOURCE_MEMBERS = {
    # Browser / DOM
    'location.hash', 'location.search', 'location.href',
    'location.pathname', 'location.origin', 'location.protocol',
    'document.cookie', 'document.URL', 'document.documentURI',
    'document.referrer', 'document.domain', 'document.baseURI',
    'window.name', 'window.location',
    # Node.js
    'process.env', 'process.argv',
}

_BUILTIN_SOURCE_VARIABLES = {
    'process', 'arguments',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'express': {
        'detect_package': ['express'],
        'source_members': {
            'req.query', 'req.body', 'req.params', 'req.headers',
            'req.cookies', 'req.files', 'req.url', 'req.method',
            'request.query', 'request.body', 'request.params',
            'request.headers', 'request.cookies',
        },
        'request_methods': {
            ('req', 'query'), ('req', 'param'), ('req', 'header'),
            ('req', 'cookie'), ('req', 'get'),
            ('request', 'query'), ('request', 'param'),
            ('request', 'header'), ('request', 'get'),
        },
    },
    'nestjs': {
        'detect_package': ['@nestjs/core', '@nestjs/common'],
        'source_members': {
            'req.query', 'req.body', 'req.params', 'req.headers',
            'request.query', 'request.body', 'request.params',
            'request.headers',
        },
        'request_methods': {
            ('req', 'query'), ('req', 'param'), ('req', 'header'),
            ('request', 'query'), ('request', 'param'),
        },
    },
    'fastify': {
        'detect_package': ['fastify'],
        'source_members': {
            'request.query', 'request.body', 'request.params',
            'request.headers',
        },
        'request_methods': {
            ('request', 'query'), ('request', 'body'),
            ('request', 'params'),
        },
    },
    'koa': {
        'detect_package': ['koa'],
        'source_members': {
            'ctx.query', 'ctx.querystring', 'ctx.params',
            'ctx.request.body', 'ctx.request.query',
            'ctx.request.header', 'ctx.request.headers',
        },
        'request_methods': {
            ('ctx', 'query'), ('ctx', 'querystring'),
            ('ctx', 'params'), ('ctx', 'get'),
        },
    },
    'hapi': {
        'detect_package': ['@hapi/hapi', 'hapi'],
        'source_members': {
            'request.query', 'request.params', 'request.payload',
            'request.headers',
        },
        'request_methods': {
            ('request', 'query'), ('request', 'param'),
            ('request', 'payload'),
        },
    },
}


# ---------------------------------------------------------------------------
# 框架检测
# ---------------------------------------------------------------------------

def detect_framework(project_dir):
    """从 package.json 检测 TypeScript Web 框架。

    向上遍历最多 5 级目录查找 package.json。
    返回 framework_name 或 None
    """
    search_dir = os.path.abspath(project_dir)
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        pkg_json = os.path.join(search_dir, 'package.json')
        if os.path.isfile(pkg_json):
            try:
                with open(pkg_json, 'r', encoding='utf-8', errors='replace') as f:
                    pkg = json.load(f)
                deps = {}
                for key in ('dependencies', 'devDependencies', 'peerDependencies'):
                    deps.update(pkg.get(key, {}))
                for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                    for pkg_name in fw_config['detect_package']:
                        if pkg_name in deps:
                            return fw_name
            except (json.JSONDecodeError, OSError):
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
        if registry.is_source_member(expr_str):
            return True
        if registry.is_source_variable(expr_str.split('.')[0]):
            return True

    node_type = node.type

    # member_expression: e.g. req.query, process.env
    if node_type == 'member_expression':
        full_str = _node_text(node)
        if full_str and registry.is_source_member(full_str):
            return True

    # call_expression / call_member_expression: e.g. req.query('id')
    if node_type in ('call_expression', 'call_member_expression'):
        for child in node.children:
            if child.type in ('identifier', 'member_expression',
                              'property_identifier'):
                func_str = _node_text(child)
                if func_str:
                    for sm in registry.source_members:
                        if func_str == sm or func_str.startswith(sm + '.'):
                            return True

    if hasattr(node, 'children') and node.children:
        for child in node.children:
            if hasattr(child, 'type'):
                if _node_contains_source(child, registry, _depth + 1):
                    return True

    return False


def _function_returns_source(func_node, registry):
    """检查函数的 return 语句是否包含已知 source"""
    if func_node is None:
        return False

    def _walk_return(node):
        if node is None or not hasattr(node, 'type'):
            return False
        if node.type == 'return_statement':
            for child in node.children:
                if hasattr(child, 'type') and child.type != 'return':
                    if _node_contains_source(child, registry):
                        return True
            return False
        if node.type in ('function_declaration', 'arrow_function',
                         'method_definition', 'class_declaration'):
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

        if child.type in ('function_declaration', 'arrow_function',
                         'method_definition', 'generator_function_declaration'):
            _check_single_function(child, file_path, registry)

        # 递归进入 class_declaration, abstract_class_declaration
        if child.type in ('class_declaration', 'abstract_class_declaration'):
            for sub in child.children:
                if hasattr(sub, 'type') and sub.type == 'class_body':
                    for method in sub.children:
                        if hasattr(method, 'type') and method.type == 'method_definition':
                            _check_single_function(method, file_path, registry)

        # 递归进入 statement_block, export_statement
        if child.type in ('statement_block', 'export_statement'):
            _walk_for_functions(child, file_path, registry)


def _check_single_function(func_node, file_path, registry):
    """检查单个函数节点"""
    func_name_node = None
    for c in func_node.children:
        if c.type in ('identifier', 'property_identifier'):
            func_name_node = c
            break
    if not func_name_node:
        return
    func_name = _node_text(func_name_node)
    if not func_name or func_name in ('main', 'constructor'):
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
        logger.debug('[SourceDiscovery][TypeScript] User source producer: {} in {}'.format(
            func_name, file_path))


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, extra_sources=None):
    """发现 TypeScript 项目中的 source

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
    for sv in _BUILTIN_SOURCE_VARIABLES:
        registry.add_source_variable(sv)

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
        for rm in fw_config.get('request_methods', set()):
            registry.framework_request_methods.add(rm)
        logger.debug('[SourceDiscovery][TypeScript] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery][TypeScript] No TypeScript framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'root_node'):
        _walk_for_functions(tree.root_node, file_path or project_dir, registry)

    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery][TypeScript] User source producers ({}): {}'.format(
            len(names), names))

    return registry
