# -*- coding: utf-8 -*-
"""
    C++ Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    自动发现 C++ 项目中的 source（数据入口）：
    1. 内置 source：argv, getenv, scanf, fgets, read, recv, std::cin 等
    2. 框架检测：从 #include / CMakeLists.txt / Makefile 检测 Web/Crypto 框架
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
        # 已知 source 成员（用于字符串匹配，注入 CPP_CONTROLLED_SOURCES）
        self.source_members = set()
        # 用户自定义 source producer 函数名 → SourceInfo
        self.user_source_functions = {}

    def add_source_member(self, name):
        """注册一个 source 变量/表达式"""
        self.source_members.add(name)

    def is_source_member(self, expr_str):
        """检查表达式字符串是否包含已知 source 成员"""
        for sm in self.source_members:
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '('):
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
    # 标准输入函数
    'fgets', 'getline', 'getdelim',
    'read', 'fread',
    # C++ IO
    'std::cin', 'cin',
    'std::getline',
    # C++ string streams
    'std::istringstream', 'std::stringstream',
    # 文件
    'fgetc', 'getc',
    # C++ std::istream
    'std::istream::read', 'std::istream::getline',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'cgi': {
        'detect_headers': ['cgic.h', 'cgi.h', 'fcgi_stdio.h', 'fastcgi.h'],
        'source_members': {
            'cgiFormString', 'cgiFormEntry', 'cgiFormSelect',
            'cgiQueryString', 'cgiCookieString',
            'FCGI_getenv',
        },
    },
    'libcurl': {
        'detect_headers': ['curl/curl.h', 'curl.h'],
        'source_members': {
            'curl_easy_getinfo', 'curl_easy_perform',
        },
    },
    'openssl': {
        'detect_headers': ['openssl/ssl.h', 'openssl/evp.h', 'openssl/rand.h'],
        'source_members': {
            'SSL_read', 'SSL_read_ex',
        },
    },
    'cpprestsdk': {
        'detect_headers': ['cpprest/http_listener.h', 'casablanca.h'],
        'source_members': {
            'http_request::extract_string', 'http_request::extract_json',
            'http_request::relative_uri', 'http_request::uri',
        },
    },
    'drogon': {
        'detect_headers': ['drogon/HttpController.h', 'drogon/HttpRequest.h'],
        'source_members': {
            'HttpRequest::getParameter', 'HttpRequest::getJsonObject',
            'HttpRequest::getBody', 'HttpRequest::getHeader',
        },
    },
}


# ---------------------------------------------------------------------------
# 框架检测 — #include / CMakeLists.txt / Makefile
# ---------------------------------------------------------------------------

def _detect_framework(project_dir):
    """通过 #include 和构建文件检测 C++ 框架

    向上遍历最多 5 级目录查找头文件和构建配置。
    返回 framework_name 或 None
    """
    search_dir = project_dir
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        # 扫描 C++ 源文件中的 #include
        for ext in ('*.cpp', '*.hpp', '*.h', '*.cc', '*.cxx'):
            import glob
            for fpath in glob.glob(os.path.join(search_dir, ext)):
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            stripped = line.strip()
                            if not stripped.startswith('#'):
                                continue
                            for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                                for header in fw_config['detect_headers']:
                                    if header in stripped:
                                        return fw_name
                except Exception:
                    pass

        # 扫描构建文件
        for build_file in ('CMakeLists.txt', 'Makefile', 'makefile', '*.cmake'):
            import glob
            for fpath in glob.glob(os.path.join(search_dir, build_file)):
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read().lower()
                    for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                        for header in fw_config['detect_headers']:
                            if header.lower().replace('.h', '') in content:
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

def _expr_to_str(node):
    """将 tree-sitter C++ 节点转为简单字符串（仅用于 source 匹配）"""
    if node is None:
        return None

    node_type = node.type
    try:
        text = node.text.decode('utf-8', errors='replace')
    except (AttributeError, UnicodeDecodeError):
        return None

    if node_type == 'identifier':
        return text
    elif node_type in ('field_expression', 'member_expression'):
        operand = node.child_by_field_name('argument') or node.child_by_field_name('object')
        field = node.child_by_field_name('field')
        operand_str = _expr_to_str(operand)
        field_str = _expr_to_str(field) if field else ''
        if operand_str and field_str:
            return operand_str + '.' + field_str
        return field_str or operand_str or text
    elif node_type == 'call_expression':
        func_node = node.child_by_field_name('function')
        func_str = _expr_to_str(func_node)
        return func_str if func_str else text
    elif node_type == 'subscript_expression':
        obj = node.child_by_field_name('argument') or node.child_by_field_name('array')
        return _expr_to_str(obj)
    elif node_type == 'declaration':
        decl = node.child_by_field_name('declarator') or node.child_by_field_name('type')
        return _expr_to_str(decl)

    # Fallback
    return text


def _node_contains_source(node, registry, _depth=0):
    """递归检查 tree-sitter C++ 节点是否直接访问已知 source"""
    if node is None or _depth > 15:
        return False

    # 检查当前节点文本
    expr_str = _expr_to_str(node)
    if expr_str:
        for sm in registry.source_members:
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '('):
                return True
        for sm in registry.source_members:
            if '.' in sm and sm in expr_str:
                return True

    node_type = node.type

    if node_type in ('field_expression', 'member_expression'):
        full_str = _expr_to_str(node)
        if full_str:
            for sm in registry.source_members:
                if sm in full_str:
                    return True

    if node_type == 'call_expression':
        func_node = node.child_by_field_name('function')
        func_str = _expr_to_str(func_node)
        if func_str:
            for sm in registry.source_members:
                if func_str == sm or func_str.startswith(sm + '.'):
                    return True

    # 递归检查子节点
    if hasattr(node, 'children') and node.children:
        for child in node.children:
            if hasattr(child, 'type'):
                if _node_contains_source(child, registry, _depth + 1):
                    return True

    return False


def _function_returns_source_cpp(func_node, registry):
    """检查 C++ 函数定义的 return 语句值是否包含已知 source"""
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
        # 不进入嵌套函数定义
        if node.type == 'function_definition':
            return False
        if node.type == 'lambda_expression':
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
    """遍历 tree-sitter C++ AST 找函数定义，检查函数体是否直接访问已知 source"""
    if root_node is None:
        return

    for child in root_node.children:
        if child is None or not hasattr(child, 'type'):
            continue

        if child.type == 'function_definition':
            func_node = child.child_by_field_name('declarator')
            func_name = None
            if func_node:
                func_name = _extract_func_name(func_node)

            if not func_name:
                continue

            if not _function_returns_source_cpp(child, registry):
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
                logger.debug('[SourceDiscovery][C++] User source producer: {} in {}'.format(
                    func_name, file_path))

        # 递归进入命名空间、类定义等
        elif child.type in ('namespace_definition', 'class_specifier',
                             'struct_specifier', 'template_declaration',
                             'declaration'):
            _walk_for_functions(child, file_path, registry)


def _extract_func_name(declarator_node):
    """从 tree-sitter C++ 的 function_declarator/pointer_declarator 中提取函数名"""
    node = declarator_node
    for _ in range(5):
        if node is None:
            return None
        if node.type == 'function_declarator':
            decl = node.child_by_field_name('declarator')
            if decl and decl.type == 'identifier':
                return decl.text.decode('utf-8', errors='replace')
            return _expr_to_str(decl)
        elif node.type == 'pointer_declarator':
            node = node.child_by_field_name('declarator')
        elif node.type == 'identifier':
            return node.text.decode('utf-8', errors='replace')
        else:
            for child in node.children:
                if hasattr(child, 'type') and child.type == 'identifier':
                    return child.text.decode('utf-8', errors='replace')
            return None
    return None


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, extra_sources=None):
    """发现 C++ 项目中的 source

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

    # 1b. 加载额外 source 列表
    if extra_sources:
        for sm in extra_sources:
            registry.add_source_member(sm)

    # 2. 检测框架
    framework = _detect_framework(project_dir)
    if framework and framework in _FRAMEWORK_CONFIGS:
        fw_config = _FRAMEWORK_CONFIGS[framework]
        for sm in fw_config['source_members']:
            registry.add_source_member(sm)
        logger.debug('[SourceDiscovery][C++] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery][C++] No C++ framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'root_node'):
        _walk_for_functions(tree.root_node, file_path or project_dir, registry)

    # 日志汇总
    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery][C++] User source producers ({}): {}'.format(
            len(names), names))

    return registry
