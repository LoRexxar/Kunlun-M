# -*- coding: utf-8 -*-
"""
    C# Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    自动发现 C# 项目中的 source（数据入口）：
    1. 内置 source：HttpContext.Request, Environment.GetEnvironmentVariable, Console.ReadLine 等
    2. 框架检测：从 .csproj 检测 Web 框架（ASP.NET Core）
    3. 用户自定义 source producer：遍历 tree-sitter AST 找函数定义

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
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '(') or expr_str.startswith(sm + '['):
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
    # ASP.NET Core / ASP.NET MVC
    'Request.QueryString',
    'Request.Form',
    'Request.Cookies',
    'Request.Headers',
    'Request.UserAgent',
    'Request.Url',
    'Request.RawUrl',
    'Request.Path',
    'Request.FilePath',
    'Request.InputStream',
    'Request.Body',
    'Request.Files',
    'Request["',
    'Request.Form["',
    'Request.QueryString["',
    'Request.Cookies["',
    'Request.Headers["',
    # Short forms (normalizer may strip Request. prefix)
    'QueryString',
    'QueryString["',
    'Form',
    'Form["',
    'Cookies',
    'Cookies["',
    'Headers',
    'Headers["',
    'HttpRequest.QueryString',
    'HttpRequest.Form',
    'HttpRequest.Cookies',
    'HttpRequest.Headers',
    'HttpRequest.Files',
    'HttpContext.Request',
    'HttpContext.Current.Request',

    # ASP.NET Core Controller
    'HttpContext.Request',
    'HttpRequest',
    'HttpResponse',

    # WebUtility / HttpUtility
    'HttpUtility.UrlDecode',
    'HttpUtility.HtmlDecode',
    'WebUtility.UrlDecode',
    'WebUtility.HtmlDecode',

    # MapPath
    'Server.MapPath',
    'HttpServerUtility.MapPath',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'aspnet_core': {
        'detect_files': ['.csproj'],
        'detect_keywords': ['Microsoft.AspNetCore', 'AspNetCore'],
        'source_members': {
            'HttpContext.Request',
            'HttpRequest',
            'HttpResponse',
            'IHttpContextAccessor',
            'Request.QueryString',
            'Request.Form',
            'Request.Cookies',
            'Request.Headers',
            'Request.Body',
            'Request.Path',
            'Request.Url',
            'Controller.HttpContext',
            'ControllerBase.HttpContext',
            'ControllerBase.Request',
            'Controller.Request',
            ' ControllerBase.User',
            'PageModel.Request',
            'RazorPage.Request',
        },
    },
    'aspnet_mvc': {
        'detect_files': ['web.config'],
        'detect_keywords': ['System.Web.Mvc', 'System.Web.Http'],
        'source_members': {
            'HttpContext.Current.Request',
            'HttpContext.Current.Response',
            'HttpRequest',
            'HttpResponse',
            'Request.QueryString',
            'Request.Form',
            'Request.Cookies',
            'Request.Headers',
            'Request.InputStream',
            'Server.MapPath',
            'HttpServerUtility.MapPath',
        },
    },
}


# ---------------------------------------------------------------------------
# 框架检测
# ---------------------------------------------------------------------------

def detect_framework(project_dir):
    """从项目文件检测 C# Web 框架"""
    search_dir = project_dir
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        # 检查 .csproj
        csproj = os.path.join(search_dir, '*.csproj')
        for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
            detect_files = fw_config.get('detect_files', [])
            detect_keywords = fw_config.get('detect_keywords', [])
            for df in detect_files:
                fp = os.path.join(search_dir, df)
                if os.path.isfile(fp):
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read()
                        for kw in detect_keywords:
                            if kw in content:
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
    """将 tree-sitter 节点转为简单字符串（仅用于 source 匹配）"""
    if node is None:
        return None

    node_type = node.type
    try:
        text = node.text.decode('utf-8', errors='replace')
    except (AttributeError, UnicodeDecodeError):
        return None

    if node_type == 'identifier':
        return text
    elif node_type == 'member_access_expression':
        for child in node.children:
            if child.type == 'identifier':
                continue
        # 收集所有部分
        parts = []
        for c in node.children:
            if c.type == 'identifier' or c.type in ('.',):
                parts.append(text if c.type == '.' else c.text.decode('utf-8', errors='replace'))
        full = node.text.decode('utf-8', errors='replace')
        return full
    elif node_type == 'invocation_expression':
        func_node = None
        for child in node.children:
            if child.type in ('identifier', 'member_access_expression', 'generic_name'):
                func_node = child
                break
        if func_node:
            return _expr_to_str(func_node)
        return text
    elif node_type == 'qualified_name':
        return text

    return text


def _node_contains_source(node, registry, _depth=0):
    """递归检查 tree-sitter 节点是否直接访问已知 source"""
    if node is None or _depth > 15:
        return False

    expr_str = _expr_to_str(node)
    if expr_str:
        for sm in registry.source_members:
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '('):
                return True
            if '.' in sm and sm in expr_str:
                return True

    if hasattr(node, 'children') and node.children:
        for child in node.children:
            if hasattr(child, 'type'):
                if _node_contains_source(child, registry, _depth + 1):
                    return True

    return False


def _function_returns_source(func_node, registry):
    """检查 C# 函数定义的 return 语句值是否包含已知 source"""
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
        if node.type in ('method_declaration', 'constructor_declaration',
                         'local_function_statement'):
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
    """遍历 tree-sitter AST 找函数定义，检查是否直接访问已知 source"""
    if root_node is None:
        return

    for child in root_node.children:
        if child is None or not hasattr(child, 'type'):
            continue

        if child.type == 'method_declaration':
            func_name_node = None
            for sc in child.children:
                if sc.type == 'identifier':
                    func_name_node = sc
                    break
            if not func_name_node:
                continue
            func_name = func_name_node.text.decode('utf-8', errors='replace')

            # 跳过一些标准函数
            if func_name.startswith('_') or func_name in ('Main', 'ToString', 'Equals',
                                                             'GetHashCode', 'GetType', 'Finalize',
                                                             'Dispose', 'InitializeComponent'):
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
                logger.debug('[SourceDiscovery][C#] User source producer: {} in {}'.format(
                    func_name, file_path))


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, extra_sources=None):
    """发现 C# 项目中的 source"""
    registry = SourceRegistry()

    # 1. 加载内置 source
    for sm in _BUILTIN_SOURCE_MEMBERS:
        registry.add_source_member(sm)

    # 1b. 加载额外 source 列表
    if extra_sources:
        for sm in extra_sources:
            registry.add_source_member(sm)

    # 2. 检测框架
    framework = detect_framework(project_dir)
    if framework and framework in _FRAMEWORK_CONFIGS:
        fw_config = _FRAMEWORK_CONFIGS[framework]
        for sm in fw_config['source_members']:
            registry.add_source_member(sm)
        logger.debug('[SourceDiscovery][C#] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery][C#] No C# framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'root_node'):
        _walk_for_functions(tree.root_node, file_path or project_dir, registry)

    # 日志汇总
    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery][C#] User source producers ({}): {}'.format(
            len(names), names))

    return registry
