# -*- coding: utf-8 -*-
"""
    Python Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    自动发现 Python 项目中的 source（数据入口）：
    1. 内置 source：sys.argv, os.environ, input(), request 对象 (Flask/Django/FastAPI)
    2. 框架检测：从 requirements.txt / setup.py / pyproject.toml 检测 Web 框架
    3. 用户自定义 source producer：遍历 AST 找函数定义，检查函数体是否直接访问已知 source
    
    :author:    KunLun-M
    :license:   MIT
"""

import ast
import os
import json
from utils.log import logger


class SourceInfo:
    """source 信息"""
    __slots__ = ('source_type', 'origin', 'is_safe', 'passthrough')

    def __init__(self, source_type='builtin', origin='', is_safe=False, passthrough=False):
        self.source_type = source_type  # builtin / framework / user_defined
        self.origin = origin            # 来源描述
        self.is_safe = is_safe
        self.passthrough = passthrough

    def __repr__(self):
        return '<SourceInfo type={} origin={}>'.format(self.source_type, self.origin)


class SourceRegistry:
    """Source 注册表"""

    def __init__(self):
        # 已知 source 成员（变量/属性名），用于 AST 节点匹配
        self.source_members = set()
        # 用户自定义 source producer 函数名 → SourceInfo
        self.user_source_functions = {}

    def add_source_member(self, name):
        """注册一个 source 变量/属性"""
        self.source_members.add(name)

    def is_source_member(self, expr_str):
        """检查表达式字符串是否包含已知 source 成员
        
        支持前缀匹配：注册了 'request.args' 则 'request.args.get("x")' 也匹配
        """
        # 拒绝包含运算符的表达式名称（如 "request.META.get() || ''"）
        # 这些不是合法的 source member 名称
        if any(op in expr_str for op in ('||', '&&', ' and ', ' or ')):
            return False
        for sm in self.source_members:
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '['):
                return True
            if '.' in sm:
                # 注册了 'sys.argv'，匹配 'sys.argv[0]'
                parts = sm.split('.')
                if '.' in expr_str:
                    expr_parts = expr_str.split('.')
                    if expr_parts[:len(parts)] == parts:
                        return True
        return False

    def is_source_producer(self, func_name):
        """检查函数是否是用户自定义 source producer"""
        info = self.user_source_functions.get(func_name)
        return info if info else None

    def get_all_source_names(self):
        """获取所有 source 成员名称（用于注入 controlled_params）"""
        return list(self.source_members)


# ---------------------------------------------------------------------------
# 内置 source 定义
# ---------------------------------------------------------------------------

_BUILTIN_SOURCE_MEMBERS = {
    # HTTP 请求对象（通用，不依赖框架检测）
    'request.args',
    'request.form',
    'request.data',
    'request.json',
    'request.files',
    'request.cookies',
    'request.values',
    'request.get_json',
    'request.get_data',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'flask': {
        'detect_files': ['requirements.txt', 'setup.py', 'pyproject.toml'],
        'detect_packages': ['flask'],
        'source_members': {
            # Flask request 对象
            'request.args',
            'request.form',
            'request.data',
            'request.json',
            'request.files',
            'request.cookies',
            'request.values',
            'request.headers',
            'request.get_json',
            'request.get_data',
            'request.query_string',
            'request.remote_addr',
            # request.url removed: redirect(request.url) is the standard Flask
            # PRG (Post-Redirect-Get) self-redirect pattern, never an open
            # redirect. Query params are already covered by request.args.
            'request.referrer',
            # session removed: server-side data, not user input
            # Flask config
            'flask.request',
        },
    },
    'django': {
        'detect_files': ['requirements.txt', 'setup.py', 'pyproject.toml'],
        'detect_packages': ['django'],
        'source_members': {
            # Django HttpRequest
            'request.GET',
            'request.POST',
            'request.FILES',
            'request.COOKIES',
            'request.META',
            'request.body',
            'request.get_full_path',
            'request.get_host',
            'request.build_absolute_uri',
            # Django 常用 shortcut
            'HttpRequest.GET',
            'HttpRequest.POST',
            'HttpRequest.FILES',
            # Django forms
            'form.cleaned_data',
            'self.cleaned_data',
            # self.kwargs/self.args removed: too generic.
            # They appear in pytest fixtures, celery extensions, and non-view
            # code. Framework detection in setup.py can also false-positive
            # (e.g. celery lists 'django' as an optional extra dependency).
            # If needed, these can be re-added as user_source_functions via
            # _walk_for_functions when Django CBV patterns are detected.
        },
    },
    'fastapi': {
        'detect_files': ['requirements.txt', 'setup.py', 'pyproject.toml'],
        'detect_packages': ['fastapi'],
        'source_members': {
            # FastAPI 依赖注入参数（通常在函数签名中，但 body/params 是通用模式）
            'request.args',
            'request.query_params',
            'request.cookies',
            'request.headers',
            'request.body',
            'request.json',
        },
    },
}

# 框架请求方法参数（函数参数级别的 source）
_FRAMEWORK_REQUEST_PARAMS = {
    'flask': {'request'},
    'django': {'request'},
    'fastapi': {'request'},
}


# ---------------------------------------------------------------------------
# 框架检测
# ---------------------------------------------------------------------------

def detect_framework(project_dir):
    """从 requirements.txt / setup.py / pyproject.toml 检测 Web 框架
    
    向上遍历最多 5 级目录查找配置文件。
    返回 (framework_name, None) 或 (None, None)
    """
    search_dir = project_dir
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        # 检查 requirements.txt
        req_file = os.path.join(search_dir, 'requirements.txt')
        if os.path.isfile(req_file):
            try:
                with open(req_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().lower()
                for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                    for pkg in fw_config['detect_packages']:
                        if pkg in content:
                            return fw_name
            except Exception:
                pass

        # 检查 setup.py
        setup_file = os.path.join(search_dir, 'setup.py')
        if os.path.isfile(setup_file):
            try:
                with open(setup_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().lower()
                for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                    for pkg in fw_config['detect_packages']:
                        if pkg in content:
                            return fw_name
            except Exception:
                pass

        # 检查 pyproject.toml
        toml_file = os.path.join(search_dir, 'pyproject.toml')
        if os.path.isfile(toml_file):
            try:
                with open(toml_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().lower()
                for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                    for pkg in fw_config['detect_packages']:
                        if pkg in content:
                            return fw_name
            except Exception:
                pass

        # 向上一级
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent

    return None


# ---------------------------------------------------------------------------
# AST 遍历：source producer 发现
# ---------------------------------------------------------------------------

def _node_contains_source(node, registry):
    """递归检查 AST 节点是否直接访问已知 source
    
    使用 ast.walk() 遍历所有子节点。
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if child.id in registry.source_members:
                return True
        elif isinstance(child, ast.Attribute):
            attr_str = _expr_to_str_simple(child)
            if attr_str and registry.is_source_member(attr_str):
                return True
        elif isinstance(child, ast.Subscript):
            sub_str = _expr_to_str_simple(child)
            if sub_str and registry.is_source_member(sub_str):
                return True
        elif isinstance(child, ast.Call):
            # 检查函数调用是否是已知 source（如 input()）
            if isinstance(child.func, ast.Name):
                if child.func.id in registry.source_members:
                    return True
            # 检查方法调用（如 request.get_json()）
            elif isinstance(child.func, ast.Attribute):
                call_str = _expr_to_str_simple(child.func)
                if call_str and registry.is_source_member(call_str):
                    return True
    return False


def _expr_to_str_simple(node):
    """将 AST 节点转为简单字符串（仅用于 source 匹配）
    
    支持链式属性：a.b.c → 'a.b.c'
    支持下标：a['b'] → 'a.b'（简化处理）
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        val = _expr_to_str_simple(node.value)
        if val:
            return val + '.' + node.attr
        return node.attr
    elif isinstance(node, ast.Subscript):
        val = _expr_to_str_simple(node.value)
        if val:
            return val  # 简化：忽略下标索引
        return None
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id + '()'
        elif isinstance(node.func, ast.Attribute):
            val = _expr_to_str_simple(node.func)
            if val:
                return val + '()'
    return None


def _function_returns_source(func_def, registry):
    """检查函数定义的 return 语句值是否包含已知 source

    只分析 return 语句的表达式，不检查函数体内其他位置的 source 访问。
    """
    for child in ast.walk(func_def):
        if isinstance(child, ast.Return) and child.value:
            if _node_contains_source(child.value, registry):
                return True
    return False


def _walk_for_functions(tree, file_path, registry):
    """遍历 AST 找函数定义，检查 return 语句的值是否直接引用已知 source

    只标记 return 值包含 source 的函数为 source producer，
    而非函数体内任何位置碰过 source 就标记。
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name

            # 跳过 dunder 方法和私有方法（以下划线开头但不是 __init__）
            if func_name.startswith('_') and func_name != '__init__':
                continue

            # 只检查 return 语句的值是否包含 source
            if not _function_returns_source(node, registry):
                continue

            if func_name not in registry.user_source_functions:
                source_info = SourceInfo(
                    source_type='user_defined',
                    origin='{}:{}'.format(os.path.basename(file_path), getattr(node, 'lineno', '?')),
                    is_safe=False,
                    passthrough=True,
                )
                registry.user_source_functions[func_name] = source_info
                logger.debug('[SourceDiscovery] User source producer: {} in {}'.format(
                    func_name, file_path))


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, controlled_list=None):
    """发现 Python 项目中的 source

    :param project_dir: 项目目录路径
    :param tree: ast.Module AST 树
    :param file_path: 当前文件路径（用于日志）
    :param controlled_list: Optional list of extra controllable source names from tamper framework
    :return: SourceRegistry 实例
    """
    registry = SourceRegistry()

    # 1. 加载内置 source
    for sm in _BUILTIN_SOURCE_MEMBERS:
        registry.add_source_member(sm)

    # 2. 检测框架
    framework = detect_framework(project_dir)
    if framework and framework in _FRAMEWORK_CONFIGS:
        fw_config = _FRAMEWORK_CONFIGS[framework]
        for sm in fw_config['source_members']:
            registry.add_source_member(sm)
        logger.debug('[SourceDiscovery] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery] No Python framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'body'):
        _walk_for_functions(tree, file_path or project_dir, registry)

    # 日志汇总
    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery] User source producers ({}): {}'.format(
            len(names), names))

    # 注入 tamper 框架的 controlled_list 作为额外的 source members
    if controlled_list:
        for src in controlled_list:
            registry.add_source_member(src)

    return registry
