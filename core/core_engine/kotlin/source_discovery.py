# -*- coding: utf-8 -*-
"""
    Kotlin Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    自动发现 Kotlin 项目中的 source（数据入口）：
    1. 内置 source：readLine, System.getenv, Scanner 等
    2. 框架检测：从 build.gradle 检测 Web 框架（Ktor/Spring Boot）
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
    # 命令行输入
    'readLine', 'readln', 'readlnOrNull',
    # System
    'System.console', 'System.getenv', 'System.getProperty',
    'System.`in`',
    # Java IO
    'java.io.BufferedReader', 'java.io.FileReader',
    'java.io.FileInputStream', 'java.io.InputStreamReader',
    'java.util.Scanner', 'Scanner',
    # 网络
    'java.net.URL', 'java.net.HttpURLConnection',
    'java.net.Socket', 'java.net.ServerSocket',
    # 编码解析
    'org.json.JSONObject', 'com.google.gson.Gson',
    'jackson.ObjectMapper',
    # 进程
    'Runtime.getRuntime', 'ProcessBuilder',
    # Kotlin IO
    'kotlinx.io.files.readFile',
    'kotlinx.coroutines.channels.Channel',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'ktor': {
        'detect_file': ['build.gradle', 'build.gradle.kts'],
        'detect_keyword': ['ktor'],
        'source_members': {
            'ApplicationCall',
            'call',
            'call.request',
            'call.parameters',
            'call.receive',
            'call.receiveParameters',
            'call.receiveText',
            'call.receiveStream',
            'request',
            'parameters',
            'sessions',
        },
    },
    'spring': {
        'detect_file': ['build.gradle', 'build.gradle.kts', 'pom.xml'],
        'detect_keyword': ['spring-boot-starter', 'spring-web'],
        'source_members': {
            'HttpServletRequest', 'HttpServletRequestWrapper',
            'RequestParam', 'PathVariable', 'RequestBody',
            'Model', 'ModelAndView',
            'Principal', 'Authentication',
            '@RequestParam', '@PathVariable', '@RequestBody',
            '@RequestHeader', '@CookieValue',
        },
    },
    'android': {
        'detect_file': ['build.gradle', 'build.gradle.kts'],
        'detect_keyword': ['com.android.application', 'androidx'],
        'source_members': {
            'Intent', 'Bundle', 'savedInstanceState',
            'getIntent', 'getStringExtra', 'getIntExtra',
            'getSerializableExtra', 'getParcelableExtra',
            'EditText', 'getText', 'toString',
            'Cursor', 'getColumnIndex', 'getString',
        },
    },
}


# ---------------------------------------------------------------------------
# 框架检测
# ---------------------------------------------------------------------------

def detect_framework(project_dir):
    """从 build.gradle / build.gradle.kts / pom.xml 检测 Kotlin 框架。

    向上遍历最多 5 级目录查找构建文件。
    返回 framework_name 或 None
    """
    search_dir = project_dir
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
            for detect_file in fw_config['detect_file']:
                build_file = os.path.join(search_dir, detect_file)
                if os.path.isfile(build_file):
                    try:
                        with open(build_file, 'r', encoding='utf-8', errors='replace') as f:
                            content = f.read().lower()
                        for kw in fw_config['detect_keyword']:
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
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '('):
                return True

    node_type = node.type

    if node_type in ('call_expression', 'dot_expression'):
        for child in node.children:
            if child.type in ('simple_identifier', 'user_type'):
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
    """检查 Kotlin 函数的 return 语句值是否包含已知 source"""
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
        if node.type in ('function_declaration', 'class_declaration',
                          'object_declaration', 'interface_declaration'):
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

        if child.type == 'function_declaration':
            func_name_node = None
            for c in child.children:
                if c.type == 'simple_identifier':
                    func_name_node = c
                    break
            if not func_name_node:
                continue
            func_name = func_name_node.text.decode('utf-8', errors='replace')

            # 跳过 main
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
                logger.debug('[SourceDiscovery][Kotlin] User source producer: {} in {}'.format(
                    func_name, file_path))

        # 递归进入类体
        if child.type in ('class_declaration', 'object_declaration',
                          'interface_declaration', 'enum_declaration'):
            body = None
            for c in child.children:
                if c.type == 'class_body':
                    body = c
                    break
            if body:
                _walk_for_functions(body, file_path, registry)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, extra_sources=None):
    """发现 Kotlin 项目中的 source

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
        logger.debug('[SourceDiscovery][Kotlin] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery][Kotlin] No Kotlin framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'root_node'):
        _walk_for_functions(tree.root_node, file_path or project_dir, registry)

    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery][Kotlin] User source producers ({}): {}'.format(
            len(names), names))

    return registry
