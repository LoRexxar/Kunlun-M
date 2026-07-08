# -*- coding: utf-8 -*-
"""
    Go Source Discovery 预处理模块
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    自动发现 Go 项目中的 source（数据入口）：
    1. 内置 source：os.Args, os.Getenv, flag.*, r.URL.Query(), r.FormValue 等
    2. 框架检测：从 go.mod 检测 Web 框架（Gin/Echo/Fiber/Beego/Chi/Mux）
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
        # 已知 source 成员（用于字符串匹配，注入 GO_CONTROLLED_SOURCES）
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
# 内置 source 定义（与 GO_CONTROLLED_SOURCES 互补）
# ---------------------------------------------------------------------------

_BUILTIN_SOURCE_MEMBERS = {
    # 命令行参数
    'os.Args',
    # 环境变量
    'os.Getenv',
    'os.LookupEnv',
    # flag 包
    'flag.String',
    'flag.Int',
    'flag.Bool',
    # io — 流读取（参数来自外部 I/O）
    'io.ReadAll',
    'bufio.Scanner',
    # URL 解析
    'url.Parse',
    # net 标准库
    'net/http',
}

# ---------------------------------------------------------------------------
# 框架配置
# ---------------------------------------------------------------------------

_FRAMEWORK_CONFIGS = {
    'gin': {
        'detect_modules': ['gin-gonic/gin'],
        'source_members': {
            'gin.Default',
            'gin.New',
            'c.Query',
            'c.DefaultQuery',
            'c.Param',
            'c.PostForm',
            'c.DefaultPostForm',
            'c.GetHeader',
            'c.GetCookie',
            'c.ShouldBind',
            'c.ShouldBindJSON',
            'c.ShouldBindQuery',
            'c.ShouldBindXML',
            'c.ShouldBindYAML',
            'c.Request',
        },
    },
    'echo': {
        'detect_modules': ['labstack/echo'],
        'source_members': {
            'echo.QueryParams',
            'echo.FormValue',
            'echo.Param',
            'echo.Cookie',
            'c.QueryParam',
            'c.FormValue',
            'c.Param',
            'c.Cookie',
            'c.Request',
        },
    },
    'fiber': {
        'detect_modules': ['gofiber/fiber'],
        'source_members': {
            'fiber.Query',
            'fiber.Params',
            'fiber.Body',
            'fiber.Get',
            'c.Query',
            'c.Params',
            'c.Body',
            'c.Cookies',
            'c.Get',
            'c.FormValue',
        },
    },
    'beego': {
        'detect_modules': ['beego'],
        'source_members': {
            'beego.Input',
            'beego.GetString',
            'beego.GetStrings',
            'beego.GetInt',
            'beego.GetBool',
            'this.GetString',
            'this.GetStrings',
            'this.Ctx.Input',
            'this.Ctx.Request',
        },
    },
    'chi': {
        'detect_modules': ['go-chi/chi'],
        'source_members': {
            'chi.URLParam',
            'chi.URLParamFromCtx',
            'r.URL.Query',
        },
    },
    'gorilla_mux': {
        'detect_modules': ['gorilla/mux'],
        'source_members': {
            'mux.Vars',
            'r.URL.Query',
        },
    },
}


# ---------------------------------------------------------------------------
# 框架检测
# ---------------------------------------------------------------------------

def detect_framework(project_dir):
    """从 go.mod 检测 Go Web 框架
    
    向上遍历最多 5 级目录查找 go.mod。
    返回 framework_name 或 None
    """
    search_dir = project_dir
    for _ in range(5):
        if not search_dir or search_dir == '/':
            break

        go_mod = os.path.join(search_dir, 'go.mod')
        if os.path.isfile(go_mod):
            try:
                with open(go_mod, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().lower()
                for fw_name, fw_config in _FRAMEWORK_CONFIGS.items():
                    for mod in fw_config['detect_modules']:
                        if mod in content:
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
    elif node_type == 'selector_expression':
        operand = node.child_by_field_name('operand')
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
    elif node_type in ('indexed_expression', 'subscript_expression'):
        obj = node.child_by_field_name('x')
        return _expr_to_str(obj)
    elif node_type == 'qualified_identifier':
        # import.path.Func or package.Func
        parts = []
        for child in node.children_by_field_name('name') or node.children:
            if hasattr(child, 'type') and child.type == 'identifier':
                parts.append(child.text.decode('utf-8', errors='replace'))
        return '.'.join(parts) if parts else text

    # Fallback
    return text


def _node_contains_source(node, registry, _depth=0):
    """递归检查 tree-sitter 节点是否直接访问已知 source
    
    只做一层分析（不递归进入被调用函数体）。
    """
    if node is None or _depth > 15:
        return False

    # 检查当前节点文本
    expr_str = _expr_to_str(node)
    if expr_str:
        # 精确匹配或前缀匹配
        for sm in registry.source_members:
            if sm == expr_str or expr_str.startswith(sm + '.') or expr_str.startswith(sm + '('):
                return True
        # 子串匹配（用于 selector_expression 如 r.URL.Query()）
        for sm in registry.source_members:
            if '.' in sm and sm in expr_str:
                return True

    node_type = node.type

    # selector_expression: obj.method 或 pkg.func
    if node_type == 'selector_expression':
        full_str = _expr_to_str(node)
        if full_str:
            for sm in registry.source_members:
                if sm in full_str:
                    return True

    # call_expression: func(args)
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


def _function_returns_source(func_node, registry):
    """检查 Go 函数定义的 return 语句值是否包含已知 source

    只分析 return_statement 的表达式，不检查函数体内其他位置的 source。
    """
    if func_node is None:
        return False

    def _walk_return(node):
        """在函数体内查找 return_statement 并检查其表达式"""
        if node is None or not hasattr(node, 'type'):
            return False
        if node.type == 'return_statement':
            for child in node.children:
                if hasattr(child, 'type') and child.type != 'return':
                    if _node_contains_source(child, registry):
                        return True
            return False
        # 不进入嵌套函数
        if node.type == 'function_declaration':
            return False
        for child in node.children:
            if _walk_return(child):
                return True
        return False

    # 从子节点开始遍历，避免 func_node 自身（function_declaration）被跳过
    for child in func_node.children:
        if _walk_return(child):
            return True
    return False


def _walk_for_functions(root_node, file_path, registry):
    """遍历 tree-sitter AST 找函数定义，检查函数体是否直接访问已知 source
    
    只做一层分析：检查函数体的 return 语句或表达式是否直接引用已知 source。
    """
    if root_node is None:
        return

    for child in root_node.children:
        if child is None or not hasattr(child, 'type'):
            continue

        if child.type == 'function_declaration':
            func_name_node = child.child_by_field_name('name')
            if not func_name_node:
                continue
            func_name = func_name_node.text.decode('utf-8', errors='replace')

            # 跳过私有函数（小写开头）和 init/main
            if func_name.startswith('_') or func_name in ('init', 'main'):
                continue

            # 检查 return 语句的值是否包含已知 source
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
                logger.debug('[SourceDiscovery][Go] User source producer: {} in {}'.format(
                    func_name, file_path))

        # 递归进入方法声明（Go 的 method 是 function_declaration 但 receiver 不同）
        # tree-sitter go 中 method_declaration 是 function_declaration 的子类型
        # 已经在 function_declaration 处理


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, extra_sources=None):
    """发现 Go 项目中的 source
    
    :param project_dir: 项目目录路径
    :param tree: tree-sitter Tree 对象
    :param file_path: 当前文件路径
    :param extra_sources: 额外 source 列表（如 GO_CONTROLLED_SOURCES），避免循环导入
    :return: SourceRegistry 实例
    """
    registry = SourceRegistry()

    # 1. 加载内置 source
    for sm in _BUILTIN_SOURCE_MEMBERS:
        registry.add_source_member(sm)

    # 1b. 加载额外 source 列表（由调用方传入，避免循环导入）
    if extra_sources:
        for sm in extra_sources:
            registry.add_source_member(sm)

    # 2. 检测框架
    framework = detect_framework(project_dir)
    if framework and framework in _FRAMEWORK_CONFIGS:
        fw_config = _FRAMEWORK_CONFIGS[framework]
        for sm in fw_config['source_members']:
            registry.add_source_member(sm)
        logger.debug('[SourceDiscovery][Go] Detected framework: {}'.format(framework))
    else:
        logger.debug('[SourceDiscovery][Go] No Go framework detected')

    # 3. 遍历 AST 发现用户自定义 source producer
    if tree and hasattr(tree, 'root_node'):
        _walk_for_functions(tree.root_node, file_path or project_dir, registry)

    # 日志汇总
    if registry.user_source_functions:
        names = sorted(registry.user_source_functions.keys())
        logger.debug('[SourceDiscovery][Go] User source producers ({}): {}'.format(
            len(names), names))

    return registry
