"""
JavaScript Source Discovery Module

Discovers:
1. Framework detection via package.json (Express, Koa, Hapi, Fastify)
2. User-defined source producer functions (functions that directly access known sources)

AST traversal: esprima nodes have .type attribute; children accessed via vars(node).
lphply-style .fields does NOT exist — we iterate vars() and skip metadata fields.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.log import logger
from esprima import nodes as jsnodes


# ── Data Structures ──────────────────────────────────────────────────────


@dataclass
class SourceInfo:
    """Describes a source entry point."""
    type: str = ''           # 'builtin' | 'framework' | 'user_defined'
    name: str = ''           # Source name / pattern
    origin: str = ''         # File:line where discovered
    framework: str = ''      # Framework name if applicable


@dataclass
class SourceRegistry:
    """Central registry for all source information."""
    # Known source member-expression chains: 'location.hash', 'req.query', etc.
    source_members: Set[str] = field(default_factory=set)
    # Known source variable names: 'process', 'arguments', etc.
    source_variables: Set[str] = field(default_factory=set)
    # Framework request method calls: (obj_name, method_name)
    # Fix 49c: 文件作用域源变量(Vue props)。key=filepath, value=set(var names)。
    file_scoped_source_vars: Dict[str, set] = field(default_factory=dict)
    framework_request_methods: Set[Tuple[str, str]] = field(default_factory=set)
    # User-defined source producer functions: func_name -> SourceInfo
    user_source_functions: Dict[str, SourceInfo] = field(default_factory=dict)
    # Detected framework
    framework: str = ''

    # ── query helpers ──

    def is_source_variable(self, name: str) -> bool:
        return name in self.source_variables

    def is_source_member(self, chain: str) -> bool:
        """Check if a member-expression chain matches any known source (prefix-aware).

        Exact match: ``req.query`` ∈ source_members → True
        Prefix match (one extra segment): ``window.location.href`` starts
        with ``window.location.`` → True (``href`` is a known location
        property registered in source_members as ``location.href``).
        But ``window.location.replace`` → False because ``replace`` is not
        a known source property of the ``location`` object.
        """
        if chain in self.source_members:
            return True
        # Pre-compute known property suffixes: last segment of every SR entry
        # that is longer than one segment.  Used to validate prefix matches.
        for src in self.source_members:
            if chain.startswith(src + '.'):
                remainder = chain[len(src) + 1:]
                if '.' not in remainder:
                    # One extra property level — only allow if the
                    # remainder is a known source property (i.e., some SR
                    # entry ends with ".<remainder>").
                    for sm2 in self.source_members:
                        if sm2.endswith('.' + remainder):
                            return True
                    # Also allow if src itself has sub-properties registered
                    # (e.g., src=window.location, remainder=href, and
                    # location.href is in SR).
                    for sm2 in self.source_members:
                        if sm2 == remainder or sm2.endswith(src.split('.')[-1] + '.' + remainder):
                            return True
                continue
            if chain.startswith(src + '['):
                return True
        return False

    def is_source_producer(self, func_name: str) -> Optional[SourceInfo]:
        return self.user_source_functions.get(func_name)

    def is_framework_request_method(self, obj_name: str, method_name: str) -> bool:
        return (obj_name, method_name) in self.framework_request_methods

    def add_user_source_function(self, func_name: str, info: SourceInfo):
        self.user_source_functions[func_name] = info

    def summary(self) -> str:
        parts = []
        if self.framework:
            parts.append('Framework: {0}'.format(self.framework))
        if self.user_source_functions:
            parts.append('User source producers ({0}): {1}'.format(
                len(self.user_source_functions), sorted(self.user_source_functions.keys())))
        return ', '.join(parts) if parts else 'No framework detected, no user source producers discovered'


# ── Framework Detection ───────────────────────────────────────────────────

_FRAMEWORK_PACKAGE_MAP = {
    'express': ['express'],
    'koa': ['koa'],
    'hapi': ['@hapi/hapi', 'hapi'],
    'fastify': ['fastify'],
    # Fix 49b: SPA 前端(Vue/Nuxt/React)的 HTTP 客户端——存储型 XSS 的
    # 污点入口是 API 响应体 (CVE-2026-116554: argilla axios.get 返回的
    # dataset.name 流入 v-html)。
    'axios': ['axios', '@nuxtjs/axios'],
}


# Fix 49b: axios 实例的常见宿主对象链(this.axios / $axios / app.$axios...)
_AXIOS_HOST_CHAINS = {
    'axios', '$axios', 'this.axios', 'this.$axios',
    'app.$axios', 'ctx.$axios', 'context.$axios', 'Vue.axios', 'http',
}
_AXIOS_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'request', '$get', '$post', '$put', '$delete'}

# _FRAMEWORK_CONFIGS 在下方 define_framework_configs 中按框架名填充;
# axios 无 source_members(响应不是成员表达式,是解构变量),请求方法
# 匹配走 _is_axios_response_call。


def detect_framework(project_dir: str) -> Optional[str]:
    """Detect JS framework by reading package.json (walks up to 5 levels)."""
    current = os.path.abspath(project_dir)
    for _ in range(5):
        pkg_path = os.path.join(current, 'package.json')
        if os.path.isfile(pkg_path):
            try:
                with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                    pkg = json.load(f)
                deps: Dict[str, str] = {}
                for key in ('dependencies', 'devDependencies', 'peerDependencies'):
                    deps.update(pkg.get(key, {}))
                for fw_name, pkgs in _FRAMEWORK_PACKAGE_MAP.items():
                    if any(p in deps for p in pkgs):
                        return fw_name
            except (json.JSONDecodeError, OSError):
                pass
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


# ── Builtin & Framework Source Patterns ──────────────────────────────────

_BUILTIN_SOURCE_MEMBERS = {
    # Browser / DOM
    'location.hash', 'location.search', 'location.href',
    'location.pathname', 'location.origin', 'location.protocol',
    'document.cookie', 'document.URL', 'document.documentURI',
    'document.referrer', 'document.domain', 'document.baseURI',
    'window.name', 'window.location',
    # Common HTTP request sources (Express/Koa/NestJS/Fastify)
    'req.query', 'req.body', 'req.params', 'req.headers', 'req.cookies',
    'req.files', 'req.url', 'req.method',
    'request.query', 'request.body', 'request.params',
    'request.headers', 'request.cookies',
    'ctx.query', 'ctx.querystring', 'ctx.params',
    'ctx.request.body', 'ctx.request.query',
}

_CHROME_EXT_SOURCE_MEMBERS = {
    'chrome.tabs.query', 'chrome.tabs.get', 'chrome.tabs.getCurrent',
    'chrome.tabs.getSelected', 'chrome.tabs.getAllInWindow',
    'chrome.runtime.onMessage', 'chrome.runtime.onConnect',
    'chrome.runtime.onMessageExternal', 'chrome.runtime.onConnectExternal',
    'chrome.cookies.get', 'chrome.cookies.getAll',
}

_FRAMEWORK_CONFIGS = {
    # Fix 49b: axios —— 响应体即污点入口(SPA 存储型 XSS)。响应绑定走
    # _mark_axios_response_bindings 的源变量登记,这里留空配置占位。
    'axios': {
        'source_members': set(),
        'request_methods': set(),
    },
    'express': {
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
    'koa': {
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
        'source_members': {
            'request.query', 'request.params', 'request.payload',
            'request.headers',
        },
        'request_methods': {
            ('request', 'query'), ('request', 'param'),
            ('request', 'payload'),
        },
    },
    'fastify': {
        'source_members': {
            'request.query', 'request.body', 'request.params',
            'request.headers',
        },
        'request_methods': {
            ('request', 'query'), ('request', 'body'),
            ('request', 'params'),
        },
    },
}


# ── AST Traversal Helpers ───────────────────────────────────────────────
# esprima nodes: dict-like objects with .type + arbitrary attributes.
# No .fields list like lphply; no .child_nodes() like Python ast.
# We iterate vars() and skip known metadata fields.

_METADATA_FIELDS = frozenset({
    'type', 'start', 'end', 'loc', 'range', 'raw', 'sourceType',
})


def _walk_esprima(node, callback):
    """Recursively walk esprima AST, calling *callback* for every node."""
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            _walk_esprima(item, callback)
        return
    # Skip primitives (str, int, float, bool, None) — they lack __dict__
    if not hasattr(node, '__dict__'):
        return
    if not hasattr(node, 'type'):
        return
    callback(node)
    for attr_name, val in vars(node).items():
        if attr_name in _METADATA_FIELDS:
            continue
        if val is not None and val is not node:
            _walk_esprima(val, callback)


def _is_member_expr(node) -> bool:
    """Check if node is any kind of member expression (static or computed)."""
    return isinstance(node, (jsnodes.StaticMemberExpression, jsnodes.ComputedMemberExpression))


def _extract_member_chain(node) -> str:
    """Reconstruct a MemberExpression chain as a dot-separated string.

    ``req.query.name`` → ``'req.query.name'``
    ``arr[0]``          → ``'arr[...]'``
    """
    if _is_member_expr(node):
        obj_str = _extract_member_chain(node.object)
        if isinstance(node, jsnodes.ComputedMemberExpression):
            prop_str = _extract_member_chain(node.property)
            return '{0}[{1}]'.format(obj_str, prop_str) if obj_str else '[...]'
        prop_str = _extract_member_chain(node.property)
        return '{0}.{1}'.format(obj_str, prop_str) if obj_str else prop_str
    if isinstance(node, jsnodes.Identifier):
        return node.name
    if isinstance(node, jsnodes.ThisExpression):
        return 'this'
    return ''


def _extract_root_name(node) -> str:
    """Return the leftmost Identifier name of a member-expression chain."""
    if isinstance(node, jsnodes.Identifier):
        return node.name
    if isinstance(node, jsnodes.ThisExpression):
        return 'this'
    if _is_member_expr(node):
        return _extract_root_name(node.object)
    return ''


# ── Source Detection (single node, non-recursive) ───────────────────────


def _node_contains_source(node, registry: SourceRegistry) -> bool:
    """Return True if *node* itself (not its children) directly accesses a known source."""
    if node is None or not hasattr(node, 'type'):
        return False

    # MemberExpression: e.g. location.hash, req.query.name
    if _is_member_expr(node):
        chain = _extract_member_chain(node)
        if chain and registry.is_source_member(chain):
            return True

    # Identifier: direct reference to a source variable
    if isinstance(node, jsnodes.Identifier):
        if registry.is_source_variable(node.name):
            return True

    # CallExpression on framework request object: e.g. req.query('id')
    if isinstance(node, jsnodes.CallExpression):
        callee = node.callee
        if _is_member_expr(callee):
            obj_name = _extract_root_name(callee.object)
            method_name = getattr(callee.property, 'name', '')
            if obj_name and method_name and registry.is_framework_request_method(obj_name, method_name):
                return True

    return False


def _find_return_statements(body_stmts: list):
    """从函数体语句列表中收集所有 ReturnStatement 节点的 argument"""
    returns = []
    if not body_stmts:
        return returns

    def _walk(nodes):
        if isinstance(nodes, list):
            for node in nodes:
                _walk(node)
        elif hasattr(nodes, 'type'):
            if nodes.type == 'ReturnStatement':
                arg = getattr(nodes, 'argument', None)
                if arg:
                    returns.append(arg)
            # 不递归进入函数嵌套（如内部函数定义）
            elif nodes.type not in ('FunctionDeclaration', 'FunctionExpression',
                                     'ArrowFunctionExpression'):
                for attr_name, val in vars(nodes).items():
                    if attr_name in _METADATA_FIELDS:
                        continue
                    if isinstance(val, list):
                        _walk(val)
                    elif hasattr(val, 'type'):
                        _walk(val)

    _walk(body_stmts)
    return returns


def _function_body_contains_source(body_stmts: list, registry: SourceRegistry) -> bool:
    """Check if any return statement's value contains or depends on a known source.

    Previously this walked all nodes in the function body, which over-marked
    functions whose return values had nothing to do with user input.
    Now only marks a function as source producer when at least one return
    statement's argument directly references a source.
    """
    if not body_stmts:
        return False

    return_args = _find_return_statements(body_stmts)

    # 没有 return 语句 → 返回值不携带 source
    if not return_args:
        return False

    for arg in return_args:
        if _node_contains_source(arg, registry):
            return True

    return False


# ── Function Discovery ─────────────────────────────────────────────────


def _is_axios_response_call(node) -> bool:
    """node 是 axios 宿主链上的请求调用(this.axios.get(...) / $axios.get(...) / axios(...))"""
    if not isinstance(node, jsnodes.CallExpression):
        return False
    callee = node.callee
    # 直接调用: axios(...) / $axios(...)
    if isinstance(callee, jsnodes.Identifier) and callee.name in _AXIOS_HOST_CHAINS:
        return True
    if _is_member_expr(callee):
        chain = _extract_member_chain(callee)  # e.g. 'this.axios.get'
        if chain and '.' in chain:
            host, method = chain.rsplit('.', 1)
            if method in _AXIOS_METHODS and (host in _AXIOS_HOST_CHAINS or host.split('.')[-1] in ('axios', '$axios')):
                return True
    return False


def _ts_node_type(node) -> str:
    return getattr(node, 'type', '') or ''


def _ts_children(node):
    """tree-sitter Node 的子节点列表(named + unnamed,保序)。"""
    out = []
    try:
        for i in range(node.child_count):
            c = node.child(i)
            if c is not None:
                out.append(c)
    except Exception:
        pass
    return out


def _mark_axios_response_bindings(nodes, registry: SourceRegistry, _fp_hint: str = ''):
    """遍历 AST,把 axios 响应绑定(含解构)登记为源变量"""
    if isinstance(nodes, list):
        for node in nodes:
            _mark_axios_response_bindings(node, registry, _fp_hint)
        return
    # Fix 49b-v4: pretreatment 存的 TS ast_nodes 是 tree_sitter Tree(非 Node),
    # 没有 .type 属性,会在下方 hasattr 检查处整体静默返回 → 解包 root_node。
    if nodes is not None and hasattr(nodes, 'root_node') and not hasattr(nodes, 'type'):
        nodes = nodes.root_node
    if nodes is None or not hasattr(nodes, 'type'):
        return

    # Fix 49b-v3: tree-sitter 节点(TS AST 无 __dict__,vars() 会崩)。
    # 形态: lexical_declaration > variable_declarator
    #   (value: await_expression > call_expression (this.axios.get ...),
    #    name: object_pattern > shorthand_property_identifier_pattern 'data')
    _t = _ts_node_type(nodes)
    if _t == 'variable_declarator':
        val = nodes.child_by_field_name('value')
        name_node = nodes.child_by_field_name('name')
        while val is not None and _ts_node_type(val) == 'await_expression':
            # tree-sitter await_expression 的 call 是匿名子节点(无 'value' 字段名)
            _named = [c for c in val.named_children] if hasattr(val, 'named_children') else []
            val = _named[0] if _named else None
        # Fix 49c (tree-sitter): __vue_props__(a, b) 标记调用
        _val0 = nodes.child_by_field_name('value')
        if _val0 is not None and _ts_node_type(_val0) == 'call_expression':
            _fn0 = _val0.child_by_field_name('function')
            if _fn0 is not None and hasattr(_fn0, 'text') and _fn0.text.decode('utf8', 'ignore') == '__vue_props__':
                _argf = _val0.child_by_field_name('arguments')
                if _argf is not None:
                    for _ch in _argf.named_children:
                        if _ts_node_type(_ch) == 'identifier':
                            registry.file_scoped_source_vars.setdefault(_fp_hint, set()).add(
                                _ch.text.decode('utf8', 'ignore'))

        if val is not None and _ts_node_type(val) == 'call_expression':
            fn = val.child_by_field_name('function')
            fn_s = fn.text.decode('utf8', 'ignore') if fn is not None and hasattr(fn, 'text') else ''
            host, _, method = fn_s.rpartition('.')
            if method in _AXIOS_METHODS and (host in _AXIOS_HOST_CHAINS or host.split('.')[-1] in ('axios', '$axios')):
                if name_node is not None:
                    nt = _ts_node_type(name_node)
                    if nt in ('identifier', 'shorthand_property_identifier_pattern'):
                        registry.source_variables.add(name_node.text.decode('utf8', 'ignore'))
                    elif nt == 'object_pattern':
                        for ch in name_node.children:
                            if _ts_node_type(ch) in ('shorthand_property_identifier_pattern', 'pair_pattern'):
                                v = ch.child_by_field_name('value') if _ts_node_type(ch) == 'pair_pattern' else ch
                                if v is not None and hasattr(v, 'text'):
                                    registry.source_variables.add(v.text.decode('utf8', 'ignore'))

    # Fix 49c (esprima): __vue_props__(a, b) 标记调用
    if isinstance(nodes, jsnodes.CallExpression):
        _c = nodes.callee
        if isinstance(_c, jsnodes.Identifier) and _c.name == '__vue_props__':
            for _a in (nodes.arguments or []):
                if isinstance(_a, jsnodes.Identifier):
                    registry.file_scoped_source_vars.setdefault(_fp_hint, set()).add(_a.name)

    # esprima 分支(原逻辑)
    if isinstance(nodes, jsnodes.VariableDeclarator):
        init = getattr(nodes, 'init', None)
        # 剥 await
        if isinstance(init, jsnodes.AwaitExpression):
            init = getattr(init, 'argument', None)
        if init is not None and _is_axios_response_call(init):
            pid = getattr(nodes, 'id', None)
            if pid is None:
                pass
            elif isinstance(pid, jsnodes.Identifier):
                registry.source_variables.add(pid.name)
            elif isinstance(pid, jsnodes.ObjectPattern) and hasattr(pid, 'properties'):
                for prop in pid.properties:
                    v = getattr(prop, 'value', None)
                    if isinstance(v, jsnodes.Identifier):
                        registry.source_variables.add(v.name)

    # tree-sitter 递归(children 是 list);esprima 节点有 .children 属性但为
    # None,须用 vars() 走原逻辑 —— 用 child_count 区分两者。
    if getattr(nodes, 'child_count', None) is not None and not isinstance(nodes, jsnodes.VariableDeclarator):
        for ch in nodes.children:
            _mark_axios_response_bindings(ch, registry, _fp_hint)
        return

    for attr_name, val in vars(nodes).items():
        if attr_name in _METADATA_FIELDS:
            continue
        if isinstance(val, list):
            _mark_axios_response_bindings(val, registry, _fp_hint)
        elif hasattr(val, 'type'):
            _mark_axios_response_bindings(val, registry, _fp_hint)


def _walk_for_functions(nodes, filepath: str, registry: SourceRegistry):
    """Walk AST to find FunctionDeclaration / MethodDefinition that access sources."""
    if isinstance(nodes, list):
        for node in nodes:
            _walk_for_functions(node, filepath, registry)
        return

    if nodes is None or not hasattr(nodes, 'type'):
        return

    lineno = getattr(nodes, 'start', '?')

    # FunctionDeclaration: function foo() { ... }
    if nodes.type == 'FunctionDeclaration':
        func_id = getattr(nodes, 'id', None)
        func_name = getattr(func_id, 'name', None) if func_id else None
        if func_name:
            body = getattr(nodes, 'body', None)
            body_stmts = getattr(body, 'body', []) if body else []
            if _function_body_contains_source(body_stmts, registry):
                registry.add_user_source_function(func_name, SourceInfo(
                    type='user_defined', name=func_name,
                    origin='{0}:{1}'.format(os.path.basename(filepath), lineno),
                ))

    # ClassMethod in classes
    elif nodes.type == 'ClassMethod' or isinstance(nodes, jsnodes.ClassMethod):
        key = getattr(nodes, 'key', None)
        func_name = getattr(key, 'name', None) if isinstance(key, jsnodes.Identifier) else None
        if func_name:
            value = getattr(nodes, 'value', None)
            body = getattr(value, 'body', None) if value else None
            body_stmts = getattr(body, 'body', []) if body else []
            if _function_body_contains_source(body_stmts, registry):
                registry.add_user_source_function(func_name, SourceInfo(
                    type='user_defined', name=func_name,
                    origin='{0}:{1}'.format(os.path.basename(filepath), lineno),
                ))

    # Recurse into children
    for attr_name, val in vars(nodes).items():
        if attr_name in _METADATA_FIELDS:
            continue
        if val is not None and val is not nodes:
            _walk_for_functions(val, filepath, registry)


# ── Main Entry Point ────────────────────────────────────────────────────


def discover_sources(project_dir: str, ast_object, controlled_list=None) -> SourceRegistry:
    """Run source discovery for a JavaScript project.

    Args:
        project_dir: The project root directory.
        ast_object:  The Pretreatment singleton with .pre_result populated.
        controlled_list: Optional list of extra controllable source names from tamper framework.

    Returns:
        A SourceRegistry with all discovered sources.
    """
    registry = SourceRegistry()

    # Step 1: Builtin sources (always available)
    registry.source_members.update(_BUILTIN_SOURCE_MEMBERS)
    registry.source_members.update(_CHROME_EXT_SOURCE_MEMBERS)

    # Step 2: Framework detection + source injection
    framework = detect_framework(project_dir)
    if framework and framework in _FRAMEWORK_CONFIGS:
        cfg = _FRAMEWORK_CONFIGS[framework]
        registry.source_members.update(cfg['source_members'])
        registry.framework_request_methods.update(cfg['request_methods'])
        registry.framework = framework
        logger.info('[SourceDiscovery] Detected framework: {0}'.format(framework))
    else:
        logger.info('[SourceDiscovery] No JS framework detected')

    # Step 3: User-defined source producer discovery
    if hasattr(ast_object, 'pre_result') and ast_object.pre_result:
        for filepath, info in ast_object.pre_result.items():
            if info.get('language') != 'javascript':
                continue
            ast_nodes = info.get('ast_nodes')
            if not ast_nodes:
                continue
            try:
                _walk_for_functions(ast_nodes, filepath, registry)
                # Fix 49b: axios 响应解构 —— const { data } = await this.axios.get(...)
                # 把 data(及裸 const resp = await axios.get)登记为源变量,
                # 使 `return data` 能把仓库方法标记为源生产者。
                _mark_axios_response_bindings(ast_nodes, registry, _fp_hint=filepath)
            except Exception as e:
                logger.debug('[SourceDiscovery] Error processing {0}: {1}'.format(filepath, e))

    if registry.user_source_functions:
        logger.info('[SourceDiscovery] User source producers: {0}'.format(
            sorted(registry.user_source_functions.keys())))

    # 注入 tamper 框架的 controlled_list 作为额外的 source members
    if controlled_list:
        for src in controlled_list:
            registry.source_members.add(src)

    logger.info('[SourceDiscovery] Summary: {0}'.format(registry.summary()))
    return registry
