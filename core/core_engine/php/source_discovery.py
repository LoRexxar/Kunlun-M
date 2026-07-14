# -*- coding: utf-8 -*-

"""
Source Discovery Module for PHP

Pre-scan phase that discovers data entry points (sources) in a PHP project.

Two responsibilities:
1. Framework detection + framework source injection
2. Custom source function discovery (one-pass, direct source access only)

Usage:
    source_registry = discover_sources(project_dir, ast_object)
    # Then in scan engine, check source_registry for controllability
"""

import os
import json
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, Any

from phply import phpast as php

from utils.log import logger

# MethodCall types (including NullsafeMethodCall if available)
_METHOD_CALL_TYPES = (php.MethodCall, getattr(php, 'NullsafeMethodCall', php.MethodCall))
_OBJECT_PROPERTY_TYPES = (php.ObjectProperty, getattr(php, 'NullsafeProperty', php.ObjectProperty))


@dataclass
class SourceInfo:
    """Information about a source entry point."""
    type: str          # 'builtin' | 'framework' | 'user_defined'
    name: str          # e.g. '$_GET', 'input', 'getParam'
    framework: str = ''  # which framework (empty for builtin/user_defined)
    origin: str = ''     # where this source was discovered (e.g. 'File.php:15')


@dataclass
class SourceRegistry:
    """Registry of all known source entry points for a PHP project."""
    framework: Optional[str] = None

    # PHP builtin superglobals ($_SESSION / $_SERVER excluded — $_SESSION is
    # server-side session data; $_SERVER has mixed controllability handled
    # per-key by graph_analyzer._SERVER_UNCONTROLLED_KEYS).
    builtin_sources: Set[str] = field(default_factory=lambda: {
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
        '$_FILES', '$_ENV',
        '$HTTP_RAW_POST_DATA',
        '$HTTP_POST_FILES', '$HTTP_COOKIE_VARS', '$HTTP_REQUEST_VARS',
        '$HTTP_POST_VARS', '$HTTP_GET_VARS',
    })

    # Framework request object names (e.g. {'request', '$request'})
    framework_request_objects: Set[str] = field(default_factory=set)

    # Framework request method patterns: {method_name: SourceInfo}
    framework_methods: Dict[str, SourceInfo] = field(default_factory=dict)

    # Framework global source functions: {func_name: SourceInfo}
    framework_global_functions: Dict[str, SourceInfo] = field(default_factory=dict)

    # User-defined source producer functions: {func_name: SourceInfo}
    user_source_functions: Dict[str, SourceInfo] = field(default_factory=dict)

    def is_source_variable(self, name: str) -> bool:
        """Check if a variable name is a known source (superglobal)."""
        return name in self.builtin_sources

    def is_source_producer(self, func_name: str) -> Optional[SourceInfo]:
        """Check if a function name is a known source producer.

        Checks user-defined functions, framework global functions, and framework methods.
        Returns SourceInfo if matched, None otherwise.
        """
        if func_name in self.user_source_functions:
            return self.user_source_functions[func_name]
        if func_name in self.framework_global_functions:
            return self.framework_global_functions[func_name]
        if func_name in self.framework_methods:
            return self.framework_methods[func_name]
        return None

    def is_framework_request_method(self, obj_name: str, method_name: str) -> bool:
        """Check if a method call on an object is a framework source method.

        Example: $request->input() in Laravel -> True
        """
        if not self.framework:
            return False
        config = FRAMEWORK_CONFIGS.get(self.framework)
        if not config:
            return False
        # Check if the object is a request-like object
        if obj_name not in config['request_object_names']:
            return False
        # Check if the method is a source method
        return method_name in config['request_methods']

    def is_framework_global_function(self, func_name: str) -> bool:
        """Check if a function name is a framework global source function."""
        return func_name in self.framework_global_functions

    def add_framework(self, framework: str):
        """Initialize framework-specific source patterns."""
        self.framework = framework
        config = FRAMEWORK_CONFIGS[framework]

        self.framework_request_objects = set(config['request_object_names'])

        # ⚠️ request_methods 不注册为 framework_methods（即不作为全局 source producer）。
        # 这些方法（如 get, query, all）只有在 request 对象上调用时才是 source，
        # 全局注册会导致所有名为 get() 的方法被误标。保留在 request_methods 中
        # 供 is_framework_request_method() 上下文检查使用。
        self.request_methods = set(config['request_methods'])

        for func in config.get('global_source_functions', set()):
            self.framework_global_functions[func] = SourceInfo(
                type='framework',
                name=func,
                framework=framework,
            )

    def add_user_source_function(self, func_name: str, info: SourceInfo):
        """Register a user-defined function as a source producer."""
        self.user_source_functions[func_name] = info

    def summary(self) -> str:
        """Return a human-readable summary of the registry."""
        parts = []
        if self.framework:
            parts.append("Framework: {}".format(self.framework))
        if self.framework_methods:
            parts.append("Framework methods: {}".format(sorted(self.framework_methods.keys())))
        if self.framework_global_functions:
            parts.append("Framework globals: {}".format(sorted(self.framework_global_functions.keys())))
        if self.user_source_functions:
            parts.append("User source producers ({0}): {1}".format(
                len(self.user_source_functions),
                sorted(self.user_source_functions.keys()),
            ))
        if not parts:
            return "No framework detected, no user source producers discovered"
        return " | ".join(parts)


# ── Framework Configurations ──

FRAMEWORK_CONFIGS = {
    'laravel': {
        'request_object_names': {'request', '$request'},
        'request_methods': {
            'input', 'query', 'post', 'get', 'all',
            'cookie', 'header', 'ip', 'only', 'except',
        },
        'global_source_functions': set(),
    },
    'thinkphp': {
        'request_object_names': {'request', '$request'},
        'request_methods': {
            'param', 'get', 'post', 'route', 'file', 'session', 'cookie',
        },
        'global_source_functions': {'input', 'request', 'I'},
    },
    'codeigniter': {
        'request_object_names': {'request', '$request'},
        'request_methods': {
            'getGet', 'getPost', 'getVar', 'getPostGet',
        },
        'global_source_functions': set(),
    },
    'symfony': {
        'request_object_names': {'request', '$request'},
        'request_methods': {
            'get', 'query', 'request', 'getContent', 'getPayload',
            'toArray', 'getBasePath', 'getBaseUrl', 'getRequestUri',
        },
        # ParameterBag 方法：$request->query->get(), $request->request->all() 等
        # 这些通过链式调用（query→get）使用，需要特殊处理
        'parameter_bag_methods': {'get', 'all', 'has', 'set', 'remove'},
        'global_source_functions': set(),
    },
}


# ── Framework Detection ──

def detect_framework(project_dir: str) -> Optional[str]:
    """Detect PHP framework from composer.json or directory structure."""
    composer_json = os.path.join(project_dir, 'composer.json')
    if os.path.isfile(composer_json):
        try:
            with open(composer_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            deps = {}
            deps.update(data.get('require', {}))
            deps.update(data.get('require-dev', {}))

            for dep in deps:
                if dep == 'laravel/framework':
                    return 'laravel'
                if dep.startswith('topthink/'):
                    return 'thinkphp'
                if dep.startswith('codeigniter'):
                    return 'codeigniter'
                if dep.startswith('symfony/'):
                    # 任何 symfony/* 组件都算 Symfony 框架
                    # 特别是 symfony/http-foundation 包含 Request 对象
                    return 'symfony'
        except (json.JSONDecodeError, OSError):
            pass

    # Fallback: directory structure
    if os.path.isdir(os.path.join(project_dir, 'app', 'Http', 'Controllers')):
        return 'laravel'
    if os.path.isdir(os.path.join(project_dir, 'app', 'controller')):
        return 'thinkphp'
    if os.path.isdir(os.path.join(project_dir, 'application', 'controllers')):
        return 'codeigniter'

    return None


# ── AST Walking Helpers ──

def get_simple_name(node) -> Optional[str]:
    """Extract a simple name string from an AST node."""
    if node is None:
        return None
    if isinstance(node, str):
        return node
    if isinstance(node, php.Variable):
        return node.name
    if isinstance(node, php.Identifier):
        return node.name
    return None


def extract_method_object_name(node) -> Optional[str]:
    """Extract the effective object name from a MethodCall's object node.

    Handles:
    - Variable('$request') -> '$request'
    - ObjectProperty(Variable('$this'), 'request') -> 'request' ($this->request)
    - FunctionCall('request') -> 'request' (request() helper)
    """
    if isinstance(node, php.Variable):
        return node.name
    if isinstance(node, _OBJECT_PROPERTY_TYPES):
        return node.name
    if isinstance(node, php.FunctionCall):
        return get_simple_name(node.name)
    return None


def _node_contains_source(node: Any, registry: SourceRegistry) -> bool:
    """Check if an AST node directly accesses any known source.

    Only checks direct access, not indirect (calls to other source producers).
    """
    if node is None:
        return False

    # Direct superglobal variable reference: $_GET
    if isinstance(node, php.Variable):
        if node.name in registry.builtin_sources:
            return True

    # Array access on superglobal: $_GET['key']
    if isinstance(node, php.ArrayOffset):
        if isinstance(node.node, php.Variable) and node.node.name in registry.builtin_sources:
            return True

    # Method call on request object: $request->input()
    if isinstance(node, _METHOD_CALL_TYPES):
        obj_name = extract_method_object_name(node.node)
        if obj_name:
            method_name = get_simple_name(node.name)
            if method_name and registry.is_framework_request_method(obj_name, method_name):
                return True

    # Chain call on request sub-property: $request->query->get()
    # Recognized pattern: $obj-><request_prop>-><method>()
    # where request_prop is 'query', 'request', 'headers', 'cookies', 'attributes'
    if isinstance(node, _METHOD_CALL_TYPES):
        obj_node = node.node
        if isinstance(obj_node, _METHOD_CALL_TYPES):
            inner_obj_name = extract_method_object_name(obj_node.node)
            inner_method_name = get_simple_name(obj_node.name)
            outer_method_name = get_simple_name(node.name)
            if (inner_obj_name and inner_method_name and outer_method_name
                    and registry.is_framework_request_method(inner_obj_name, inner_method_name)):
                # $request->query is a request method returning ParameterBag
                config = FRAMEWORK_CONFIGS.get(registry.framework, {})
                bag_methods = config.get('parameter_bag_methods', set())
                if outer_method_name in bag_methods:
                    return True

    # Function call to framework global function: input()
    if isinstance(node, php.FunctionCall):
        func_name = get_simple_name(node.name)
        if func_name and registry.is_framework_global_function(func_name):
            return True

    # Recurse into children via lphply's fields mechanism
    # (lphply Node has no child_nodes() method — must use .fields)
    node_type = type(node)
    if hasattr(node_type, 'fields'):
        for field_name in node_type.fields:
            child = getattr(node, field_name, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    if _node_contains_source(item, registry):
                        return True
            elif isinstance(child, php.Node):
                if _node_contains_source(child, registry):
                    return True

    return False


def _find_return_nodes(body_nodes: list):
    """从函数体中收集所有 Return 节点"""
    returns = []
    if not body_nodes:
        return returns

    def _walk(nodes):
        if isinstance(nodes, list):
            for node in nodes:
                _walk(node)
        elif isinstance(nodes, php.Return):
            returns.append(nodes)
        elif isinstance(nodes, php.Node):
            node_type = type(nodes)
            if hasattr(node_type, 'fields'):
                for field_name in node_type.fields:
                    child = getattr(nodes, field_name, None)
                    if child is None:
                        continue
                    if isinstance(child, list):
                        _walk(child)
                    elif isinstance(child, php.Node):
                        _walk(child)

    _walk(body_nodes)
    return returns


def _function_body_contains_source(body_nodes: list, registry: SourceRegistry) -> bool:
    """Check if any return statement's value contains or depends on a known source.

    Previously this checked if ANY node in the function body referenced a source,
    which over-marked functions whose return values had nothing to do with user input.
    Now only marks a function as source producer when at least one return statement's
    value directly references a source variable (or a framework request method call).
    """
    if not body_nodes:
        return False

    return_nodes = _find_return_nodes(body_nodes)

    # 没有 return 语句 → 返回值不携带 source
    if not return_nodes:
        return False

    for ret in return_nodes:
        ret_value = getattr(ret, 'node', None)
        if ret_value and _node_contains_source(ret_value, registry):
            return True

    return False


def _walk_for_functions(nodes: Any, filepath: str, registry: SourceRegistry):
    """Recursively walk AST to find Function/Method definitions and mark source producers."""
    if isinstance(nodes, list):
        for node in nodes:
            _walk_for_functions(node, filepath, registry)
        return

    if nodes is None:
        return

    # Found a function definition
    if isinstance(nodes, php.Function):
        func_name = get_simple_name(nodes.name)
        if func_name:
            body = getattr(nodes, 'nodes', None) or []
            if _function_body_contains_source(body, registry):
                registry.add_user_source_function(func_name, SourceInfo(
                    type='user_defined',
                    name=func_name,
                    origin='{0}:{1}'.format(
                        os.path.basename(filepath),
                        getattr(nodes, 'lineno', '?')),
                ))

    # Found a method definition (inside a class)
    if isinstance(nodes, php.Method):
        func_name = get_simple_name(nodes.name)
        if func_name:
            body = getattr(nodes, 'nodes', None) or []
            if _function_body_contains_source(body, registry):
                registry.add_user_source_function(func_name, SourceInfo(
                    type='user_defined',
                    name=func_name,
                    origin='{0}:{1}'.format(
                        os.path.basename(filepath),
                        getattr(nodes, 'lineno', '?')),
                ))

    # Recurse into child nodes via lphply's fields mechanism
    node_type = type(nodes)
    if hasattr(node_type, 'fields'):
        for field_name in node_type.fields:
            child = getattr(nodes, field_name, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    _walk_for_functions(item, filepath, registry)
            elif isinstance(child, php.Node):
                _walk_for_functions(child, filepath, registry)


# ── Main Entry Point ──

def discover_sources(project_dir: str, ast_object, controlled_list=None) -> SourceRegistry:
    """Run source discovery for a PHP project.

    Args:
        project_dir: The project root directory
        ast_object: The Pretreatment singleton with .pre_result populated
        controlled_list: Optional list of extra controllable source names from tamper framework

    Returns:
        A SourceRegistry with all discovered sources
    """
    registry = SourceRegistry()

    # Step 1: Framework detection + source injection
    framework = detect_framework(project_dir)
    if framework and framework in FRAMEWORK_CONFIGS:
        registry.add_framework(framework)
        logger.info('[SourceDiscovery] Detected framework: {}'.format(framework))
    else:
        logger.info('[SourceDiscovery] No PHP framework detected')

    # Step 2: Custom source function discovery
    # Walk all PHP file ASTs to find functions that directly access known sources
    if hasattr(ast_object, 'pre_result') and ast_object.pre_result:
        for filepath, info in ast_object.pre_result.items():
            if info.get('language') != 'php':
                continue
            ast_nodes = info.get('ast_nodes')
            if not ast_nodes:
                continue
            try:
                _walk_for_functions(ast_nodes, filepath, registry)
            except Exception as e:
                logger.debug('[SourceDiscovery] Error processing {0}: {1}'.format(filepath, e))

    if registry.user_source_functions:
        logger.info('[SourceDiscovery] User source producers: {0}'.format(
            sorted(registry.user_source_functions.keys())))

    # 注入 tamper 框架的 controlled_list 作为额外的 builtin sources
    if controlled_list:
        for src in controlled_list:
            registry.builtin_sources.add(src)

    logger.info('[SourceDiscovery] Summary: {0}'.format(registry.summary()))

    return registry
