# -*- coding: utf-8 -*-
"""
Java Source Discovery 预处理模块

在扫描预处理阶段发现 Java 项目中的 user source producer（用户可控数据入口），
用于后续数据流分析判断变量是否可控。

Source Discovery 只回答"数据从哪里进入系统"，不管数据进入后经历了什么。
只做一层直接访问，不做多层传播（传播留给扫描引擎的 parameters_back）。

框架支持：Spring Boot/Spring MVC、JAX-RS (Jersey/RESTEasy)、Struts 2、Servlet
"""
import os
import re
import logging

logger = logging.getLogger('KunlunLog')


# ---------------------------------------------------------------------------
# 内置 source 成员 — Servlet API 标准方法
# ---------------------------------------------------------------------------
_BUILTIN_SOURCE_MEMBERS = frozenset({
    # HttpServletRequest 方法
    "getParameter", "getHeader", "getInputStream", "getReader",
    "getQueryString", "getCookies", "getParameterValues", "getParameterMap",
    "getProtocol", "getScheme", "getServerName", "getRemoteAddr",
    "getRemoteHost", "getRequestURI", "getRequestURL",
    "getContextPath", "getPathInfo", "getPart", "getParts",
    "getAttribute", "getSession",
})

# 内置 source producer 函数（方法名匹配）
_BUILTIN_SOURCE_PRODUCERS = {}


# ---------------------------------------------------------------------------
# SourceInfo — 描述一个 source 的元信息
# ---------------------------------------------------------------------------
class SourceInfo:
    """描述一个 source 的元信息"""

    __slots__ = ('type', 'name', 'framework', 'origin', 'is_safe', 'passthrough')

    def __init__(self, type, name, framework='', origin='', is_safe=False, passthrough=False):
        self.type = type          # 'builtin' | 'framework' | 'user_defined'
        self.name = name
        self.framework = framework
        self.origin = origin      # 如 "Spring Boot", "Servlet API"
        self.is_safe = is_safe
        self.passthrough = passthrough

    def __repr__(self):
        return f"SourceInfo({self.type}, {self.name!r}, framework={self.framework!r})"


# ---------------------------------------------------------------------------
# SourceRegistry — 存储 source 信息，提供查询接口
# ---------------------------------------------------------------------------
class SourceRegistry:
    """存储 Java source discovery 结果的注册表"""

    def __init__(self):
        self.source_members = set()           # 可控成员名（如 "getParameter", "getHeader"）
        self.source_producers = {}            # func_name -> SourceInfo
        self.framework_request_methods = {}  # (qualifier, member) -> SourceInfo
        self.framework = ''                   # 检测到的框架名
        self.annotated_param_names = set()     # 通过注解标记的可控参数名

    def add_source_member(self, name, source_info=None):
        """添加可控成员名"""
        self.source_members.add(name)
        if source_info:
            self.source_producers[name] = source_info

    def add_framework_method(self, qualifier, member, source_info):
        """添加框架方法（如 request -> input 映射）"""
        self.framework_request_methods[(qualifier, member)] = source_info
        self.source_members.add(f"{qualifier}.{member}")

    def add_annotated_param(self, param_name, source_info=None):
        """添加通过注解标记的可控参数"""
        self.annotated_param_names.add(param_name)
        if source_info:
            self.source_producers[param_name] = source_info

    def is_source_producer(self, func_name):
        """检查函数名是否是 source producer"""
        # 直接匹配
        info = self.source_producers.get(func_name)
        if info:
            return info
        # 匹配 qualified name
        short = func_name.split(".")[-1] if "." in func_name else func_name
        info = self.source_producers.get(short)
        if info:
            return info
        # 匹配 builtin source members
        if short in self.source_members:
            return SourceInfo(type='builtin', name=short, origin='Servlet API')
        # 匹配 builtin source producers
        for full_name, origin in _BUILTIN_SOURCE_PRODUCERS.items():
            if func_name == full_name or short == full_name.split(".")[-1]:
                return SourceInfo(type='builtin', name=full_name, origin=origin)
        return None

    def get_all_source_names(self):
        """返回所有 source 名称（用于注入 controlled_params）"""
        names = set(self.source_members)
        names.update(self.annotated_param_names)
        for (qual, mem), info in self.framework_request_methods.items():
            names.add(qual)
            names.add(f"{qual}.{mem}")
        for full_name in _BUILTIN_SOURCE_PRODUCERS:
            names.add(full_name)
        return list(names)

    def is_framework_request_method(self, qualifier, member):
        """检查 qualifier.member 是否是框架请求方法"""
        return (qualifier, member) in self.framework_request_methods

    def __repr__(self):
        return (f"SourceRegistry(framework={self.framework!r}, "
                f"members={len(self.source_members)}, "
                f"producers={len(self.source_producers)}, "
                f"annotated_params={len(self.annotated_param_names)})")


# ---------------------------------------------------------------------------
# 框架检测 — 解析 pom.xml / build.gradle
# ---------------------------------------------------------------------------
_FRAMEWORK_CONFIGS = {
    'spring': {
        'detect_packages': [
            'spring-boot-starter-web', 'spring-webmvc',
            'spring-boot-starter', 'spring-web',
        ],
        'source_members': {
            # Spring MVC Controller 参数绑定的方法
            "getParam", "getQuery",
        },
    },
    'struts2': {
        'detect_packages': [
            'struts2-core', 'struts2-spring-plugin',
        ],
        'source_members': {
            "ActionContext.getParameters",
            "ServletActionContext.getRequest",
        },
    },
    'jaxrs': {
        'detect_packages': [
            'jaxrs-api', 'jersey-core', 'jersey-server',
            'jersey-container-servlet', 'resteasy-jaxrs',
        ],
        'source_members': {},
    },
    'servlet': {
        'detect_packages': [
            'javax.servlet-api', 'jakarta.servlet-api',
            'javax.servlet', 'jakarta.servlet',
            'tomcat-servlet-api',
        ],
        'source_members': set(_BUILTIN_SOURCE_MEMBERS),
    },
}


def _detect_framework(project_dir):
    """
    向上遍历目录，查找 pom.xml / build.gradle 检测 Java 框架。
    返回 (framework_name, detected_packages) 或 (None, [])
    """
    detect_dir = project_dir
    for _ in range(5):
        if not detect_dir or detect_dir == '/':
            break

        pom_xml = os.path.join(detect_dir, 'pom.xml')
        build_gradle = os.path.join(detect_dir, 'build.gradle')
        build_gradle_kts = os.path.join(detect_dir, 'build.gradle.kts')

        # 解析 pom.xml
        if os.path.isfile(pom_xml):
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(pom_xml)
                root = tree.getroot()
                ns = ''
                if root.tag.startswith('{'):
                    ns = root.tag.split('}')[0] + '}'
                found = []
                for dep in root.iter(f'{ns}dependency'):
                    artifact = dep.find(f'{ns}artifactId')
                    if artifact is not None and artifact.text:
                        found.append(artifact.text.strip())
                return _match_framework(found)
            except Exception:
                pass

        # 解析 build.gradle / build.gradle.kts
        for gradle_file in (build_gradle, build_gradle_kts):
            if os.path.isfile(gradle_file):
                try:
                    with open(gradle_file, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    found = _parse_gradle_deps(content)
                    if found:
                        return _match_framework(found)
                except Exception:
                    pass

        detect_dir = os.path.dirname(detect_dir)

    # 未找到构建文件，但目录结构暗示
    # 检查是否是标准的 Maven/Gradle 项目结构
    src_main = os.path.join(project_dir, 'src', 'main', 'java')
    if os.path.isdir(src_main):
        return 'servlet', []

    return None, []


def _parse_gradle_deps(content):
    """从 build.gradle 文本中提取依赖 artifact"""
    deps = []
    # 匹配 implementation/compile/api 块
    pattern = r"(?:implementation|compile|api|runtimeOnly|compileOnly)\s*\(?['\"]([^'\"]+)['\"]\)?"
    for m in re.finditer(pattern, content):
        deps.append(m.group(1))
    # 匹配 project(":xxx") 形式的模块依赖
    for m in re.finditer(r"(?:implementation|compile|api)\s*(?:\(?\s*)project\s*\(\s*['\"]?:([^'\"]+)['\"]?", content):
        deps.append(m.group(1))
    return deps


def _match_framework(found_deps):
    """根据检测到的依赖匹配框架"""
    detected_frameworks = []
    for fw_name, config in _FRAMEWORK_CONFIGS.items():
        for pkg in config['detect_packages']:
            for dep in found_deps:
                if pkg.lower() in dep.lower():
                    detected_frameworks.append(fw_name)
                    break

    if detected_frameworks:
        return detected_frameworks[0], found_deps
    return None, found_deps


# ---------------------------------------------------------------------------
# AST 遍历 — javalang AST 遍历发现 source
# ---------------------------------------------------------------------------

def _walk_javalang_tree(tree):
    """递归遍历 javalang AST，yield 所有节点"""
    yield tree
    if hasattr(tree, 'children'):
        for child in tree.children():
            yield from _walk_javalang_tree(child)


def _find_source_producers_in_tree(tree, file_path=None):
    """
    遍历 javalang AST 树，发现用户自定义的 source producer。

    识别模式：
    1. 方法定义中参数类型为 HttpServletRequest → 参数名可控
    2. 方法参数有 Spring/JAX-RS 注解 → 参数名可控
    3. 局部变量通过 request.getXxx() 赋值 → 变量名可控
    4. 用户自定义的返回可控值的函数（如 getInput()，函数体有 return request.getParameter）
    """
    producers = []
    source_members = set()
    annotated_params = set()

    try:
        import javalang
    except ImportError:
        return producers, source_members, annotated_params

    # 所有内置 source members
    source_members.update(_BUILTIN_SOURCE_MEMBERS)

    # 遍历所有 MethodDeclaration
    methods = list(tree.filter(javalang.tree.MethodDeclaration))

    for method_node in methods:
        _process_method_declaration(method_node, source_members, annotated_params)

    return producers, source_members, annotated_params


def _process_method_declaration(method_node, source_members, annotated_params):
    """处理单个 MethodDeclaration 节点"""
    SPRING_PARAM_ANNOTATIONS = {
        'RequestParam', 'PathVariable', 'RequestBody',
        'RequestHeader', 'CookieValue', 'ModelAttribute',
    }
    JAXRS_PARAM_ANNOTATIONS = {
        'PathParam', 'QueryParam', 'FormParam',
        'HeaderParam', 'BeanParam',
    }
    ALL_PARAM_ANNOTATIONS = SPRING_PARAM_ANNOTATIONS | JAXRS_PARAM_ANNOTATIONS

    # 1. 检查方法参数
    if method_node.parameters:
        for param in method_node.parameters:
            param_type = ""
            if hasattr(param, 'type') and param.type:
                param_type = param.type.name if hasattr(param.type, 'name') else str(param.type)

            # HttpServletRequest / MultipartFile / InputStream / Principal 类型
            if any(t in param_type for t in ('Request', 'MultipartFile', 'InputStream', 'Principal')):
                annotated_params.add(param.name)
                continue

            # 检查注解
            if hasattr(param, 'annotations') and param.annotations:
                for ann in param.annotations:
                    ann_name = ann.name if hasattr(ann, 'name') else str(ann)
                    if '.' in ann_name:
                        ann_name = ann_name.split('.')[-1]
                    if ann_name in ALL_PARAM_ANNOTATIONS:
                        annotated_params.add(param.name)
                        break

    # 2. 检查方法体中的 request.getXxx() 赋值
    if not method_node.body:
        return

    # 找出方法参数中的 request 变量名
    request_var_names = set()
    if method_node.parameters:
        for param in method_node.parameters:
            ptype = ""
            if hasattr(param, 'type') and param.type:
                ptype = param.type.name if hasattr(param.type, 'name') else str(param.type)
            if 'Request' in ptype:
                request_var_names.add(param.name)

    for stmt in method_node.body:
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for declarator in stmt.declarators:
                if declarator.initializer and isinstance(declarator.initializer, javalang.tree.MethodInvocation):
                    init = declarator.initializer
                    # request.getParameter / request.getHeader 等
                    if (init.qualifier in request_var_names and
                            init.member in _BUILTIN_SOURCE_MEMBERS):
                        source_members.add(declarator.name)
                    # Spring: controllable_map.get("key")
                    elif init.member == 'get' and init.qualifier in annotated_params:
                        source_members.add(declarator.name)


# ---------------------------------------------------------------------------
# discover_sources — 主入口
# ---------------------------------------------------------------------------

def discover_sources(project_dir, tree, file_path=None, controlled_list=None):
    """
    发现 Java 项目中的 source。

    :param project_dir: 项目目录（用于框架检测）
    :param tree: javalang AST 树
    :param file_path: 当前文件路径（可选）
    :param controlled_list: Optional list of extra controllable source names from tamper framework
    :return: SourceRegistry 实例
    """
    registry = SourceRegistry()

    if tree is None:
        logger.debug('[AST][Java] Source Discovery: tree is None, skipping')
        return registry

    # 1. 框架检测
    framework, deps = _detect_framework(project_dir)
    if framework:
        registry.framework = framework
        config = _FRAMEWORK_CONFIGS.get(framework, {})
        for member in config.get('source_members', set()):
            if isinstance(member, set):
                registry.source_members.update(member)
            else:
                registry.add_source_member(member, SourceInfo(
                    type='framework', name=member, framework=framework,
                    origin=f"Java {framework.title()}"
                ))
        logger.debug('[AST][Java] Source Discovery: detected framework {} (deps: {})'.format(
            framework, deps[:5] if deps else []))

    # 2. 内置 source members
    registry.source_members.update(_BUILTIN_SOURCE_MEMBERS)

    # 3. AST 遍历发现 source producers
    producers, source_members, annotated_params = _find_source_producers_in_tree(tree, file_path)

    for member in source_members:
        if member not in registry.source_members:
            registry.add_source_member(member, SourceInfo(
                type='user_defined', name=member,
                origin='AST analysis'
            ))

    for param_name in annotated_params:
        registry.add_annotated_param(param_name, SourceInfo(
            type='user_defined', name=param_name,
            origin='AST annotation analysis'
        ))

    if registry.annotated_param_names:
        logger.debug('[AST][Java] Source Discovery: annotated params {}'.format(
            list(registry.annotated_param_names)))

    if registry.source_members - _BUILTIN_SOURCE_MEMBERS:
        logger.debug('[AST][Java] Source Discovery: extra source members {}'.format(
            list(registry.source_members - _BUILTIN_SOURCE_MEMBERS)))

    # 注入 tamper 框架的 controlled_list 作为额外的 source members
    if controlled_list:
        for src in controlled_list:
            registry.source_members.add(src)

    logger.debug('[AST][Java] Source Discovery: {}'.format(registry))
    return registry
