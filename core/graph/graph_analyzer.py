"""Graph-based vulnerability backtracking analyzer.

Operates on an already-built igraph AST graph (with ast/own/use/cg/dfg edges)
to perform taint analysis.  Graph-native replacement for the legacy
``_parameters_back_impl`` and ``function_back`` in php/parser.py.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

import igraph as ig

from core.graph.node_edge_schema import (
    AstRole, EdgeLabel, NodeLabel, OperatorType,
)
from utils.igraph_compat import _vattr

__all__ = ["GraphAnalyzer", "AnalysisResult"]
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPERGLOBALS: frozenset[str] = frozenset({
    # PHP superglobals ($_SESSION excluded — server-side session data, not direct user input)
    # ($argc/$argv excluded — CLI-only sources, not web-controllable)
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER",
    "$_ENV", "$HTTP_RAW_POST_DATA",
    # Python web framework sources (object names)
    "request.GET", "request.POST", "request.REQUEST", "request.COOKIES",
    "request.FILES", "request.data", "request.body", "request.query_params",
    "request.query_string", "request.form",
    # Flask/WSGI
    "flask.request", "django.http.HttpRequest",
})

# $_SERVER keys that are NOT directly user-controlled (server config / runtime info).
# Keys not in this set (HTTP_*, REQUEST_URI, PHP_SELF, QUERY_STRING, etc.)
# are treated as user-controlled sources.
_SERVER_UNCONTROLLED_KEYS: frozenset[str] = frozenset({
    "SERVER_NAME", "SERVER_ADDR", "SERVER_PORT", "SERVER_SOFTWARE",
    "SERVER_SIGNATURE", "SERVER_ADMIN", "DOCUMENT_ROOT",
    "SCRIPT_FILENAME", "GATEWAY_INTERFACE", "PATH_TRANSLATED",
    "argv", "argc",
    "SERVER_PROTOCOL", "SCRIPT_NAME", "REMOTE_ADDR", "REMOTE_HOST",
    "REMOTE_PORT", "REQUEST_TIME", "REQUEST_TIME_FLOAT", "HTTPS",
})

# $_FILES keys that are NOT user-controlled (server-generated metadata).
# Keys not in this set ('name', 'type') are treated as user-controlled sources.
_FILES_NON_SOURCE_MEMBERS: frozenset[str] = frozenset({
    "tmp_name", "size", "error", "full_path",
})

# JS/TS source roots (location.hash, document.cookie, process.env, window.name)
_JS_SOURCE_ROOTS: frozenset[str] = frozenset({
    "location", "document", "window", "process",
})

_REPAIR_FUNCTIONS: frozenset[str] = frozenset({
    # PHP
    "htmlspecialchars", "htmlentities", "strip_tags", "urlencode",
    "rawurlencode", "addslashes", "intval", "floatval",
    "escapeshellarg", "escapeshellcmd",
    "mysql_real_escape_string", "mysqli_real_escape_string",
    "pg_escape_string", "pg_escape_bytea",
    "SQLite3::escapeString", "PDO::quote",
    "trim", "stripslashes", "filter_var", "filter_input",
    "htmlspecialchars_decode", "basename", "realpath",
    "ctype_alnum", "ctype_digit", "ctype_alpha",
    "is_numeric", "json_encode", "serialize",
    # Python
    "shlex.quote", "shlex.quote_plus",
    "html.escape", "html.unescape",
    "re.escape", "urllib.parse.quote", "urllib.parse.quote_plus",
    "cgi.escape", "markupsafe.escape",
    "os.path.basename", "os.path.realpath",
    "int", "float", "str",
    "json.dumps", "json.loads",
    "pickle.dumps", "pickle.loads",
    # Java
    "StringEscapeUtils.escapeSql",
    "org.apache.commons.lang3.StringEscapeUtils.escapeSql",
    # Go
    "html.EscapeString", "url.QueryEscape",
    "shellescape.Quote",
    # JavaScript/TypeScript
    "encodeURIComponent", "encodeURI",
    "DOMPurify.sanitize", "sanitizeHtml",
    "escape", "unescape",
    # Ruby
    "ERB::Util.html_escape", "ERB::Util.url_encode",
    "CGI.escapeHTML", "CGI.escape",
    "Shellwords.escape", "Shellwords.shellescape",
    "ActiveRecord::SanitizationHelper.sanitize_sql",
    "params.to_unsafe_h",
})

# Fix 14: PHP type cast operators that sanitize taint.
# (int), (float), (bool), (array) casts destroy string content,
# making XSS/SQLi/injection impossible through the cast result.
_TYPE_CAST_SAFE: frozenset[str] = frozenset({
    "int", "integer", "float", "double", "real",
    "bool", "boolean", "array", "object",
})

_SINK_FUNCTIONS: frozenset[str] = frozenset({
    "system", "exec", "passthru", "shell_exec", "popen", "proc_open", "pcntl_exec", "expect_popen",
    "eval", "assert", "create_function",
    "call_user_func", "call_user_func_array", "register_tick_function", "register_shutdown_function", "dl",
    "usort", "uasort", "array_map", "array_filter",
    "echo", "print", "printf", "vprintf", "sprintf", "vsprintf", "print_r", "var_dump",
    "file_put_contents", "file_get_contents", "fopen", "readfile",
    "include", "require", "include_once", "require_once",
    "header", "setcookie", "mail", "mb_send_mail",
    "unlink", "rmdir", "mkdir", "rename", "copy", "move_uploaded_file",
    "chmod", "chown", "chgrp", "symlink", "link",
    "curl_exec", "curl_setopt",
    "mysqli_query", "mysql_query", "pg_query", "sqlite_query",
    "mysql_db_query", "pg_execute", "pg_insert", "pg_select", "pg_update",
    "odbc_exec", "oci_parse", "sqlsrv_query", "db2_exec",
    "ldap_bind", "ldap_search", "ldap_add", "ldap_delete", "ldap_list", "ldap_read",
    "unserialize",
    "extract", "parse_str",
    "highlight_file", "show_source", "php_strip_whitespace",
    "simplexml_load_string", "simplexml_load_file",
    # Python
    "HttpResponse", "JsonResponse", "render", "render_to_string",
    "write", "writelines",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "pickle.loads", "yaml.load", "exec", "eval",
    # Java
    "start", "ProcessBuilder",
    # Go
    "exec.Command", "Output", "Run",
    # C / C++
    "system", "popen", "pclose",
    # JavaScript
    "write", "eval",
    # Lua
    "os.execute", "io.popen",
    "os.remove", "io.open",
    "loadstring", "dofile", "require",
})

# Java parameter annotations that indicate user-controlled input
_USER_INPUT_PARAM_ANNOTATIONS: frozenset[str] = frozenset({
    "RequestParam", "RequestBody", "PathVariable", "CookieValue",
    "RequestHeader", "ModelAttribute", "CurrentUsername",
    "AuthenticationPrincipal",  # Spring: @AuthenticationPrincipal → controllable
})

# Java parameter types that are framework-injected (not user-controlled)
# These are resolved from Spring MVC / Servlet API arguments.
_FRAMEWORK_INJECTED_TYPES: frozenset[str] = frozenset({
    "Authentication", "Principal",
    "HttpServletRequest", "HttpServletResponse",
    "HttpSession", "ServletContext", "ServletContextAware",
    "Locale", "LocaleResolver", "TimeZone",
    "Model", "ModelMap", "RedirectAttributes",
    "BindingResult", "WebDataBinder",
    "MultipartFile[]", "MultipartFile",
    "ApplicationContext", "Environment", "WebGoatUser",
})

# Go types that carry user-controlled HTTP request data.
# Parameters with these types in Go handler functions are SOURCES (controllable),
# unlike Java where HttpServletRequest is framework-injected (uncontrollable).
_GO_SOURCE_TYPES: frozenset[str] = frozenset({
    "*http.Request",
})

# Spring/JAX-RS annotations that mark a parameter as user-controlled input
_USER_CONTROLLED_ANNOTATIONS: frozenset[str] = frozenset({
    "RequestParam", "PathVariable", "RequestBody", "RequestHeader",
    "CookieValue", "ModelAttribute", "MatrixVariable",
    "PathParam", "QueryParam", "FormParam", "HeaderParam",
    "CookieParam", "Context",  # JAX-RS
})

_TYPE_VALIDATION_FUNCS: frozenset[str] = frozenset({
    # PHP
    "is_numeric", "is_int", "is_integer", "is_float", "is_double",
    "ctype_digit", "ctype_alnum", "ctype_alpha", "ctype_xdigit",
    "ctype_lower", "ctype_upper", "ctype_graph", "ctype_print",
    "ctype_punct", "ctype_space", "ctype_cntrl",
    # Python
    "isinstance", "issubclass", "hasattr", "callable",
    "isdigit", "isalpha", "isalnum", "isdecimal", "isnumeric",
    "isupper", "islower", "istitle", "isspace",
    "isascii", "isidentifier", "isprintable",
    "isfinite", "isinf", "isnan",
})

# Java/Kotlin parameter annotations that indicate the parameter is
# framework-injected and NOT user-controlled input.
_SAFE_PARAM_ANNOTATIONS: frozenset[str] = frozenset({
    "@CurrentUsername", "@AuthenticationPrincipal",
    "@CurrentUser", "@LoginUser",
    "@ActiveUser", "@AuthUser",
})

_SAFE_CONSTRAINT_OPS: frozenset[str] = frozenset({"==", "==="})

_CALL_TYPES = {
    OperatorType.CALL.value,
    OperatorType.STATIC_CALL.value,
    OperatorType.METHOD_CALL.value,
    OperatorType.NEW.value,
}

# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """Unified analysis result — replaces legacy (code, cp, expr_lineno).

    code values: 1=controllable, 2=repaired, 3=inconclusive, -1=uncontrollable,
    'deps'=depends on caller variables.
    """
    code: int | str = 3
    reason: str = ""
    chain: list[dict] = field(default_factory=list)
    path: list[int] = field(default_factory=list)
    deps: list[str] = field(default_factory=list)
    expr_lineno: int = 0

    @property
    def is_controllable(self) -> bool: return self.code in (1, 4)
    @property
    def is_repaired(self) -> bool: return self.code == 2
    @property
    def is_inconclusive(self) -> bool: return self.code == 3
    @property
    def is_uncontrollable(self) -> bool: return self.code == -1
    @property
    def has_deps(self) -> bool: return self.code == "deps"

    def __repr__(self) -> str:
        return (f"AnalysisResult(code={self.code!r}, reason={self.reason!r}, "
                f"path_len={len(self.path)}, deps={self.deps})")

# ---------------------------------------------------------------------------
# GraphAnalyzer
# ---------------------------------------------------------------------------

class GraphAnalyzer:
    """Vulnerability backtracking on an igraph AST graph.

    Usage::

        analyzer = GraphAnalyzer(graph, language="php")
        sinks = analyzer.find_sinks()
        for sink in sinks:
            result = analyzer.parameters_back(sink["vid"])

    图上的 function 节点可携带 taint_type 属性（由 knowledge_bridge 在
    构建阶段标注）。parameters_back 遇到 call 时沿 cg 边找到 function，
    直接根据 function 节点的 taint_type 判定可控性，无需运行时查询知识库。
    """

    def __init__(self, graph: ig.Graph, language: str = "php",
                 source_registry=None) -> None:
        self.graph = graph
        self.language = language
        self._decision_cache: dict[int, AnalysisResult] = {}
        self._call_stack: list[str] = []
        self._source_registry = source_registry

        # --- 预构建 O(1) 索引 ---
        # 边索引: label → {src_vid: [tgt_vid, ...]}
        self._esrc: dict[str, dict[int, list[int]]] = {}
        # 边索引: label → {tgt_vid: [src_vid, ...]}
        self._etgt: dict[str, dict[int, list[int]]] = {}
        for e in graph.es:
            el = _vattr(e, 'label', '') or ''
            self._esrc.setdefault(el, {}).setdefault(e.source, []).append(e.target)
            self._etgt.setdefault(el, {}).setdefault(e.target, []).append(e.source)

        # 节点索引: label → [vid, ...]
        self._nlbl: dict[str, list[int]] = {}
        # 节点索引: (label, name) → [vid, ...]
        self._nname: dict[tuple[str, str], list[int]] = {}
        for v in graph.vs:
            vl = _vattr(v, 'label', '') or ''
            vn = _vattr(v, 'name', '') or ''
            self._nlbl.setdefault(vl, []).append(v.index)
            if vn:
                self._nname.setdefault((vl, vn), []).append(v.index)

        # 节点 file_path 索引: (label, name, file_path) → [vid, ...]
        # （_find_identifier_by_name 需要 file_path 过滤）
        self._nfile: dict[tuple[str, str, str], list[int]] = {}
        for v in graph.vs:
            vl = _vattr(v, 'label', '') or ''
            vn = _vattr(v, 'name', '') or ''
            fp = _vattr(v, 'file_path', '') or _vattr(v, 'path', '') or ''
            if vl and vn:
                self._nfile.setdefault((vl, vn, fp), []).append(v.index)

        # branch_safe DFG 边集合：(source_vid, target_vid)}
        # 替代 edge attribute 查询，O(1) lookup
        self._branch_safe_set: set[tuple[int, int]] = set()

        self._mark_branch_safe_dfg()

    # --- Sink discovery ---------------------------------------------------

    def find_sinks(self, sink_names: list[str] | None = None) -> list[dict]:
        """Locate sink operator nodes (call/static_call/method_call matching
        *sink_names*, defaulting to built-in _SINK_FUNCTIONS).

        Returns list of dicts with keys: vid, name, lineno, file_path, type,
        arg_vids (list of argument vertex ids).
        """
        if sink_names is None:
            sink_names = sorted(_SINK_FUNCTIONS)
        name_set = set(sink_names)
        normalized_set = {sn.replace("::", ".") for sn in name_set}
        # Case-insensitive fallback: vul_function 用类名 (JdbcTemplate.queryForObject)
        # 而图节点用代码级名称 (jdbcTemplate.queryForObject)，需要大小写不敏感匹配
        normalized_lower = {sn.lower() for sn in normalized_set}
        name_lower = {sn.lower() for sn in name_set}
        results: list[dict] = []

        # 收集所有作为 callee 的节点 vid（MemberExpression 等），用于去重
        # JS/PHP 中 method_call 的 callee MemberExpression 也会被标记为 operator+method_call
        # 我们只保留真正的调用点（有 ast[role=arg] 的 operator），跳过 callee 表达式
        # 但方法链中间有自身 arg 的节点是真正的调用点，不应跳过
        callee_targets: set[int] = set()
        callee_with_args: set[int] = set()
        for e in self.graph.es.select(label="ast"):
            if _vattr(e, "role") == "callee":
                callee_targets.add(e.target)
        # Identify callee_targets with their own args
        for ct_vid in callee_targets:
            has_arg = any(
                _vattr(e, "role") == "arg"
                for e in self.graph.es.select(_source=ct_vid, label="ast")
            )
            if has_arg:
                callee_with_args.add(ct_vid)

        for vid in self._nlbl.get(NodeLabel.OPERATOR.value, []):
            v = self.graph.vs[vid]
            # 只处理匹配当前分析器语言的节点
            node_lang = _vattr(v, 'language', '')
            if node_lang and self.language and node_lang != self.language:
                continue
            if _vattr(v, "type") not in _CALL_TYPES:
                continue
            # 跳过 callee 表达式节点（如 MemberExpression），只保留真正的调用 operator
            # 但方法链中间有自身 arg 的节点是真正的调用点，不应跳过
            if v.index in callee_targets and v.index not in callee_with_args:
                continue
            # 跳过没有参数的 MemberExpression（属性访问如 req.query，不是函数调用）。
            # JS normalizer 把 obj.prop 和 obj.method(arg) 都标记为 method_call，
            # 但只有后者有 ast[role=arg] 出边。
            if (_vattr(v, "type") == OperatorType.METHOD_CALL.value and
                    _vattr(v, "raw_type") == "MemberExpression" and
                    v.index not in callee_with_args and
                    not any(_vattr(e, "role") == "arg"
                            for e in self.graph.es.select(_source=v.index, label="ast"))):
                continue
            callee_name = self._resolve_callee_name(v.index)
            if not callee_name:
                callee_name = _vattr(v, "callee", "")
            # Fallback: use operator's full name (e.g. "document.write")
            # when _resolve_callee_name only returned the short method name.
            # The operator name attribute contains the complete dotted expression
            # from the source (set by normalizer), which is the correct match
            # target for qualified sink names like "document.write".
            # However, if the short name already matches a sink pattern (e.g.
            # "exec" matching "exec" in the sink set), do NOT override it with
            # a longer qualified name like "require().exec" that would fail to
            # match.  Only override when the short name has no direct match.
            op_name = _vattr(v, "name", "")
            _short_norm = callee_name.replace("::", ".") if callee_name else ""
            if (op_name and callee_name and
                    op_name.endswith(callee_name) and op_name != callee_name and
                    "." in op_name and
                    _short_norm not in normalized_set and _short_norm not in name_set):
                callee_name = op_name
            if not callee_name:
                continue
            if not isinstance(callee_name, str):
                continue
            if callee_name.startswith("\\"):
                callee_name = callee_name[1:]
            # Normalize: Rust uses :: but sink names use .
            normalized_callee = callee_name.replace("::", ".")
            matched_name = None
            _is_qualified_match = False  # Track if match is via qualified name (Path 2 or dotted Path 1)

            # Path 1: short name match (e.g. "unmarshal" in sink_set)
            if normalized_callee in normalized_set:
                matched_name = normalized_callee
                callee_name = normalized_callee
                if "." in normalized_callee:
                    _is_qualified_match = True

            # Path 1b: case-insensitive match (vul_function uses class names
            # like "JdbcTemplate.queryForObject" while AST nodes use code-level
            # names like "jdbcTemplate.queryForObject")
            if not matched_name and normalized_callee.lower() in normalized_lower:
                matched_name = normalized_callee
                callee_name = normalized_callee
                if "." in normalized_callee:
                    _is_qualified_match = True

            # Path 2: fullname match via use edge target function node.
            # UseEdgeBuilder resolves receiver type at graph build time,
            # so external function fullname may be a qualified name like
            # "Unmarshaller.unmarshal" rather than source text.
            # Always attempt: if a qualified name matches, it is more
            # specific than a short name from Path 1 and should win.
            for ue in self.graph.es.select(_source=v.index, label="use"):
                tgt = self.graph.vs[ue.target]
                if _vattr(tgt, "label") != NodeLabel.FUNCTION.value:
                    continue
                tgt_fullname = _vattr(tgt, "fullname", "")
                if not tgt_fullname:
                    continue
                norm_fn = tgt_fullname.replace("::", ".")
                # Skip if fullname equals short name — no gain
                if norm_fn == normalized_callee:
                    continue
                if norm_fn in normalized_set:
                    matched_name = norm_fn
                    callee_name = tgt_fullname
                    _is_qualified_match = True
                    break

            if not matched_name:
                continue

            # Guard: method_call/static_call with bare short-name match
            # (no qualifier like "Class.method" or "::" separator) is likely
            # an object method sharing a name with a built-in function.
            # e.g. $filesystem->copy() should NOT match the built-in copy().
            # Require qualified match (Path 2 use-edge or dotted name) for
            # method_call/static_call to avoid this class of false positives.
            if (not _is_qualified_match and
                    _vattr(v, "type") in (
                        OperatorType.METHOD_CALL.value,
                        OperatorType.STATIC_CALL.value,
                    ) and "." not in normalized_callee and "::" not in normalized_callee):
                continue
            # Collect argument vids via ast[role=arg] edges
            arg_vids = [
                e.target for e in self.graph.es.select(_source=v.index, label="ast")
                if _vattr(e, "role") == "arg"
            ]
            # Also collect dfg sources flowing directly into the sink node
            # (e.g., Rust macro format args: user_input → dfg → log::info).
            # Skip DFG sources from the callee chain (receiver object /
            # nested calls in method chain).  The callee chain represents
            # the call target, not data arguments — its controllability
            # does NOT make the call dangerous.
            for de in self.graph.es.select(_target=v.index, label="dfg"):
                src = de.source
                if src in arg_vids:
                    continue
                src_label = _vattr(self.graph.vs[src], "label", "")
                # Skip operator nodes: nested calls in the method chain
                # (e.g., getWriter() in resp.getWriter().write(x))
                if src_label == NodeLabel.OPERATOR.value:
                    continue
                # Skip identifier nodes matching the receiver name
                # extracted from the operator's qualified name prefix.
                # E.g., for "resp.getWriter.write", receiver = "resp".
                if _vattr(v, "type") in (
                    OperatorType.METHOD_CALL.value,
                    OperatorType.STATIC_CALL.value,
                ):
                    sink_op_name = _vattr(v, "name", "")
                    if "." in sink_op_name:
                        receiver_name = sink_op_name.split(".")[0]
                        src_name = _vattr(self.graph.vs[src], "name", "")
                        if src_name == receiver_name:
                            continue
                arg_vids.append(src)
            results.append({
                "vid": v.index, "name": callee_name,
                "lineno": _vattr(v, "lineno", 0),
                "file_path": _vattr(v, "file_path", "") or _vattr(v, "path", ""),
                "type": _vattr(v, "type", ""),
                "arg_vids": arg_vids,
            })

        # 第三轮：查找 import 类型节点（PHP include/require）
        # import 节点的 type 就是 include/require/include_once/require_once
        import_keywords = {"include", "require", "include_once", "require_once"}
        for vid in self._nlbl.get(NodeLabel.IMPORT.value, []):
            v = self.graph.vs[vid]
            # 只处理匹配当前分析器语言的节点
            node_lang = _vattr(v, 'language', '')
            if node_lang and self.language and node_lang != self.language:
                continue
            vtype = _vattr(v, "type", "")
            if vtype not in import_keywords:
                continue
            if vtype in name_set:
                matched_name = vtype
            else:
                continue
            # Collect argument vid via ast[role=arg] edge
            arg_vids = [
                e.target for e in self.graph.es.select(_source=v.index, label="ast")
                if _vattr(e, "role") == "arg"
            ]
            results.append({
                "vid": v.index, "name": matched_name,
                "lineno": _vattr(v, "lineno", 0),
                "file_path": _vattr(v, "file_path", "") or _vattr(v, "path", ""),
                "type": vtype,
                "arg_vids": arg_vids,
            })

        # 第二轮：查找 assign 类型节点中匹配 sink_name 的属性赋值
        # 例如 element.innerHTML = expr → innerHTML 是 sink
        assign_types = {OperatorType.ASSIGN.value, OperatorType.AUG_ASSIGN.value}
        for vid in self._nlbl.get(NodeLabel.OPERATOR.value, []):
            v = self.graph.vs[vid]
            if _vattr(v, "type") not in assign_types:
                continue
            # PHP: 属性赋值的属性名不应匹配 PHP 内置函数 sink
            # （如 $data->link = ... 中 link 不等于 PHP link() 硬链接函数）
            # Round 2 属性 sink 仅为 JS DOM XSS（innerHTML 等）
            if self.language == "php":
                continue
            # 查找 LHS 边
            lhs_vids = [
                e.target for e in self.graph.es.select(_source=v.index, label="ast")
                if _vattr(e, "role") == "lhs"
            ]
            lhs_name = None
            lhs_identifier_vid = None
            for lhs_vid in lhs_vids:
                lhs_v = self.graph.vs[lhs_vid]
                lhs_label = _vattr(lhs_v, "label", "")
                lhs_vname = _vattr(lhs_v, "name", "")
                if not isinstance(lhs_vname, str):
                    continue
                if lhs_label == "property" or lhs_label == "identifier":
                    if lhs_vname in name_set:
                        lhs_name = lhs_vname
                        lhs_identifier_vid = lhs_vid
                        break
                elif lhs_label == "operator":
                    # LHS 是 operator（如 document.getElementById().innerHTML）
                    # 检查其 ast 子节点中是否有 identifier/property 匹配 sink
                    for ce in self.graph.es.select(_source=lhs_vid, label="ast"):
                        child = self.graph.vs[ce.target]
                        cl = _vattr(child, "label", "")
                        cn = _vattr(child, "name", "")
                        if cl in ("property", "identifier") and cn in name_set:
                            lhs_name = cn
                            lhs_identifier_vid = ce.target
                            break
                    if lhs_name:
                        break
            if not lhs_name:
                continue
            if lhs_name not in name_set:
                continue
            # 查找 RHS 边作为 arg_vids（被赋值的表达式）
            rhs_vids = [
                e.target for e in self.graph.es.select(_source=v.index, label="ast")
                if _vattr(e, "role") == "rhs"
            ]
            results.append({
                "vid": v.index,
                "name": lhs_name,
                "lineno": _vattr(v, "lineno", 0),
                "file_path": _vattr(v, "file_path", ""),
                "type": _vattr(v, "type", ""),
                "arg_vids": rhs_vids,
            })
        # 第四轮：前缀标志匹配（a: 注解, r: return 节点）
        annotation_sinks = {sn for sn in name_set if sn.startswith('a:')}
        return_sinks = {sn for sn in name_set if sn.startswith('r:')}
        if annotation_sinks or return_sinks:
            # 收集所有 annotation 节点
            annotation_vids = set(self._nlbl.get('annotation', []))
            # 预建 annotation -> parent 映射（支持 class 和 function 两种 parent）
            # 方法级别注解（如 @ResponseBody）挂在 function 上
            # 类级别注解（如 @RestController）挂在 class 上
            anno_to_parent: dict[int, tuple[str, int]] = {}  # anno_vid -> (parent_label, parent_vid)
            for anno_vid in annotation_vids:
                for src in self._et(anno_vid, 'own'):
                    src_label = _vattr(self.graph.vs[src], 'label', '')
                    if src_label in (NodeLabel.CLASS.value, NodeLabel.FUNCTION.value):
                        anno_to_parent[anno_vid] = (src_label, src)
                        break
            # 预建 class -> function own 映射
            class_to_funcs: dict[int, list[int]] = {}
            for vid in self._nlbl.get(NodeLabel.CLASS.value, []):
                funcs = []
                for tgt in self._ef(vid, 'own'):
                    if _vattr(self.graph.vs[tgt], 'label') == NodeLabel.FUNCTION.value:
                        funcs.append(tgt)
                if funcs:
                    class_to_funcs[vid] = funcs

            for anno_vid, (parent_label, parent_vid) in anno_to_parent.items():
                anno_name = _vattr(self.graph.vs[anno_vid], 'name', '')
                # 匹配 a:AnnotationName
                for asink in annotation_sinks:
                    target_anno = asink[2:]  # strip 'a:'
                    if anno_name != target_anno:
                        continue
                    if parent_label == NodeLabel.FUNCTION.value:
                        # 方法级别注解：直接处理该 function 的 return 节点
                        func_vid = parent_vid
                        self._collect_annotation_return_sinks(
                            func_vid, asink, results
                        )
                    elif parent_label == NodeLabel.CLASS.value:
                        # 类级别注解：只传播到有 HTTP mapping 注解的方法。
                        # private 方法或非 controller 方法不应作为 HTTP response sink。
                        _http_mapping_annos = frozenset({
                            'GetMapping', 'PostMapping', 'PutMapping',
                            'DeleteMapping', 'PatchMapping', 'RequestMapping',
                        })
                        for func_vid in class_to_funcs.get(parent_vid, []):
                            has_mapping = False
                            for fe in self.graph.es.select(_source=func_vid, label='own'):
                                cn = _vattr(self.graph.vs[fe.target], 'name', '')
                                cl = _vattr(self.graph.vs[fe.target], 'label', '')
                                if cl == NodeLabel.ANNOTATION.value and cn in _http_mapping_annos:
                                    has_mapping = True
                                    break
                            if not has_mapping:
                                continue
                            self._collect_annotation_return_sinks(
                                func_vid, asink, results
                            )
                    break  # 每个 annotation 只匹配一次

            # r: 前缀：匹配所有 function 的 return 节点
            if return_sinks:
                for vid in self._nlbl.get(NodeLabel.RETURN.value, []):
                    # 只处理有 function-return scope own 边的 return 节点
                    has_func_scope = any(
                        _vattr(e, 'scope') == 'function-return' and _vattr(self.graph.vs[e.source], 'label') == NodeLabel.FUNCTION.value
                        for e in self.graph.es.select(_target=vid, label='own')
                    )
                    if not has_func_scope:
                        continue
                    ret_arg_vids = [
                        e.target for e in self.graph.es.select(_source=v.index, label='ast')
                        if _vattr(e, 'role') == 'value'
                    ]
                    results.append({
                        'vid': v.index,
                        'name': 'r:',
                        'lineno': _vattr(v, 'lineno', 0),
                        'file_path': _vattr(v, 'file_path', '') or _vattr(v, 'path', ''),
                        'type': 'return',
                        'arg_vids': ret_arg_vids,
                    })
        logger.debug("find_sinks found %d sink node(s)", len(results))
        return results

    _JSON_CT_PATTERNS = frozenset({
        'APPLICATION_JSON_VALUE', 'APPLICATION_JSON',
        'application/json', '"application/json"',
    })

    def _collect_annotation_return_sinks(self, func_vid: int, sink_name: str,
                                          results: list[dict]) -> None:
        """Collect return nodes of a function as annotation-driven sinks.

        Walks func → own(function-return) → return → ast[value] to build
        sink entries with the return expression as the controllable arg.

        For XSS-related sinks (a:ResponseBody), checks if the function declares
        a JSON content type (produces=application/json) and skips if so —
        JSON responses are not interpreted as HTML by browsers.
        """
        # 检测 JSON Content-Type：扫描函数的 own 子节点中是否有
        # MimeTypeUtils.APPLICATION_JSON_VALUE 等常量 operator
        is_json_ct = False
        for fe in self.graph.es.select(_source=func_vid, label='own'):
            child_name = _vattr(self.graph.vs[fe.target], 'name', '')
            for jp in self._JSON_CT_PATTERNS:
                if jp in child_name:
                    is_json_ct = True
                    break
            if is_json_ct:
                break

        for fe in self.graph.es.select(_source=func_vid, label='own'):
            if _vattr(fe, 'scope') != 'function-return':
                continue
            ret_vid = fe.target
            ret_label = _vattr(self.graph.vs[ret_vid], 'label', '')
            if ret_label != NodeLabel.RETURN.value:
                continue
            ret_arg_vids = [
                e.target for e in self.graph.es.select(_source=ret_vid, label='ast')
                if _vattr(e, 'role') == 'value'
            ]
            results.append({
                'vid': ret_vid,
                'name': sink_name,
                'lineno': _vattr(self.graph.vs[ret_vid], 'lineno', 0),
                'file_path': (
                    _vattr(self.graph.vs[ret_vid], 'file_path', '')
                    or _vattr(self.graph.vs[ret_vid], 'path', '')
                ),
                'type': 'annotation-return',
                'func_vid': func_vid,
                'arg_vids': ret_arg_vids,
                'json_safe': is_json_ct,
            })

    # --- Controllability backtracking (core) ------------------------------

    def parameters_back(self, start_vid: int, context_vid: int | None = None,
                       max_depth: int = 50) -> AnalysisResult:
        """BFS backward along dfg edges to determine controllability.

        Classification per upstream node:
        1. Superglobal source (``$_GET`` etc.) → code=1
        2. Repair function in chain → code=2
        3. Constant / literal → skip (not controllable)
        4. Function call → delegate to analyze_function_return
        5. Ordinary identifier → continue BFS
        6. Max depth / no more upstream → code=3
        """
        cache_key = (start_vid, context_vid)
        if cache_key in self._decision_cache:
            return self._decision_cache[cache_key]

        sv = self.graph.vs[start_vid]
        sname = _vattr(sv, "name", "")

        # Pre-check: branch constraint on start node
        if _vattr(sv, "label") == NodeLabel.IDENTIFIER.value and sname:
            branch_chain = self.get_branch_chain(start_vid)
            if branch_chain:
                # Check ALL branches in the chain, not just innermost/outermost.
                # A variable can be protected by a parent branch even if the
                # innermost branch doesn't constrain it.
                for branch_vid in branch_chain:
                    if self.check_branch_constraint(branch_vid, sname):
                        return self._cached(cache_key, AnalysisResult(
                            code=-1,
                            reason=f"branch constraint on '{sname}' in "
                                   f"{_vattr(self.graph.vs[branch_vid], 'type', '')} "
                                   f"('{_vattr(self.graph.vs[branch_vid], 'condition', '')}')",
                            chain=[{"step": "branch_constraint", "vid": branch_vid,
                                    "name": sname, "code": -1}],
                            path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # Quick checks on start node itself
        # $_SERVER as a whole is not a source — only specific keys are.
        # Specific keys are detected via the member-chain walk below, where
        # _SERVER_UNCONTROLLED_KEYS filters out server-config fields.
        if sname != "$_SERVER" and self._is_source_variable(sname):
            return self._cached(cache_key, AnalysisResult(
                code=1, reason=f"'{sname}' is a superglobal",
                chain=[{"step": "source", "vid": start_vid, "name": sname, "code": 1}],
                path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # Quick check: field/property full_text (e.g., "process.argv" for node named "argv")
        if _vattr(sv, "label") == NodeLabel.IDENTIFIER.value:
            stype = _vattr(sv, "type", "")
            if stype in ("field", "property"):
                full_text = _vattr(sv, "full_text", "")
                if full_text and full_text != sname and self._is_source_variable(full_text):
                    return self._cached(cache_key, AnalysisResult(
                        code=1, reason=f"'{full_text}' is a superglobal (via member '{sname}')",
                        chain=[{"step": "source", "vid": start_vid, "name": full_text, "code": 1}],
                        path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        if _vattr(sv, "label") == NodeLabel.CONST.value:
            # Ruby string interpolation: a const string with DFG edges from
            # interpolated variables (e.g. userInput → dfg → "User: #{userInput}").
            # Continue BFS through these incoming DFG edges instead of returning constant.
            has_dfg_in = False
            for e in self.graph.es.select(_target=start_vid, label="dfg"):
                has_dfg_in = True
                break
            if not has_dfg_in:
                return self._cached(cache_key, AnalysisResult(
                    code=-1, reason=f"'{sname}' is a constant",
                    chain=[{"step": "const", "vid": start_vid, "name": sname, "code": -1}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # Check member access on start node: $_GET['cmd'] / $obj->prop
        # Supports nested chains: $_FILES['uploaded']['tmp_name']
        if _vattr(sv, "type") in ("field", "property"):
            # Quick reject: if this member key itself is a known non-source key
            # of a superglobal (e.g., tmp_name for $_FILES), don't waste BFS cycles.
            # The parent variable may trace back to the superglobal via DFG, but
            # this specific member access returns a server-generated value.
            if sname in _FILES_NON_SOURCE_MEMBERS:
                return self._cached(cache_key, AnalysisResult(
                    code=-1,
                    reason=f"member key '{sname}' is a non-source property (server-generated)",
                    chain=[{"step": "non_source_member", "vid": start_vid,
                            "name": sname, "code": -1}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
            cur_member = start_vid
            for _ in range(10):
                member_edges = list(self.graph.es.select(_target=cur_member, label="member"))
                if not member_edges:
                    break
                obj_vid = member_edges[0].source
                obj_v = self.graph.vs[obj_vid]
                obj_name = _vattr(obj_v, "name", "")
                obj_label = _vattr(obj_v, "label", "")
                obj_type = _vattr(obj_v, "type", "")
                if self._is_source_variable(obj_name):
                    # $_SERVER has mixed controllability — skip server-config keys
                    # $_FILES has mixed controllability — skip non-source sub-keys
                    if (obj_name == "$_SERVER" and sname in _SERVER_UNCONTROLLED_KEYS) \
                            or (obj_name == "$_FILES" and sname in _FILES_NON_SOURCE_MEMBERS):
                        pass
                    else:
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"superglobal '{obj_name}' via member access",
                            chain=[{"step": "member_source", "vid": obj_vid,
                                    "name": obj_name, "code": 1}],
                            path=[start_vid, obj_vid],
                            expr_lineno=_vattr(obj_v, "lineno", 0)))
                if obj_label == NodeLabel.IDENTIFIER.value and obj_type in ("field", "property"):
                    cur_member = obj_vid
                else:
                    break

        if _vattr(sv, "label") == NodeLabel.OPERATOR.value \
                and _vattr(sv, "type") in _CALL_TYPES:
            callee = self._resolve_callee_name(start_vid)
            if callee and self._is_repair_function(callee):
                return self._cached(cache_key, AnalysisResult(
                    code=2, reason=f"calls repair '{callee}'",
                    chain=[{"step": "repair", "vid": start_vid, "name": callee, "code": 2}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # Start-node passthrough: when the starting arg itself is a call
        # operator annotated as passthrough (by enrich_taint), its arguments
        # flow into it via ast[arg] edges (not dfg).  Recursively trace each
        # passthrough-marked argument to find controllable sources.
        if _vattr(sv, "label") == NodeLabel.OPERATOR.value \
                and _vattr(sv, "type") in _CALL_TYPES:
            node_taint = _vattr(sv, "taint_type", "")
            if node_taint == "passthrough":
                tp = _vattr(sv, "taint_passthrough", [])
                pt_indices: set[int] = set(
                    int(i) for i in tp if isinstance(i, int)
                )
                if pt_indices:
                    arg_counter = 0
                    for ae in self.graph.es.select(
                        _source=start_vid, label="ast"
                    ):
                        if _vattr(ae, "role") != "arg":
                            continue
                        idx = _vattr(ae, "index")
                        actual_idx = int(idx) if idx else arg_counter
                        if actual_idx in pt_indices:
                            r = self.parameters_back(
                                ae.target,
                                max_depth=max_depth - 1,
                                context_vid=context_vid,
                            )
                            if r is not None and r.is_controllable:
                                return self._cached(cache_key, r)
                        arg_counter += 1

        # BFS backward along dfg edges
        visited: set[int] = {start_vid}
        queue: deque[tuple[int, int, list[int]]] = deque()
        queue.append((start_vid, 0, [start_vid]))

        # Pre-check: if start_vid itself is a property in a member chain,
        # walk the chain to find a source variable (e.g., $_FILES['uploaded']['tmp_name'])
        start_label = _vattr(sv, "label", "")
        start_type = _vattr(sv, "type", "")
        if start_label == NodeLabel.IDENTIFIER.value and start_type in ("field", "property"):
            # Quick reject: if this member key itself is a known non-source key
            # of a superglobal (e.g., tmp_name for $_FILES), don't waste BFS cycles.
            # The parent variable may trace back to the superglobal via DFG, but
            # this specific member access returns a server-generated value.
            if sname in _FILES_NON_SOURCE_MEMBERS:
                return self._cached(cache_key, AnalysisResult(
                    code=-1,
                    reason=f"member key '{sname}' is a non-source property (server-generated)",
                    chain=[{"step": "non_source_member", "vid": start_vid,
                            "name": sname, "code": -1}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
            cur_member = start_vid
            for _ in range(10):
                member_edges = list(self.graph.es.select(_target=cur_member, label="member"))
                if not member_edges:
                    break
                obj_vid = member_edges[0].source
                obj_v = self.graph.vs[obj_vid]
                obj_name = _vattr(obj_v, "name", "")
                obj_label = _vattr(obj_v, "label", "")
                obj_type = _vattr(obj_v, "type", "")
                if self._is_source_variable(obj_name):
                    # $_SERVER has mixed controllability — skip server-config keys
                    # $_FILES has mixed controllability — skip non-source sub-keys
                    if (obj_name == "$_SERVER" and sname in _SERVER_UNCONTROLLED_KEYS) \
                            or (obj_name == "$_FILES" and sname in _FILES_NON_SOURCE_MEMBERS):
                        pass
                    else:
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"superglobal '{obj_name}' via member access",
                            chain=[{"step": "member_source", "vid": obj_vid,
                                    "name": obj_name, "code": 1}],
                            path=[start_vid, obj_vid],
                            expr_lineno=_vattr(obj_v, "lineno", 0)))
                if obj_label == NodeLabel.IDENTIFIER.value and obj_type in ("field", "property"):
                    cur_member = obj_vid
                else:
                    break

        # Pre-compute branch chain for the sink arg (start_vid).
        # Branch constraints protect the sink location, not intermediate
        # trace nodes.  A variable assigned before a match/case but used
        # inside a specific case body must be checked against that case
        # constraint, not against the assignment's location.
        sink_branch_chain = self.get_branch_chain(start_vid)
        sink_branch_set: set[int] = set(sink_branch_chain)
        # Fallback: if BFS exhausts but visited a parameter node,
        # treat it as entry point (code=4).  This handles the case where
        # _analyze_parameter_passing creates cross-file arg→param DFG
        # edges (e.g. test file caller → source file parameter), making
        # the parameter appear "defined" even though it's still a function
        # boundary entry.
        param_fallback: AnalysisResult | None = None

        while queue:
            cur_vid, depth, path = queue.popleft()
            for up_vid in self._get_dfg_sources(cur_vid):
                if up_vid in visited:
                    continue
                # Skip DFG edges marked as branch-safe (pre-processed).
                # These edges carry data that has been validated by a
                # branch condition (e.g., is_numeric guard).
                # Scope gate: only respect branch-safe when the target node
                # (cur_vid) shares a branch scope with the sink.  Cross-scope
                # branch-safe marks should not block BFS traversal — e.g.
                # vid=28 (cmd in if-A) is marked branch-safe, but BFS from
                # vid=38 (cmd in if-B) must still traverse through vid=28
                # to reach the true source (argv).
                if self._is_dfg_branch_safe(up_vid, cur_vid):
                    cur_bc = self.get_branch_chain(cur_vid)
                    if cur_bc and (set(cur_bc) & sink_branch_set):
                        continue
                visited.add(up_vid)
                uv = self.graph.vs[up_vid]
                # Safe node — taint propagation stops here
                up_taint = _vattr(uv, "taint_type", "")
                if up_taint == "safe":
                    continue
                # Fix 14: type cast operators also sanitize taint.
                # (int), (float), (bool) etc. destroy string content.
                if _vattr(uv, "type", "") == "type_cast" and _vattr(uv, "name", "") in _TYPE_CAST_SAFE:
                    continue
                uname = _vattr(uv, "name", "")
                ulabel = _vattr(uv, "label", "")
                utype = _vattr(uv, "type", "")
                new_path = path + [up_vid]

                # Rule 0: function parameter (entry point)
                if ulabel == "parameter":
                    # Check for taint_type="source" annotation on parameter
                    # nodes (set by enrich_taint for framework-injected request
                    # objects like PHP $request, Python request, etc.).
                    node_taint = _vattr(uv, "taint_type", "")
                    if node_taint == "source":
                        logger.debug(
                            "entry parameter '%s' vid=%d has taint_type=source → controllable",
                            uname, up_vid,
                        )
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"tainted parameter '{uname}'",
                            chain=[{"step": "source", "vid": up_vid,
                                    "name": uname, "code": 1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))
                    # For Go: *http.Request etc. are user-controlled sources
                    # Checked here (after taint_type=source, before Java type checks)
                    # so Go source types are recognized without needing enrich_taint annotations.
                    if self.language == "go":
                        go_type = _vattr(uv, "go_type", "")
                        if go_type in _GO_SOURCE_TYPES:
                            logger.debug(
                                "entry parameter '%s' vid=%d (Go source type '%s', controllable)",
                                uname, up_vid, go_type,
                            )
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"Go source type '{go_type}'",
                                chain=[{"step": "source_type", "vid": up_vid,
                                        "name": uname, "code": 1}],
                                path=new_path,
                                expr_lineno=_vattr(uv, "lineno", 0)))
                    # Check for user-controlled annotations (Spring/JAX-RS) first,
                    # regardless of DFG upstream.  Parameters annotated with
                    # @RequestParam, @PathVariable, @RequestBody etc. are
                    # user-controlled HTTP input sources.
                    if self.language in ("java", "kotlin"):
                        if self._has_user_controlled_annotation(up_vid):
                            logger.debug(
                                "entry parameter '%s' vid=%d has user-controlled annotation → controllable",
                                uname, up_vid,
                            )
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"user-controlled annotation on '{uname}'",
                                chain=[{"step": "source", "vid": up_vid,
                                        "name": uname, "code": 1}],
                                path=new_path,
                                expr_lineno=_vattr(uv, "lineno", 0)))
                        # Check java_type: numeric primitive/wrapper types cannot
                        # carry injection payloads (Long, Integer, int, etc.).
                        # Even if upstream data is user-controlled, the type system
                        # restricts the value to non-injectable forms.
                        _NUMERIC_JAVA_TYPES = frozenset({
                            "int", "long", "float", "double", "short", "byte",
                            "Integer", "Long", "Float", "Double", "Short", "Byte",
                            "BigInteger", "BigDecimal", "Number",
                        })
                        # Collection types (List, Set, Map, etc.) cannot be directly
                        # used as injection payloads. In MyBatis ${param} with a
                        # List param produces "[1, 2, 3]" which is not valid SQL.
                        # The normalizer doesn't extract generic params, so
                        # java_type is just "List" without "<Long>".
                        _COLLECTION_JAVA_TYPES = frozenset({
                            "List", "Set", "Map", "Collection",
                            "ArrayList", "LinkedList", "HashSet", "TreeSet",
                            "HashMap", "TreeMap", "LinkedHashMap",
                            "Queue", "Deque", "Stack", "Vector",
                            "Iterator", "Iterable", "Enumeration",
                        })
                        _NON_INJECTABLE_JAVA_TYPES = _NUMERIC_JAVA_TYPES | _COLLECTION_JAVA_TYPES
                        param_java_type = _vattr(uv, "java_type", "")
                        if param_java_type in _NON_INJECTABLE_JAVA_TYPES:
                            logger.debug(
                                "parameter '%s' vid=%d (java_type='%s', numeric — not injectable)",
                                uname, up_vid, param_java_type,
                            )
                            # Record as fallback but continue BFS — other DFG paths
                            # may still reach a controllable source.
                            if param_fallback is None:
                                param_fallback = AnalysisResult(
                                    code=-1,
                                    reason=f"parameter '{uname}' (numeric java_type: {param_java_type})",
                                    chain=[{"step": "entry_param", "vid": up_vid,
                                            "name": uname, "code": -1}],
                                    path=new_path,
                                    expr_lineno=_vattr(uv, "lineno", 0))
                            continue
                    # If this parameter has no DFG upstream, it's an entry point
                    if not list(self._get_dfg_sources(up_vid)):
                        # For Java/Kotlin: check if this is a framework-injected
                        # parameter type (e.g. Authentication, HttpServletRequest).
                        # These are NOT user-controlled and should be treated as
                        # uncontrollable to avoid false positives.
                        if self.language in ("java", "kotlin"):
                            java_type = _vattr(uv, "java_type", "")
                            if java_type in _FRAMEWORK_INJECTED_TYPES:
                                logger.debug(
                                    "entry parameter '%s' vid=%d (framework type '%s', uncontrollable)",
                                    uname, up_vid, java_type,
                                )
                                # Record as fallback but continue BFS — other
                                # DFG paths (e.g. sink arguments independent of
                                # this DI receiver) may still reach a source.
                                if param_fallback is None:
                                    param_fallback = AnalysisResult(
                                        code=-1,
                                        reason=f"entry parameter '{uname}' (framework type: {java_type})",
                                        chain=[{"step": "entry_param", "vid": up_vid,
                                                "name": uname, "code": -1}],
                                        path=new_path,
                                        expr_lineno=_vattr(uv, "lineno", 0))
                                continue
                            # Check parameter-level annotations for
                            # framework-injected identity markers (e.g. @CurrentUsername).
                            safe_ann = self._check_safe_param_annotation(up_vid)
                            if safe_ann:
                                logger.debug(
                                    "entry parameter '%s' vid=%d (safe annotation '%s')",
                                    uname, up_vid, safe_ann,
                                )
                                if param_fallback is None:
                                    param_fallback = AnalysisResult(
                                        code=-1,
                                        reason=f"entry parameter '{uname}' (safe annotation: {safe_ann})",
                                        chain=[{"step": "entry_param", "vid": up_vid,
                                                "name": uname, "code": -1}],
                                        path=new_path,
                                        expr_lineno=_vattr(uv, "lineno", 0))
                                continue
                        logger.debug(
                            "unresolved entry parameter '%s' vid=%d (no DFG upstream → recording as fallback, continue BFS)",
                            uname, up_vid,
                        )
                        # Don't return immediately — other DFG paths from the
                        # same sink may still reach a controllable source.
                        # E.g. jdbcTemplate.queryForObject(sql, rowMapper):
                        #   jdbcTemplate → DI bean (uncontrollable receiver)
                        #   sql → built from user input (controllable argument)
                        # We must continue BFS to check the argument path.
                        if param_fallback is None:
                            param_fallback = AnalysisResult(
                                code=-1,
                                reason=f"unresolved entry parameter '{uname}'",
                                chain=[{"step": "entry_param", "vid": up_vid,
                                        "name": uname, "code": -1}],
                                path=new_path,
                                expr_lineno=_vattr(uv, "lineno", 0))
                        continue
                    # Parameter has DFG upstream — continue BFS.
                    # Record as fallback entry point — if BFS exhausts without
                    # reaching a source, treat as uncontrollable (not all function
                    # parameters come from tainted callers).
                    if param_fallback is None:
                        param_fallback = AnalysisResult(
                            code=-1,
                            reason=f"unresolved entry parameter '{uname}'",
                            chain=[{"step": "entry_param", "vid": up_vid,
                                    "name": uname, "code": -1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0))

                # Rule 1: superglobal
                if self._is_source_variable(uname):
                    # $_SERVER/$_FILES have mixed controllability per key — check if all
                    # member children in this file are non-source keys
                    if self._is_superglobal_only_non_source_members(up_vid):
                        logger.debug("superglobal blocked: all member keys non-source, vid=%d", up_vid)
                        continue
                    logger.debug("source found '%s' vid=%d", uname, up_vid)
                    return self._cached(cache_key, AnalysisResult(
                        code=1, reason=f"superglobal '{uname}'",
                        chain=[{"step": "dfg", "vid": up_vid, "name": uname, "code": 1}],
                        path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 1b: member/field identifier — check full_text and member
                # chain for source (e.g., environ → os.environ → source)
                if ulabel == NodeLabel.IDENTIFIER.value and utype in ("field", "property"):
                    full_text = _vattr(uv, "full_text", "")
                    if full_text and full_text != uname:
                        if self._is_source_variable(full_text):
                            # $_SERVER/$_FILES have mixed controllability — check member chain
                            if self._is_superglobal_member_blocked(up_vid):
                                pass
                            else:
                                logger.debug("source found via full_text '%s' vid=%d", full_text, up_vid)
                                return self._cached(cache_key, AnalysisResult(
                                    code=1, reason=f"superglobal '{full_text}' (via member '{uname}')",
                                    chain=[{"step": "dfg", "vid": up_vid,
                                            "name": full_text, "code": 1}],
                                    path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))
                    # Reconstruct member chain (a.b.c → check "a.b.c", "a.b", "a")
                    chain_name = self._is_source_via_member_chain(up_vid, uname)
                    if chain_name:
                        # $_SERVER/$_FILES have mixed controllability — check member chain
                        if self._is_superglobal_member_blocked(up_vid):
                            pass
                        else:
                            logger.debug("source found via member chain '%s' vid=%d", chain_name, up_vid)
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"superglobal '{chain_name}' (via member chain from '{uname}')",
                                chain=[{"step": "dfg", "vid": up_vid,
                                        "name": chain_name, "code": 1}],
                                path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 2: constant — skip, keep searching
                if ulabel == NodeLabel.CONST.value:
                    continue

                # Rule 2b: binary_op / subscript / call (e.g., sys.argv[0],
                # arr[key], obj.method()) — check ast children for source
                # variable (the object being indexed/called).  DFG only flows
                # from the operator to its result; the indexed/called object is
                # connected via ast edges, not dfg.
                if ulabel == NodeLabel.OPERATOR.value and utype in (
                    "binary_op", "subscript", "call",
                ):
                    for ae in self.graph.es.select(_source=up_vid, label="ast"):
                        child_vid = ae.target
                        cv = self.graph.vs[child_vid]
                        child_name = _vattr(cv, "name", "")
                        child_type = _vattr(cv, "type", "")
                        child_label = _vattr(cv, "label", "")
                        # Direct name check
                        if self._is_source_variable(child_name):
                            if self._is_superglobal_member_blocked(child_vid):
                                pass
                            else:
                                return self._cached(cache_key, AnalysisResult(
                                    code=1,
                                    reason=f"superglobal '{child_name}' via subscript",
                                    chain=[{"step": "subscript_source", "vid": child_vid,
                                            "name": child_name, "code": 1}],
                                    path=new_path + [child_vid],
                                    expr_lineno=_vattr(cv, "lineno", 0)))
                        # Member chain check (e.g., argv → sys.argv)
                        if child_label == NodeLabel.IDENTIFIER.value and child_type in ("field", "property"):
                            chain_name = self._is_source_via_member_chain(child_vid, child_name)
                            if chain_name:
                                if self._is_superglobal_member_blocked(child_vid):
                                    pass
                                else:
                                    return self._cached(cache_key, AnalysisResult(
                                        code=1,
                                        reason=f"superglobal '{chain_name}' via subscript member chain",
                                        chain=[{"step": "subscript_source", "vid": child_vid,
                                                "name": chain_name, "code": 1}],
                                        path=new_path + [child_vid],
                                        expr_lineno=_vattr(cv, "lineno", 0)))

                # Rule 2c: operator(method_call/static_call) — JS-style member
                # chain where operator name IS the full dotted path
                # (e.g., "process.env.INPUT", "req.query.cmd").
                # The operator's name may directly match source_registry, or
                # we can reconstruct parent chain via incoming member edges.
                if ulabel == NodeLabel.OPERATOR.value and utype in (
                    "method_call", "static_call",
                ):
                    # Direct name check — operator name may be "process.env.INPUT"
                    if self._is_source_variable(uname):
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"superglobal '{uname}' (operator member chain)",
                            chain=[{"step": "dfg", "vid": up_vid,
                                    "name": uname, "code": 1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))
                    # Member chain reconstruction from operator
                    chain_name = self._is_source_via_member_chain(up_vid, uname)
                    if chain_name:
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"superglobal '{chain_name}' (operator member chain)",
                            chain=[{"step": "dfg", "vid": up_vid,
                                    "name": chain_name, "code": 1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 3: repair function
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    callee = self._resolve_callee_name(up_vid)
                    if callee and self._is_repair_function(callee):
                        return self._cached(cache_key, AnalysisResult(
                            code=2, reason=f"repair '{callee}'",
                            chain=[{"step": "dfg", "vid": up_vid, "name": callee, "code": 2}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 3b: superglobal method call (e.g., request.GET.get() in Python)
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    is_sg, sg_name = self._is_superglobal_method_call(up_vid)
                    if is_sg:
                        callee = self._resolve_callee_name(up_vid)
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"superglobal '{sg_name}' via method '{callee}'",
                            chain=[{"step": "sg_method", "vid": up_vid,
                                    "name": f"{sg_name}.{callee}", "code": 1}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 3c: operator with taint_type="source" (enriched by knowledge_bridge)
                # e.g., std::env::var("INPUT") in Rust, document.cookie in JS
                if ulabel == NodeLabel.OPERATOR.value:
                    node_taint = _vattr(uv, "taint_type", "")
                    if node_taint == "source":
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"source function '{uname}'",
                            chain=[{"step": "taint_source", "vid": up_vid,
                                    "name": uname, "code": 1}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 4: function call — cg → function(taint_type) → parameter(passthrough_arg)
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    callee = self._resolve_callee_name(up_vid)

                    # 沿 use 边找到 function 定义节点，读 taint_type
                    func_taint = ""
                    func_vid = None
                    for ce in self.graph.es.select(_source=up_vid, label="use"):
                        fv = self.graph.vs[ce.target]
                        if _vattr(fv, "label") == NodeLabel.FUNCTION.value:
                            func_vid = ce.target
                            func_taint = _vattr(fv, "taint_type", "")
                            break

                    # 如果 use 边没找到 function 定义，检查 call 节点自身的 taint 属性
                    # （builtin 函数调用被 enrich_taint 直接标注在 call 节点上）
                    if not func_taint:
                        func_taint = _vattr(uv, "taint_type", "")
                        if func_taint:
                            func_vid = up_vid

                    # 4a: source — 函数本身产生可控数据
                    if func_taint == "source":
                        return self._cached(cache_key, AnalysisResult(
                            code=1, reason=f"taint source '{callee}'",
                            chain=[{"step": "taint_source", "vid": func_vid,
                                    "name": callee, "code": 1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))

                    # 4b: safe — 函数过滤，不可控
                    if func_taint == "safe":
                        return self._cached(cache_key, AnalysisResult(
                            code=-1, reason=f"taint safe '{callee}'",
                            chain=[{"step": "taint_safe", "vid": func_vid,
                                    "name": callee, "code": -1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))

                    # 4c: passthrough — 读 function.taint_passthrough 常驻属性
                    #     function.taint_passthrough 与 parameter.taint_type="passthrough_arg"
                    #     是同一数据的两个视图：反向分析走 function，正向分析走 parameter
                    #     形参 index → 映射到 call 的 ast[role=arg] → 追踪实参
                    if func_taint == "passthrough" and func_vid is not None:
                        # 优先追溯 receiver passthrough (this/self)
                        if _vattr(self.graph.vs[func_vid], "taint_receiver_pt", False):
                            receiver_result = self._trace_call_receiver(
                                up_vid, callee, context_vid,
                                max_depth - depth, new_path)
                            if receiver_result is not None:
                                return self._cached(cache_key, receiver_result)

                        # 位置参数 passthrough：读 function 节点的常驻属性
                        tp = _vattr(self.graph.vs[func_vid], "taint_passthrough", [])
                        pt_param_indices: set[int] = set(
                            int(i) for i in tp if isinstance(i, int)
                        )
                        # 映射到 call 的实参
                        if pt_param_indices:
                            arg_counter = 0
                            for ae in self.graph.es.select(_source=up_vid, label="ast"):
                                if _vattr(ae, "role") != "arg":
                                    continue
                                idx = _vattr(ae, "index")
                                actual_idx = int(idx) if idx else arg_counter
                                if actual_idx in pt_param_indices:
                                    arg_vid = ae.target
                                    # Try tracing arg_vid directly via dfg first;
                                    # only fall back to _find_identifier_by_name (which
                                    # searches the whole graph by name) when the arg has
                                    # no local dfg sources (e.g. bare unbound identifier).
                                    dep_res = self.parameters_back(
                                        arg_vid, context_vid,
                                        max_depth - depth)
                                    if dep_res is None or not dep_res.is_controllable:
                                        arg_name = _vattr(self.graph.vs[arg_vid], "name", "")
                                        if arg_name and dep_res is None:
                                            dep_vid = self._find_identifier_by_name(
                                                arg_name, context_vid)
                                            if dep_vid is not None:
                                                dep_res = self.parameters_back(
                                                    dep_vid, context_vid,
                                                    max_depth - depth)
                                    if dep_res is not None and dep_res.is_controllable:
                                                # Branch scope isolation: if the
                                                # source identifier is outside the
                                                # current branch but up_vid is inside,
                                                # the definition may have been overridden
                                                # inside the branch.
                                                dep_chain = self.get_branch_chain(arg_vid)
                                                cur_chain = self.get_branch_chain(up_vid)
                                                if cur_chain and not set(dep_chain) & set(cur_chain):
                                                    pass  # skip — dep outside branch scope
                                                else:
                                                    return self._cached(cache_key, dep_res)
                                arg_counter += 1

                    # 4d: graph-based function trace (unknown or no taint attribute)
                    # Skip if use-edge already resolved the callee — re-searching by
                    # short name would match unrelated same-named methods across classes.
                    if callee and callee not in self._call_stack and func_vid is None:
                        func_vids = self.find_function_def(callee, from_vid=up_vid)
                        if func_vids:
                            self._call_stack.append(callee)
                            try:
                                ret = self.analyze_function_return(up_vid, func_vids[0])
                            finally:
                                self._call_stack.pop()
                            if ret.is_controllable or ret.is_repaired:
                                ret.path = new_path + ret.path
                                return self._cached(cache_key, ret)
                            if ret.has_deps:
                                for dep_name in ret.deps:
                                    dep_vid = self._find_identifier_by_name(
                                        dep_name, context_vid)
                                    if dep_vid is not None:
                                        dep_res = self.parameters_back(
                                            dep_vid, context_vid, max_depth - depth)
                                        if dep_res.is_controllable:
                                            return self._cached(cache_key, dep_res)

                # Rule 6: branch constraint — identifier inside a branch
                # whose condition constrains this variable to a safe value.
                # Always use the current BFS node's branch chain (more precise
                # than sink's chain for nested branch scenarios).
                # BUT: only check if the current node's branch chain shares
                # at least one branch with the start_vid's chain.  A variable
                # in a *different* code block should not inherit constraints
                # from unrelated branches.  (Fixes cross-block DFG chain
                # pollution — e.g. C's linear cmd→cmd→cmd DFG links that
                # span multiple independent if/else blocks.)
                if ulabel == NodeLabel.IDENTIFIER.value and uname:
                    cur_branch_chain = self.get_branch_chain(up_vid)
                    if cur_branch_chain:
                        # Scope gate: skip if no shared branch with start
                        if not (set(cur_branch_chain) & sink_branch_set):
                            pass  # different code block, no constraint
                        else:
                            # Same branch scope — check constraints
                            # Skip if in ternary iffalse (not constrained)
                            in_ternary_false = False
                            innermost_cur = cur_branch_chain[0]
                            cbtype = _vattr(self.graph.vs[innermost_cur],
                                           "type", "").lower()
                            if cbtype == "ternary" and self._is_in_ternary_iffalse(
                                    up_vid, innermost_cur):
                                in_ternary_false = True

                            if not in_ternary_false:
                                # Check ALL branches in the node's chain,
                                # not just the innermost one. A variable can
                                # be protected by a parent branch constraint.
                                for branch_vid in cur_branch_chain:
                                    if self.check_branch_constraint(
                                            branch_vid, uname):
                                        return self._cached(cache_key,
                                        AnalysisResult(
                                            code=-1,
                                            reason=f"branch constraint on "
                                                   f"'{uname}' in "
                                                   f"{_vattr(self.graph.vs[branch_vid], 'type', '')} "
                                                   f"('{_vattr(self.graph.vs[branch_vid], 'condition', '')}')",
                                            chain=[{"step": "branch_constraint",
                                                    "vid": branch_vid,
                                                    "name": uname,
                                                    "code": -1}],
                                            path=new_path,
                                            expr_lineno=_vattr(uv, "lineno", 0)))

                # Continue BFS
                if ulabel in (NodeLabel.IDENTIFIER.value,
                              NodeLabel.OPERATOR.value,
                              NodeLabel.RETURN.value,
                              NodeLabel.PARAMETER.value):
                    if depth + 1 < max_depth:
                        queue.append((up_vid, depth + 1, new_path))

                # Rule 5: member access — e.g. $_GET['id'] or $obj->prop
                # The identifier 'id' is the property/key, track back via
                # member edge to find the object node ($_GET).
                # Support nested member chains: $_FILES['uploaded']['tmp_name']
                # → member chain tmp_name←uploaded←$_FILES
                if ulabel == NodeLabel.IDENTIFIER.value and _vattr(uv, "type") in ("field", "property"):
                    cur_member = up_vid
                    for _ in range(10):
                        member_edges = list(self.graph.es.select(_target=cur_member, label="member"))
                        if not member_edges:
                            break
                        obj_vid = member_edges[0].source
                        obj_v = self.graph.vs[obj_vid]
                        obj_name = _vattr(obj_v, "name", "")
                        obj_label = _vattr(obj_v, "label", "")
                        obj_type = _vattr(obj_v, "type", "")
                        if self._is_source_variable(obj_name):
                            # $_SERVER/$_FILES have mixed controllability — check member chain
                            if self._is_superglobal_member_blocked(cur_member):
                                break
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"superglobal '{obj_name}' via member access",
                                chain=[{"step": "member_source", "vid": obj_vid,
                                        "name": obj_name, "code": 1}],
                                path=new_path + [obj_vid],
                                expr_lineno=_vattr(obj_v, "lineno", 0)))
                        if obj_label == NodeLabel.IDENTIFIER.value and obj_type in ("field", "property"):
                            cur_member = obj_vid
                        else:
                            break

        # Before returning Inconclusive, try "same-name variable def-chaining":
        # SSA-like graphs create separate identifier nodes per assignment.
        # When $target = str_replace(..., $target) forms a DFG cycle, BFS
        # visits vid=14953→14954→14960→14953 and exhausts without reaching
        # vid=14947 ($target = $_REQUEST['ip'], the real source).
        # Fix: collect all identifier names in visited, find same-name
        # identifier nodes in the same file not in visited, and recursively
        # check if they lead to a controllable source.
        start_fp = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        if start_fp and len(visited) > 2:
            # Collect identifier names encountered during BFS
            visited_idents: dict[str, list[int]] = {}
            for up_vid in visited:
                uv = self.graph.vs[up_vid]
                if _vattr(uv, "label") != NodeLabel.IDENTIFIER.value:
                    continue
                u_name = _vattr(uv, "name", "")
                if not u_name:
                    continue
                visited_idents.setdefault(u_name, []).append(up_vid)
            # For each identifier name, find same-file same-name nodes NOT in visited
            # Use attribute-based filtering to avoid full graph scan
            checked: set[int] = set()
            for u_name, vids in visited_idents.items():
                # Fast path: select vertices by name attribute
                for cand in self._nname.get(
                    (NodeLabel.IDENTIFIER.value, u_name), []
                ):
                    if cand in visited or cand in checked:
                        continue
                    cand_fp = _vattr(self.graph.vs[cand], "file_path", "") or _vattr(self.graph.vs[cand], "path", "")
                    if cand_fp != start_fp:
                        continue
                    # Function scope check: def-chain should not cross
                    # function boundaries. Variables with the same name
                    # in different functions are unrelated.
                    cand_func = self._get_enclosing_func_vid(cand)
                    start_func = self._get_enclosing_func_vid(start_vid)
                    if cand_func is not None and start_func is not None and cand_func != start_func:
                        continue
                    checked.add(cand)
                    # Skip candidates that have branch-safe DFG edges
                    # (their value is protected by a branch constraint).
                    if self._has_branch_safe_dfg_in(cand):
                        continue
                    # Skip candidates that are NOT in the same branch scope
                    # as the start_vid. Def-chaining should not cross branch
                    # boundaries — a variable inside an if-branch should not
                    # be linked to the same-named variable outside the branch.
                    if sink_branch_chain:
                        cand_chain = self.get_branch_chain(cand)
                        # Candidate must share at least one ancestor branch
                        if not set(cand_chain) & sink_branch_set:
                            continue
                    # Check if this candidate has DFG sources to trace
                    if self._get_dfg_sources(cand):
                        # Use _trace_dfg_direct to avoid recursive
                        # parameters_back calling def-chain again
                        r = self._trace_dfg_direct(cand, max_depth=20, file_path=start_fp)
                        if r is not None and r.is_controllable:
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"def-chain '{u_name}' → {r.reason}",
                                chain=r.chain,
                                path=r.path,
                                expr_lineno=r.expr_lineno))

        # Exhausted
        if param_fallback is not None:
            return self._cached(cache_key, param_fallback)
        return self._cached(cache_key, AnalysisResult(
            code=3,
            reason=f"Inconclusive for vid={start_vid} ('{sname}') after {max_depth} hops",
            chain=[{"step": "exhausted", "vid": start_vid, "name": sname, "code": 3}],
            path=[start_vid] + list(visited), expr_lineno=_vattr(sv, "lineno", 0)))

    # --- Receiver passthrough tracing ------------------------------------

    def _trace_call_receiver(self, call_vid: int, callee_name: str,
                              context_vid: int | None, max_depth: int,
                              path: list[int]) -> AnalysisResult | None:
        """追溯 method call 的 receiver (this/self) 的可控性。

        三种追溯策略（按优先级）：
        1. 沿已有 DFG receiver 边回溯（通用，适用于所有语言）
        2. 沿 callee member chain 回溯到 root identifier（JS/Go 的 member expression）
        3. 在 call 的 own/ast 子节点中查找 this/self identifier（PHP $this 等）
        """
        # 策略 1: 检查是否有 DFG receiver 边指向 call（forward_slice，且 source 不是 callee 的参数）
        callee_arg_vids: set[int] = set()
        for ae in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(ae, "role") == "arg":
                callee_arg_vids.add(ae.target)
        for e in self.graph.es.select(_target=call_vid, label="dfg"):
            source_vid = e.source
            if source_vid in callee_arg_vids:
                continue  # source 是 call 的实参，不是 receiver
            source_name = _vattr(self.graph.vs[source_vid], "name", "")
            if not source_name:
                continue
            dep_vid = self._find_identifier_by_name(source_name, context_vid)
            if dep_vid is None:
                continue
            result = self.parameters_back(dep_vid, context_vid, max_depth)
            if result.is_controllable:
                return AnalysisResult(
                    code=result.code,
                    reason=f"receiver '{source_name}' ({callee_name})",
                    chain=[{"step": "receiver_pt", "vid": dep_vid,
                            "name": source_name, "code": result.code}],
                    path=path,
                    expr_lineno=_vattr(self.graph.vs[call_vid], "lineno", 0))

        # 策略 2: 沿 callee member chain 回溯到 root identifier（JS/Go）
        callee_vid = None
        for e in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                callee_vid = e.target
                break
        if callee_vid is not None:
            root_vid = self._trace_member_chain_root(callee_vid)
            if root_vid is not None:
                root_name = _vattr(self.graph.vs[root_vid], "name", "")
                if root_name:
                    dep_vid = self._find_identifier_by_name(root_name, context_vid)
                    if dep_vid is not None:
                        result = self.parameters_back(dep_vid, context_vid, max_depth)
                        if result.is_controllable:
                            return AnalysisResult(
                                code=result.code,
                                reason=f"receiver '{root_name}' ({callee_name})",
                                chain=[{"step": "receiver_pt", "vid": dep_vid,
                                        "name": root_name, "code": result.code}],
                                path=path,
                                expr_lineno=_vattr(self.graph.vs[call_vid], "lineno", 0))

        # 策略 3: 在 call 的 own/ast 父节点的子节点中查找 this/self identifier
        parent_vid = None
        for e in self.graph.es.select(_target=call_vid):
            elabel = _vattr(e, "label", "")
            if elabel in ("own", "ast"):
                parent_vid = e.source
                break
        if parent_vid is not None:
            for e in self.graph.es.select(_source=parent_vid):
                elabel = _vattr(e, "label", "")
                if elabel not in ("own", "ast"):
                    continue
                child = self.graph.vs[e.target]
                child_name = _vattr(child, "name", "")
                if child_name in ("this", "self"):
                    dep_vid = self._find_identifier_by_name(child_name, context_vid)
                    if dep_vid is None:
                        continue
                    result = self.parameters_back(dep_vid, context_vid, max_depth)
                    if result.is_controllable:
                        return AnalysisResult(
                            code=result.code,
                            reason=f"receiver '{child_name}' ({callee_name})",
                            chain=[{"step": "receiver_pt", "vid": dep_vid,
                                    "name": child_name, "code": result.code}],
                            path=path,
                            expr_lineno=_vattr(self.graph.vs[call_vid], "lineno", 0))

        return None

    def _trace_member_chain_root(self, callee_vid: int) -> int | None:
        """沿 member 边链回溯到 root identifier。

        例如 callee_vid("location.hash.slice") <-- member -- ("location.hash")
                                    <-- member -- ("location")  → 返回 root identifier
        遇到 operator 节点（中间表达式）则继续向上回溯。
        """
        current = callee_vid
        visited: set[int] = {current}
        while True:
            found = False
            for e in self.graph.es.select(_target=current, label="member"):
                source = e.source
                if source in visited:
                    continue
                visited.add(source)
                src_label = _vattr(self.graph.vs[source], "label", "")
                if src_label == NodeLabel.IDENTIFIER.value:
                    return source
                elif src_label == NodeLabel.OPERATOR.value:
                    current = source
                    found = True
                    break
            if not found:
                return None

    # --- Function definition lookup --------------------------------------

    def find_function_def(self, func_name: str,
                           from_vid: int | None = None) -> list[int]:
        """Find function/method definition node(s).  Prefers same-file matches."""
        scope_path: str | None = None
        if from_vid is not None:
            scope_path = _vattr(self.graph.vs[from_vid], "file_path", None)

        results: list[int] = []
        for vid in self._nlbl.get(NodeLabel.FUNCTION.value, []):
            v = self.graph.vs[vid]
            vn = _vattr(v, "name", "") or ""
            vf = _vattr(v, "fullname", "") or ""
            if not (vn == func_name or vf.endswith("\\" + func_name) or vf == func_name):
                continue
            if scope_path:
                fp = _vattr(v, "file_path") or ""
                if fp == scope_path:
                    results.insert(0, vid)
                else:
                    results.append(vid)
            else:
                results.append(vid)
        logger.debug("find_function_def('%s', from=%s) → %s",
                      func_name, from_vid, results)
        return results

    # --- Function return analysis -----------------------------------------

    def analyze_function_return(self, call_vid: int,
                                  func_vid: int) -> AnalysisResult:
        """Analyze whether a function's return value is controllable.

        1. Map formal params to actual args (positional).
        2. Find return nodes and trace their expressions backward.
        3. If return depends on a controllable param → code=1.
           If return depends on a caller variable → code='deps'.
        """
        call_v = self.graph.vs[call_vid]

        # Formal params: own children with label=parameter
        param_vids = self._find_own_children(func_vid, child_label=NodeLabel.PARAMETER.value)
        formal: dict[int, tuple[int, str]] = {}
        for pvid in param_vids:
            pv = self.graph.vs[pvid]
            pidx = _vattr(pv, "index", len(formal))
            formal[int(pidx) if pidx else len(formal)] = (pvid, _vattr(pv, "name", ""))

        # Actual args: ast edges with role=arg from the call operator
        actual_args: dict[int, int] = {}
        arg_counter = 0
        for e in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(e, "role") == "arg":
                idx = _vattr(e, "index")
                actual_args[int(idx) if idx else arg_counter] = e.target
                arg_counter += 1

        # Classify formal params by actual arg controllability
        controllable_indices: set[int] = set()
        caller_deps: list[str] = []
        for fidx, (pvid, pname) in formal.items():
            if fidx not in actual_args:
                continue
            av = self.graph.vs[actual_args[fidx]]
            aname = _vattr(av, "name", "")
            if self._is_source_variable(aname):
                controllable_indices.add(fidx)
            elif _vattr(av, "label") == NodeLabel.CONST.value:
                pass
            else:
                caller_deps.append(aname)

        # Find return children
        return_vids = self._find_own_children(func_vid, child_label=NodeLabel.RETURN.value)
        if not return_vids:
            return AnalysisResult(code=3,
                                  reason=f"No return in func vid={func_vid}",
                                  expr_lineno=_vattr(call_v, "lineno", 0))

        for ret_vid in return_vids:
            rv = self.graph.vs[ret_vid]
            # Find return expression via ast[role=value/rhs] or dfg backward
            expr_vid: int | None = None
            for e in self.graph.es.select(_source=ret_vid, label="ast"):
                if _vattr(e, "role") in ("value", "rhs"):
                    expr_vid = e.target
                    break
            if expr_vid is None:
                ups = self._get_dfg_sources(ret_vid)
                expr_vid = ups[0] if ups else None
            if expr_vid is None:
                continue

            ev = self.graph.vs[expr_vid]
            ename = _vattr(ev, "name", "")

            # Check if expr directly names a controllable formal param
            for fidx, (pvid, pname) in formal.items():
                if ename == pname:
                    if fidx in controllable_indices:
                        return AnalysisResult(
                            code=1,
                            reason=f"Returns controllable param '{pname}'",
                            path=[call_vid, func_vid, ret_vid, expr_vid],
                            expr_lineno=_vattr(rv, "lineno", 0))
                    caller_deps.append(pname)

            # Recurse into return expression
            sub = self.parameters_back(expr_vid, context_vid=func_vid, max_depth=20)
            if sub.is_controllable:
                return sub
            if sub.has_deps:
                caller_deps.extend(sub.deps)

        if controllable_indices:
            return AnalysisResult(code=1, reason="Return depends on controllable params",
                                  deps=caller_deps,
                                  expr_lineno=_vattr(call_v, "lineno", 0))
        if caller_deps:
            return AnalysisResult(code="deps",
                                  reason=f"Return depends on caller vars: {caller_deps}",
                                  deps=caller_deps,
                                  expr_lineno=_vattr(call_v, "lineno", 0))
        return AnalysisResult(code=3,
                              reason=f"Return inconclusive (call={call_vid}, func={func_vid})",
                              expr_lineno=_vattr(call_v, "lineno", 0))

    # --- Branch constraint analysis ---------------------------------------

    def analyze_branch_constraint(self, sink_vid: int) -> dict:
        """Check if sink is protected by a branch condition.

        Walks up own edges to find enclosing branch nodes, then checks
        their condition for type-validation, strict regex, etc.

        Returns: {"protected": bool, "constraints": [...], "reason": str}
        """
        constraints: list[dict] = []
        protected = False

        for bvid in self._find_enclosing_branches(sink_vid):
            bv = self.graph.vs[bvid]
            cond = _vattr(bv, "condition", "")
            btype = _vattr(bv, "type", "")
            if not cond:
                continue
            for func in _TYPE_VALIDATION_FUNCS:
                if func in cond:
                    constraints.append({"type": "type_validation",
                                        "function": func, "branch_type": btype})
                    protected = True
            if "preg_match" in cond and self._has_strict_regex(cond):
                constraints.append({"type": "regex_validation",
                                    "pattern": cond, "branch_type": btype})
                protected = True
            if "===" in cond or "==" in cond:
                constraints.append({"type": "equality_check",
                                    "condition": cond, "branch_type": btype})

        return {
            "protected": protected,
            "constraints": constraints,
            "reason": (f"Protected: {constraints}" if protected
                       else f"No protective constraints for vid={sink_vid}"),
        }

    # --- Decision marking -------------------------------------------------

    def mark_decision(self, vid: int, decision: dict) -> None:
        """Append analysis decision to vertex's 'analysis_decisions' attribute."""
        v = self.graph.vs[vid]
        existing: list = _vattr(v, "analysis_decisions", [])
        if not isinstance(existing, list):
            existing = []
        existing.append(decision)
        v["analysis_decisions"] = existing

    # --- Taint path search ------------------------------------------------

    def find_taint_paths(self, source_vid: int, sink_vid: int,
                         max_depth: int = 20) -> list[dict]:
        """BFS forward along dfg edges from source to sink.

        Returns list of dicts: {"path": [vid...], "length": int, "decisions": []}
        """
        results: list[dict] = []
        visited: set[int] = set()
        queue: deque[tuple[int, int, list[int]]] = deque()
        queue.append((source_vid, 0, [source_vid]))

        while queue:
            cur_vid, depth, path = queue.popleft()
            if depth > max_depth:
                continue
            if cur_vid == sink_vid:
                results.append({"path": path, "length": len(path), "decisions": []})
                continue
            for e in self.graph.es.select(_source=cur_vid, label="dfg"):
                tgt = e.target
                if tgt not in visited:
                    visited.add(tgt)
                    queue.append((tgt, depth + 1, path + [tgt]))
        return results

    # --- Internal helpers -------------------------------------------------

    def _cached(self, key, result: AnalysisResult) -> AnalysisResult:
        self._decision_cache[key] = result
        return result

    def _trace_dfg_direct(self, start_vid: int, max_depth: int = 20,
                          file_path: str = "") -> AnalysisResult | None:
        """Simplified DFG backward trace for def-chain resolution.

        Unlike parameters_back(), this does NOT trigger def-chain recursion,
        preventing infinite loops. Used only by the def-chain fallback in
        parameters_back() when SSA-style graphs create disconnected
        identifier nodes (e.g., $x = f($x) cycles).

        When file_path is provided, the trace is restricted to vertices in
        the same file — preventing cross-file DFG backtracking from
        reaching superglobals defined in unrelated files (e.g. model.php).
        """
        visited: set[int] = {start_vid}
        queue: deque[tuple[int, int]] = deque()
        queue.append((start_vid, 0))
        while queue:
            cur_vid, depth = queue.popleft()
            for up_vid in self._get_dfg_sources(cur_vid):
                if up_vid in visited:
                    continue
                # 文件限制：如果指定了 file_path，跳过不同文件的节点
                if file_path:
                    up_fp = _vattr(self.graph.vs[up_vid], "file_path", "") or _vattr(self.graph.vs[up_vid], "path", "")
                    if up_fp and up_fp != file_path:
                        continue
                visited.add(up_vid)
                uv = self.graph.vs[up_vid]
                # Safe node — taint propagation stops here
                up_taint = _vattr(uv, "taint_type", "")
                if up_taint == "safe":
                    continue
                # Fix 14: type cast operators also sanitize taint.
                # (int), (float), (bool) etc. destroy string content.
                if _vattr(uv, "type", "") == "type_cast" and _vattr(uv, "name", "") in _TYPE_CAST_SAFE:
                    continue
                uname = _vattr(uv, "name", "")
                ulabel = _vattr(uv, "label", "")
                utype = _vattr(uv, "type", "")
                # Source variable
                if self._is_source_variable(uname):
                    if self._is_superglobal_only_non_source_members(up_vid):
                        continue
                    return AnalysisResult(
                        code=1, reason=f"superglobal '{uname}'",
                        chain=[{"step": "dfg", "vid": up_vid, "name": uname, "code": 1}],
                        path=[start_vid, up_vid],
                        expr_lineno=_vattr(uv, "lineno", 0))
                # Member access source (e.g., $_REQUEST['ip'])
                if ulabel == NodeLabel.IDENTIFIER.value and utype in ("field", "property"):
                    full_text = _vattr(uv, "full_text", "")
                    if full_text and full_text != uname and self._is_source_variable(full_text):
                        # $_SERVER has mixed controllability — check member chain for uncontrolled keys
                        if self._is_superglobal_member_blocked(up_vid):
                            pass
                        else:
                            return AnalysisResult(
                                code=1,
                                reason=f"superglobal '{full_text}' (via member '{uname}')",
                                chain=[{"step": "member_source", "vid": up_vid,
                                        "name": full_text, "code": 1}],
                                path=[start_vid, up_vid],
                                expr_lineno=_vattr(uv, "lineno", 0))
                    # Also check member edges for source objects (e.g., $_REQUEST → member → 'ip')
                    for me in self.graph.es.select(_target=up_vid, label="member"):
                        obj_vid = me.source
                        obj_name = _vattr(self.graph.vs[obj_vid], "name", "")
                        if self._is_source_variable(obj_name):
                            # $_SERVER has mixed controllability — check member chain
                            if self._is_superglobal_member_blocked(up_vid):
                                pass
                            else:
                                return AnalysisResult(
                                    code=1,
                                    reason=f"superglobal '{obj_name}' via member access",
                                    chain=[{"step": "member_source", "vid": obj_vid,
                                            "name": obj_name, "code": 1}],
                                    path=[start_vid, up_vid, obj_vid],
                                    expr_lineno=_vattr(self.graph.vs[obj_vid], "lineno", 0))
                # Continue BFS
                if depth + 1 < max_depth:
                    queue.append((up_vid, depth + 1))
        return None

    def _check_safe_param_annotation(self, param_vid: int) -> str | None:
        """Check if a parameter node has a safe annotation (e.g. @CurrentUsername).

        Returns the annotation name if found safe, else None.
        """
        for e in self.graph.es.select(_source=param_vid, label="own"):
            tgt = self.graph.vs[e.target]
            if _vattr(tgt, "label") == "annotation":
                ann_name = _vattr(tgt, "name", "")
                # Check both with and without @ prefix
                check = ann_name if not ann_name.startswith("@") else ann_name
                for safe in _SAFE_PARAM_ANNOTATIONS:
                    safe_check = safe.lstrip("@")
                    if check == safe_check or ann_name == safe:
                        return safe
        return None

    def _has_user_controlled_annotation(self, param_vid: int) -> bool:
        """Check if a Java/Kotlin parameter has a user-controlled annotation.

        Spring annotations like @RequestParam, @PathVariable, @RequestBody
        indicate that the parameter carries user-supplied HTTP input.
        JAX-RS annotations (@QueryParam, @PathParam, @FormParam) similarly.

        Returns False for parameters whose java_type is a numeric primitive
        or wrapper (int, long, float, double, Integer, Long, Float, Double,
        Short, Byte, BigInteger, BigDecimal) — these cannot carry injection
        payloads regardless of annotation.
        """
        # Numeric types are not injectable even if annotated
        _NON_INJECTABLE_TYPES = frozenset({
            "int", "long", "float", "double", "short", "byte",
            "Integer", "Long", "Float", "Double", "Short", "Byte",
            "BigInteger", "BigDecimal", "Number",
        })
        param_v = self.graph.vs[param_vid]
        jtype = _vattr(param_v, "java_type", "")
        if jtype in _NON_INJECTABLE_TYPES:
            return False

        for e in self.graph.es.select(_source=param_vid, label="own"):
            tgt = self.graph.vs[e.target]
            if _vattr(tgt, "label") == "annotation":
                ann_name = _vattr(tgt, "name", "").lstrip("@")
                if ann_name in _USER_CONTROLLED_ANNOTATIONS:
                    return True
        return False

    def _is_source_variable(self, name: str) -> bool:
        if not name:
            return False
        if name in _SUPERGLOBALS:
            return True
        if "[" in name:
            if name.split("[", 1)[0] in _SUPERGLOBALS:
                return True
            # Ruby-style: ARGV[0], ENV['X'] → check "ARGV", "ENV[]", etc.
            base = name.split("[", 1)[0]
            if self._source_registry is not None:
                try:
                    # Check base name directly (e.g., "ARGV")
                    if self._source_registry.is_source_member(base):
                        return True
                    # Check base+[] pattern (e.g., "ENV[]")
                    if self._source_registry.is_source_member(f"{base}[]"):
                        return True
                except Exception:
                    pass
        if "." in name:
            # Support dotted paths like "request.GET"
            if name in _SUPERGLOBALS:
                return True
            # Don't short-circuit — SourceRegistry may recognize it (e.g., params.key)
        # JS/TS source roots (location.hash, document.cookie, process.env, window.name)
        if self.language in ("javascript", "typescript"):
            if name in _JS_SOURCE_ROOTS:
                return True
        # C: argv is a user-controlled source (command-line arguments)
        if self.language == "c":
            if name == "argv" or (name.startswith("argv")):
                return True
        # SourceRegistry: builtin source members for all languages
        # (e.g., Go: os.Args, os.Getenv; C: argv, getenv; Python: sys.argv, os.environ)
        if self._source_registry is not None:
            try:
                if self._source_registry.is_source_member(name):
                    return True
                # Prefix-stripping fallback: Rust normalizer may strip "std::"
                # producing "env::var" while SR has "std::env::var".
                # Also: Java normalizer strips class prefix producing "getParameter"
                # while SR has "getParameter" — but sometimes SR has longer form.
                # Try BOTH directions: strip leading segments from name, AND
                # check if any SR entry ends with the current name.
                for sep in ("::", "."):
                    if sep in name:
                        parts = name.split(sep)
                        # Direction 1: strip leading segments → suffix in SR
                        for i in range(1, len(parts)):
                            sfx = sep.join(parts[i:])
                            if self._source_registry.is_source_member(sfx):
                                return True
                        # Direction 2: check if any SR entry ends with
                        # sep+name (e.g., env::var → std::env::var)
                        try:
                            sr_set = getattr(
                                self._source_registry, 'source_members',
                                getattr(self._source_registry, '_source_members', None),
                            )
                            if sr_set:
                                for sr_entry in sr_set:
                                    if sr_entry.endswith(sep + name) or sr_entry == name:
                                        return True
                        except (AttributeError, TypeError):
                            pass
                        break
            except Exception:
                pass
        return False

    def _is_superglobal_member_blocked(self, vid: int) -> bool:
        """Generalized version of _is_server_member_blocked.
        Checks member chains on $_SERVER and $_FILES for non-source keys."""
        if not self.graph:
            return False
        cur_vid = vid
        chain_names = []
        for _ in range(10):
            member_in = list(self.graph.es.select(_target=cur_vid, label="member"))
            if not member_in:
                break
            parent_vid = member_in[0].source
            parent_name = _vattr(self.graph.vs[parent_vid], "name", "")
            cur_name = _vattr(self.graph.vs[cur_vid], "name", "")
            chain_names.append(cur_name)
            if parent_name == "$_SERVER":
                for key in chain_names:
                    if key in _SERVER_UNCONTROLLED_KEYS:
                        return True
                return False
            if parent_name == "$_FILES":
                for key in chain_names:
                    if key in _FILES_NON_SOURCE_MEMBERS:
                        return True
                return False
            cur_vid = parent_vid
        return False

    def _is_server_member_blocked(self, vid: int) -> bool:
        return self._is_superglobal_member_blocked(vid)

    def _is_superglobal_only_non_source_members(self, sg_vid: int) -> bool:
        """Generalized version of _is_server_only_uncontrolled_members.
        Returns True if ALL outgoing member children of a superglobal node
        ($_SERVER or $_FILES) are non-source keys."""
        if not self.graph:
            return False
        vid_name = _vattr(self.graph.vs[sg_vid], "name", "")
        if vid_name == "$_SERVER":
            non_source_set = _SERVER_UNCONTROLLED_KEYS
        elif vid_name == "$_FILES":
            non_source_set = _FILES_NON_SOURCE_MEMBERS
        else:
            return False
        for e in self.graph.es.select(_source=sg_vid, label="member"):
            child_name = _vattr(self.graph.vs[e.target], "name", "")
            if child_name and child_name not in non_source_set:
                return False
        return True

    def _is_server_only_uncontrolled_members(self, server_vid: int) -> bool:
        return self._is_superglobal_only_non_source_members(server_vid)

    def _is_source_via_member_chain(self, vid: int, name: str) -> str | None:
        """从节点沿 incoming member 边重建组合名，
        检查 source_registry / superglobals。

        支持两种 member chain 图结构:
        1. Python-style: identifier(os) --member--> identifier(environ) --member--> ...
           成员链是 identifier 之间的 member 边。
        2. JS-style: identifier(process) --member--> operator(process.env)
                    --member--> operator(process.env.INPUT)
           成员链是 identifier/operator 交替的 member 边，operator 通过
           ast 边连接内部 property identifier。

        Returns: 第一个匹配 source_registry 的组合名，或 None。
        """
        if not name or self.graph is None:
            return None
        # 快速检查：name 本身就是 source
        if self._is_source_variable(name):
            return name

        # 沿 incoming member 边回溯，逐步拼接组合名
        chain = name
        cur_vid = vid
        for _ in range(10):  # 最多 10 级，防止循环
            member_in = list(self.graph.es.select(_target=cur_vid, label="member"))
            if not member_in:
                break
            parent_vid = member_in[0].source
            parent_v = self.graph.vs[parent_vid]
            parent_name = _vattr(parent_v, "name", "")
            if not parent_name:
                break
            # Avoid double-counting when chain already starts with parent_name
            if chain.startswith(parent_name + "."):
                # chain already has parent as prefix — the parent itself
                # might be the source (e.g., chain="process.env.INPUT",
                # parent="process.env" is in source_registry)
                if self._is_source_variable(parent_name):
                    return parent_name
                break  # no further useful chain to build
            chain = f"{parent_name}.{chain}"
            if self._is_source_variable(chain):
                return chain
            cur_vid = parent_vid

        return None

    def _is_repair_function(self, name: str) -> bool:
        if not name:
            return False
        clean = name.lstrip("\\")
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[-1]
        return clean in _REPAIR_FUNCTIONS

    def _is_sink_function(self, name: str) -> bool:
        if not name:
            return False
        clean = name.lstrip("\\")
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[-1]
        return clean in _SINK_FUNCTIONS

    def _is_superglobal_method_call(self, call_vid: int) -> tuple[bool, str]:
        """Check if a call operator's callee is a method on a superglobal object.

        Walks member edges from the callee identifier to reconstruct the
        object chain (e.g., request.GET.get → check if 'request.GET' is superglobal).

        Returns (is_superglobal, superglobal_name).
        """
        # Find callee identifier via ast[role=callee]
        callee_vid = None
        for ae in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(ae, "role") == "callee":
                callee_vid = ae.target
                break
        if callee_vid is None:
            return False, ""

        callee_name = _vattr(self.graph.vs[callee_vid], "name", "")
        callee_type = _vattr(self.graph.vs[callee_vid], "type", "")

        # If callee is a property (method call like .get()), walk member chain
        if callee_type == "property":
            # Collect member chain: callee → parent → grandparent...
            chain = [callee_name]
            current = callee_vid
            visited_members: set[int] = {callee_vid}
            while True:
                found_member = False
                for me in self.graph.es.select(_target=current, label="member"):
                    obj_vid = me.source
                    if obj_vid in visited_members:
                        continue
                    visited_members.add(obj_vid)
                    obj_name = _vattr(self.graph.vs[obj_vid], "name", "")
                    obj_type = _vattr(self.graph.vs[obj_vid], "type", "")
                    chain.append(obj_name)
                    current = obj_vid
                    found_member = True

                    # Build all possible prefix paths and check
                    # Chain: [get, GET, request] → check "request.GET.get", "request.GET", "request"
                    reversed_chain = list(reversed(chain))
                    for i in range(len(reversed_chain)):
                        prefix = ".".join(reversed_chain[:i+1])
                        if prefix in _SUPERGLOBALS:
                            return True, prefix

                    # Check if the object itself is a superglobal (non-property)
                    if obj_type != "property" and self._is_source_variable(obj_name):
                        return True, obj_name

                    # If object is not a property, stop traversing further
                    if obj_type != "property":
                        break
                if not found_member:
                    break

        return False, ""

    # --- DFG branch-safe edge marking -------------------------------------

    def _mark_branch_safe_dfg(self) -> None:
        """Pre-process: mark DFG edges as branch_safe when the target
        identifier is inside a branch whose condition constrains it.

        For each identifier node, check its branch_chain. If any branch
        in the chain has a check_branch_constraint match for this variable,
        mark all incoming DFG edges as branch_safe=True.

        Also mark identifiers that are re-assigned inside a branch that
        has ANY constraint (even if not directly on this variable), since
        the re-assignment creates a new value derived from constrained data.
        """
        for vid in self._nlbl.get(NodeLabel.IDENTIFIER.value, []):
            v = self.graph.vs[vid]
            uname = _vattr(v, "name", "")
            if not uname:
                continue
            branch_chain = self.get_branch_chain(vid)
            if not branch_chain:
                continue

            # Check if any branch in the chain constrains this variable
            constrained = False
            for bvid in branch_chain:
                if self.check_branch_constraint(bvid, uname):
                    constrained = True
                    break

            # Also mark if any branch in the chain constrains a related
            # variable that this identifier's DFG upstream depends on.
            # This is handled by BFS at runtime — no extra marking needed.

            if constrained:
                for src in self._et(vid, "dfg"):
                    self._branch_safe_set.add((src, vid))

    def _is_dfg_branch_safe(self, source_vid: int, target_vid: int) -> bool:
        """Check if the DFG edge from source_vid to target_vid is
        marked as branch_safe."""
        return (source_vid, target_vid) in self._branch_safe_set

    def _has_branch_safe_dfg_in(self, vid: int) -> bool:
        """Check if vid has any incoming DFG edge marked branch_safe."""
        return any((src, vid) in self._branch_safe_set
                   for src in self._et(vid, "dfg"))

    def _get_dfg_sources(self, vid: int) -> list[int]:
        """Upstream vertices via dfg edges (target=vid → source)."""
        return self._et(vid, "dfg")

    def _ef(self, vid: int, label: str) -> list[int]:
        """edges FROM vid with given label → target vids"""
        return self._esrc.get(label, {}).get(vid, [])

    def _et(self, vid: int, label: str) -> list[int]:
        """edges TO vid with given label → source vids"""
        return self._etgt.get(label, {}).get(vid, [])

    def _has_user_input_annotation(self, param_vid: int) -> bool:
        """Check if a parameter node has a user-input annotation (e.g. @RequestParam).

        Looks for own edges from param to annotation nodes whose name is in
        _USER_INPUT_PARAM_ANNOTATIONS.
        """
        for e in self.graph.es.select(_source=param_vid, label="own"):
            ann = self.graph.vs[e.target]
            ann_name = _vattr(ann, "name", "")
            if ann_name in _USER_INPUT_PARAM_ANNOTATIONS:
                return True
        return False

    def _get_context(self, vid: int) -> int | None:
        """Walk up own edges to find enclosing function/file vid."""
        cur, seen = vid, set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return cur
            inc = self.graph.es.select(_target=cur, label="own")
            cur = inc[0].source if inc else None
        return None

    def _get_ast_parent(self, vid: int) -> int | None:
        """从 vid 沿 ast 边反向找直接父节点（ast[source=parent, target=vid]）。"""
        inc = self.graph.es.select(_target=vid, label="ast")
        return inc[0].source if inc else None

    def get_enclosing_branch(self, vid: int) -> int | None:
        """从 vid 向上搜索，返回包含该节点最近的 branch 节点 vid。

        搜索逻辑：
        1. 先沿 ast 反向走到 own 边的 target（顶层语句）
        2. 再沿 own 反向找到最近的 branch
        3. 如果中间遇到 branch/function/file，直接判定

        own 边方向是 parent own→ child，反向查找即 _target=cur 的 own 边。
        ast 边方向是 parent ast→ child，反向查找即 _target=cur 的 ast 边。
        """
        cur, seen = vid, set()
        for _ in range(30):
            if cur is None or cur in seen:
                return None
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label == NodeLabel.BRANCH.value:
                return cur
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return None
            # 先检查是否是 own target（顶层语句），沿 own 反向
            own_inc = self.graph.es.select(_target=cur, label="own")
            if own_inc:
                cur = own_inc[0].source
            else:
                # 不在 own target 上，沿 ast 反向找父节点
                cur = self._get_ast_parent(cur)
        return None

    _NEGATED_BRANCH_TYPES = frozenset({"else", "default"})

    def _get_enclosing_func_vid(self, vid: int) -> int | None:
        """Return the vid of the nearest ancestor FUNCTION node, or None."""
        cur = vid
        seen: set[int] = set()
        for _ in range(30):
            if cur is None or cur in seen:
                break
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label == NodeLabel.FUNCTION.value:
                return cur
            if label == NodeLabel.FILE.value:
                return None
            # Walk up via OWN edges (incoming, i.e., parent owns child)
            own_in = self.graph.es.select(_target=cur, label="own")
            if own_in:
                cur = own_in[0].source
            else:
                # Parameter nodes are connected via AST edges, not OWN.
                # Try the AST parent as fallback.
                ast_in = self.graph.es.select(_target=cur, label="ast")
                if ast_in:
                    cur = ast_in[0].source
                else:
                    break
        return None

    def get_branch_chain(self, vid: int) -> list[int]:
        """从 vid 向上搜索，返回 vid 到最近的 function/file 之间
        经过的所有 branch 节点（按从内到外排序）。

        注意：else/default 分支不会继承其父 if/switch 的条件约束，
        所以遇到 else/default 时停止向上收集（不包含父 if/switch）。

        例如：vid 在 else 内部，返回 [else_branch_vid]（不含 if_branch）。
        """
        result: list[int] = []
        cur, seen = vid, set()
        stop_at_parent = False
        for _ in range(30):
            if cur is None or cur in seen:
                break
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                break
            if label == NodeLabel.BRANCH.value:
                btype = _vattr(self.graph.vs[cur], "type", "").lower()
                result.append(cur)
                # else/default 不继承父 if/switch 的条件
                if btype in self._NEGATED_BRANCH_TYPES:
                    break
            own_inc = self.graph.es.select(_target=cur, label="own")
            if own_inc:
                # Check if any branch has this node as its condition
                # (ast edge with role='condition'). If so, include that
                # branch in the chain — needed for JS/TS where condition
                # nodes may be owned by function rather than branch.
                found_branch = False
                for ae in self.graph.es.select(_target=cur, label="ast"):
                    if _vattr(ae, "role", "") == "condition":
                        src = self.graph.vs[ae.source]
                        if _vattr(src, "label", "") == NodeLabel.BRANCH.value:
                            btype = _vattr(src, "type", "").lower()
                            result.append(ae.source)
                            if btype in self._NEGATED_BRANCH_TYPES:
                                found_branch = True
                                break
                if found_branch:
                    break
                cur = own_inc[0].source
            else:
                cur = self._get_ast_parent(cur)
        return result

    def is_inside_branch(self, vid: int, branch_type: str | None = None) -> bool:
        """判断 vid 是否在 branch 节点内部。

        可选参数 ``branch_type`` 用于过滤特定类型的 branch，匹配逻辑为
        大小写不敏感地比较 branch 节点 ``attrs.type``（如 "if"/"switch"）
        或 ``attrs.raw_type``（如 "If"/"Switch"）。未指定则只要在任意 branch
        内即返回 True。
        """
        chain = self.get_branch_chain(vid)
        if not branch_type:
            return bool(chain)
        wanted = branch_type.lower()
        for bvid in chain:
            attrs = _vattr(self.graph.vs[bvid], "attrs", {}) or {}
            btype = attrs.get("type") if isinstance(attrs, dict) else None
            rtype = attrs.get("raw_type") if isinstance(attrs, dict) else None
            if (isinstance(btype, str) and btype.lower() == wanted) or \
               (isinstance(rtype, str) and rtype.lower() == wanted):
                return True
        return False

    # -- Branch constraint checking --------------------------------------------

    def _is_in_ternary_iffalse(self, vid: int, ternary_vid: int) -> bool:
        """检查 vid 是否在 ternary branch 的 iffalse 分支下。

        从 ternary 的 iffalse 子节点向下 BFS（沿所有边类型），
        如果能到达 vid 则认为 vid 在 iffalse 分支内。
        """
        # 找到 ternary 的 iffalse 子节点
        iffalse_vids = set()
        for e in self.graph.es.select(
            _source=ternary_vid, label="ast"
        ):
            if _vattr(e, "role", "") == "iffalse":
                iffalse_vids.add(e.target)

        if not iffalse_vids:
            return False

        # BFS 沿所有边（正向）向下
        visited = set(iffalse_vids)
        queue = list(iffalse_vids)
        while queue:
            cur = queue.pop(0)
            if cur == vid:
                return True
            for e in self.graph.es.select(_source=cur):
                if e.target not in visited:
                    visited.add(e.target)
                    queue.append(e.target)
        return False

    def _get_condition_root(self, branch_vid: int) -> int | None:
        """Get the condition expression root node vid from a branch."""
        for e in self.graph.es.select(_source=branch_vid, label="ast"):
            if _vattr(e, "role", "") == "condition":
                return e.target
        return None

    def check_branch_constraint(self, branch_vid: int, var_name: str) -> bool:
        """Check if the branch condition constrains var_name to a safe value.

        Returns True if:
        - $x == "fixed" (variable compared to constant with ==)
        - $x == "a" || $x == "b" (enum via OR of ==)
        - is_numeric($x) / ctype_digit($x) etc. (type validator)
        - switch case with fixed condition value
        - re.match anchored regex, Python str.isdigit etc.
        """
        btype = _vattr(self.graph.vs[branch_vid], "type", "")

        # Wildcard branches: else and default normally don't constrain.
        # EXCEPTION: else of a != branch — the else means == (constraining).
        # e.g. if (strcmp(x, "rm") != 0) { ... } else { BLOCKED }
        # In this case, the else branch inherits the NEGATED condition,
        # and != negated is ==, which IS a safe constraint.
        if btype in self._NEGATED_BRANCH_TYPES:
            if btype == "else":
                # Find parent if branch via own or ast edge
                # (C normalizer uses ast with role=iffalse;
                #  PHP/JS may use own)
                parent_if_vid = None
                for lbl in ("own", "ast"):
                    for e in self.graph.es.select(
                        _target=branch_vid, label=lbl
                    ):
                        p = self.graph.vs[e.source]
                        if _vattr(p, "label") == NodeLabel.BRANCH.value \
                                and _vattr(p, "type") == "if":
                            parent_if_vid = e.source
                            break
                    if parent_if_vid is not None:
                        break
                if parent_if_vid is not None:
                    parent_cond = self._get_condition_root(parent_if_vid)
                    if parent_cond is not None:
                        pname = _vattr(self.graph.vs[parent_cond], "name", "")
                        ptype = _vattr(self.graph.vs[parent_cond], "type", "")
                        # != or !== negated → ==, which is a safe constraint.
                        # _check_condition_node returns False for != directly,
                        # so we extract left/right and check as if it were ==.
                        if pname in ("!=", "!=="):
                            left_vid, right_vid = None, None
                            for e in self.graph.es.select(
                                _source=parent_cond, label="ast"
                            ):
                                role = _vattr(e, "role", "")
                                if role == "left":
                                    left_vid = e.target
                                elif role == "right":
                                    right_vid = e.target
                            if left_vid is not None and right_vid is not None:
                                left_name = _vattr(
                                    self.graph.vs[left_vid], "name", "")
                                right_label = _vattr(
                                    self.graph.vs[right_vid], "label", "")
                                right_name = _vattr(
                                    self.graph.vs[right_vid], "name", "")
                                # var == const (negated !=)
                                if left_name == var_name and right_label in (
                                        NodeLabel.CONST.value,
                                        NodeLabel.IDENTIFIER.value):
                                    return True
                                if right_name == var_name:
                                    left_label = _vattr(
                                        self.graph.vs[left_vid], "label", "")
                                    if left_label in (
                                            NodeLabel.CONST.value,
                                            NodeLabel.IDENTIFIER.value):
                                        return True
                                # strcmp(var, const) == 0 (negated !=)
                                left_type = _vattr(
                                    self.graph.vs[left_vid], "type", "")
                                if (left_type == "call"
                                        and left_name in (
                                            "strcmp", "strncmp", "memcmp",
                                            "strcasecmp", "strncasecmp")):
                                    cmp_args = [
                                        e.target for e in self.graph.es.select(
                                            _source=left_vid, label="ast")
                                        if _vattr(e, "role") == "arg"]
                                    if len(cmp_args) >= 2:
                                        a0 = _vattr(
                                            self.graph.vs[cmp_args[0]], "name", "")
                                        a1l = _vattr(
                                            self.graph.vs[cmp_args[1]], "label", "")
                                        if (a0 == var_name and a1l in (
                                                NodeLabel.CONST.value,
                                                NodeLabel.IDENTIFIER.value)):
                                            return True
            return False
        if btype == "case":
            cond_vid = self._get_condition_root(branch_vid)
            if cond_vid is not None:
                cond_name = _vattr(self.graph.vs[cond_vid], "name", "")
                cond_label = _vattr(self.graph.vs[cond_vid], "label", "")
                # MatchStar / MatchAs without pattern → wildcard
                if cond_label == NodeLabel.CONST.value and cond_name.strip("'\"") == "_":
                    return False

        cond_vid = self._get_condition_root(branch_vid)
        if cond_vid is None:
            return False
        return self._check_condition_node(cond_vid, var_name, depth=0)

    def _check_condition_node(self, cond_vid: int, var_name: str, depth: int = 0) -> bool:
        """Recursively analyze a condition sub-tree node."""
        if depth > 5:
            return False

        label = _vattr(self.graph.vs[cond_vid], "label", "")
        name = _vattr(self.graph.vs[cond_vid], "name", "")
        ntype = _vattr(self.graph.vs[cond_vid], "type", "")

        # BinaryOp: ==, ===, !=, !==, ||, &&, <, >, etc.
        if label == NodeLabel.OPERATOR.value and ntype == OperatorType.BINARY_OP.value:
            # Determine actual operator — normalizers differ:
            # - PHP/JS/Java/Go/Python: name = operator ("==", "||", etc.)
            # - Ruby: name = whole expression ("target == 'ls'"), operator in "text" attr
            actual_op = name
            if name not in ("==", "===", "!=", "!==", "||", "&&", "<", ">", "<=", ">="):
                text_attr = _vattr(self.graph.vs[cond_vid], "text", "")
                for op in _SAFE_CONSTRAINT_OPS | {"||", "&&"}:
                    if op in text_attr or op in name:
                        actual_op = op
                        break

            if actual_op in _SAFE_CONSTRAINT_OPS:
                # == or === : one side must be var_name, other must be constant
                left_vid, right_vid = None, None
                operand_vids = []  # fallback: Ruby uses OPERAND role
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    role = _vattr(e, "role", "")
                    if role == "left":
                        left_vid = e.target
                    elif role == "right":
                        right_vid = e.target
                    elif role == "operand":
                        operand_vids.append(e.target)
                # Fallback: if no left/right, use first two operand children
                if left_vid is None and len(operand_vids) >= 2:
                    left_vid, right_vid = operand_vids[0], operand_vids[1]
                if left_vid is None or right_vid is None:
                    return False
                # Check if either side references var_name
                left_name = _vattr(self.graph.vs[left_vid], "name", "")
                right_name = _vattr(self.graph.vs[right_vid], "name", "")
                right_label = _vattr(self.graph.vs[right_vid], "label", "")
                left_label = _vattr(self.graph.vs[left_vid], "label", "")

                if left_name == var_name and right_label in (NodeLabel.CONST.value, NodeLabel.IDENTIFIER.value):
                    return True  # var == constant
                if right_name == var_name and left_label in (NodeLabel.CONST.value, NodeLabel.IDENTIFIER.value):
                    return True  # constant == var

                # strcmp(var, const) == 0 → var is constrained to const
                # Pattern: left is a call to strcmp/memcmp/etc.,
                # right is a constant 0 (or NULL/false).
                # The first arg of strcmp must be var_name, second must be constant.
                left_label_type = _vattr(self.graph.vs[left_vid], "type", "")
                if left_label in (NodeLabel.OPERATOR.value,) and left_label_type == "call":
                    callee = left_name  # already resolved from name attr
                    if callee in ("strcmp", "strncmp", "memcmp", "strcasecmp",
                                 "strncasecmp"):
                        # Extract strcmp args
                        cmp_args = []
                        for ce in self.graph.es.select(_source=left_vid, label="ast"):
                            if _vattr(ce, "role") == "arg":
                                cmp_args.append(ce.target)
                        if len(cmp_args) >= 2:
                            arg0_name = _vattr(self.graph.vs[cmp_args[0]], "name", "")
                            arg1_label = _vattr(self.graph.vs[cmp_args[1]], "label", "")
                            arg1_name = _vattr(self.graph.vs[cmp_args[1]], "name", "")
                            if (arg0_name == var_name
                                    and arg1_label in (NodeLabel.CONST.value, NodeLabel.IDENTIFIER.value)):
                                return True
                return False

            elif actual_op == "||":
                # OR: both sides must constrain → enum pattern
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if not self._check_condition_node(e.target, var_name, depth + 1):
                        return False
                return True

            elif actual_op == "&&":
                # AND: either side constrains → safe
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if self._check_condition_node(e.target, var_name, depth + 1):
                        return True
                return False

            # !=, !==, <, >, <=, >= don't constrain to safe values
            return False

        # FunctionCall / MethodCall: type validator (is_numeric, isdigit, etc.)
        if label == NodeLabel.OPERATOR.value and ntype in _CALL_TYPES:
            if name in _TYPE_VALIDATION_FUNCS:
                # Check if any arg references var_name
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        arg_name = _vattr(self.graph.vs[e.target], "name", "")
                        if arg_name == var_name:
                            return True
                # Check method receiver via member chain
                # e.g. page.isdigit() → callee 'isdigit' → member → 'page'
                for ae in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(ae, "role", "") == "callee":
                        callee_vid = ae.target
                        for me in self.graph.es.select(_target=callee_vid, label="member"):
                            recv_name = _vattr(self.graph.vs[me.source], "name", "")
                            if recv_name == var_name:
                                return True
                # Check method receiver via DFG edge (Python: user_input.isdigit())
                # Python normalizer routes the receiver through a DFG edge into
                # the method_call node instead of a member edge.
                for de in self.graph.es.select(_target=cond_vid, label="dfg"):
                    recv_name = _vattr(self.graph.vs[de.source], "name", "")
                    if recv_name == var_name:
                        return True

            # JS/TS RegExp method calls: /regex/.test(var) or /regex/.match(var)
            # The JS normalizer stores the full expression as name (e.g. "/regex/.test").
            # The receiver (regex literal) is linked via member edge to the method_call node.
            callee_name = name.split(".")[-1] if "." in name else name
            if callee_name in ("test", "match", "search", "exec"):
                recv_vid = None
                arg_vid = None
                # Receiver is linked via member edge INTO the method_call node
                for me in self.graph.es.select(_target=cond_vid, label="member"):
                    recv_vid = me.source
                    break
                # Arg is the ast child with role='arg'
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        arg_vid = e.target
                        break
                # Fallback: try member or use edge source for receiver
                if recv_vid is None:
                    for me in self.graph.es.select(_source=cond_vid, label="member"):
                        recv_vid = me.target
                        break
                if recv_vid is not None and arg_vid is not None:
                    recv_name = _vattr(self.graph.vs[recv_vid], "name", "")
                    recv_label = _vattr(self.graph.vs[recv_vid], "label", "")
                    arg_name = _vattr(self.graph.vs[arg_vid], "name", "")
                    if (recv_label == NodeLabel.CONST.value
                            and recv_name.startswith("/") and recv_name.endswith("/")
                            and arg_name == var_name):
                        # Check if regex is anchored (starts with ^ and ends with $)
                        inner = recv_name[1:-1]  # strip outer slashes
                        # Handle flags suffix: /[0-9]+/g → pattern = [0-9]+
                        pattern = inner
                        for ch in inner[::-1]:
                            if ch in "gimsuy":
                                pattern = pattern[:-1]
                            else:
                                break
                        if pattern.startswith("^") and pattern.endswith("$"):
                            return True

            # preg_match: anchored regex without dot wildcard → safe
            if name == "preg_match":
                args = []
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        args.append(e.target)
                # args[0] = pattern, args[1] = subject
                if len(args) >= 2:
                    subject_name = _vattr(self.graph.vs[args[1]], "name", "")
                    if subject_name == var_name:
                        # 检查正则模式是否锚定
                        pat_label = _vattr(self.graph.vs[args[0]], "label", "")
                        pat_name = _vattr(self.graph.vs[args[0]], "name", "")
                        if pat_label == NodeLabel.CONST.value and pat_name:
                            # 去掉 repr 的引号，提取 PHP 正则内容
                            raw = pat_name.strip("'\"")
                            # PHP regex: /pattern/flags → 提取 pattern
                            if len(raw) >= 2 and raw[0] == '/' and raw[-1] == '/':
                                pattern = raw[1:-1]
                            else:
                                pattern = raw
                            # ^ 和 $ 锚定 → 严格匹配整个字符串 → 安全
                            if pattern.startswith("^") and pattern.endswith("$"):
                                return True

            # re.match / re.fullmatch: anchored regex → safe
            if name in ("match", "fullmatch", "search"):
                args = []
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        args.append(e.target)
                # args[0] = pattern, args[1] = subject (for re.match/re.fullmatch)
                if len(args) >= 2:
                    subject_name = _vattr(self.graph.vs[args[1]], "name", "")
                    if subject_name == var_name:
                        pat_label = _vattr(self.graph.vs[args[0]], "label", "")
                        pat_name = _vattr(self.graph.vs[args[0]], "name", "")
                        if pat_label == NodeLabel.CONST.value and pat_name:
                            raw = pat_name.strip("'\"")
                            # Python regex: raw string r'...' — already the pattern
                            # ^ and $ anchoring → strict match → safe
                            if raw.startswith("^") and raw.endswith("$"):
                                return True
                            # re.fullmatch always matches the entire string
                            if name == "fullmatch":
                                return True

            return False

        # Identifier in case condition: switch case with fixed value
        # e.g. switch($x) { case "ls": ... } — condition is "ls"
        # The branch is case type, and condition is the matched value
        branch_parent = self._get_ast_parent(cond_vid)
        if branch_parent is not None:
            parent_label = _vattr(self.graph.vs[branch_parent], "label", "")
            parent_type = _vattr(self.graph.vs[branch_parent], "type", "")
            if parent_label == NodeLabel.BRANCH.value and parent_type == "case":
                # case condition is a fixed value — all variables inside
                # this case branch are constrained to that value
                # BUT we need to check if the switch variable is var_name
                # The switch branch owns the case branch, and switch's condition
                # references the variable
                switch_vid = None
                for e in self.graph.es.select(_target=branch_parent, label="own"):
                    switch_vid = e.source
                    break
                if switch_vid is not None:
                    switch_label = _vattr(self.graph.vs[switch_vid], "label", "")
                    switch_type = _vattr(self.graph.vs[switch_vid], "type", "")
                    if switch_label == NodeLabel.BRANCH.value and switch_type in ("switch", "match"):
                        switch_cond = self._get_condition_root(switch_vid)
                        if switch_cond is not None:
                            switch_var = _vattr(self.graph.vs[switch_cond], "name", "")
                            if switch_var == var_name:
                                return True
                            # Subscript: switch(x[i]) constrains x
                            # Extract base variable from subscript operator
                            # C/Java: x[0] → binary_op, left=identifier x, right=index
                            sc_label = _vattr(self.graph.vs[switch_cond], "label", "")
                            sc_type = _vattr(self.graph.vs[switch_cond], "type", "")
                            if (sc_label == NodeLabel.OPERATOR.value
                                    and sc_type == OperatorType.BINARY_OP.value):
                                for se in self.graph.es.select(
                                    _source=switch_cond, label="ast"
                                ):
                                    if _vattr(se, "role") == "left":
                                        base_name = _vattr(
                                            self.graph.vs[se.target], "name", "")
                                        # Strip subscript suffix: "cmd[...]" → "cmd"
                                        if "[" in base_name:
                                            base_name = base_name[:base_name.index("[")]
                                        if base_name == var_name:
                                            return True
                                        break

        return False

    def _find_own_children(self, parent_vid: int,
                           child_label: str | None = None,
                           index: int | None = None) -> list[int]:
        """Vertex IDs of children linked via own or ast edges."""
        children: list[int] = []
        for e in self.graph.es.select(_source=parent_vid):
            elabel = _vattr(e, "label")
            if elabel not in ("own", "ast"):
                continue
            child = self.graph.vs[e.target]
            if child_label and _vattr(child, "label") != child_label:
                continue
            if index is not None and _vattr(e, "index") != index:
                continue
            children.append(e.target)
        return children

    def _resolve_callee_name(self, op_vid: int) -> str | None:
        """Resolve callee name from call operator.

        Strategy:
        1. Look for ast[role=callee] edges → collect callee names.
           For chained method calls (e.g. ``a.b.c()``), the *last*
           callee edge whose target is an ``identifier``/``property``
           is the actual method name (e.g. ``c``).  Intermediate
           operator callee targets (e.g. ``a.b`` as a static_call)
           are skipped so the real method name surfaces.
        2. Fall back to cg/use edge → target function node name.
        3. Fall back to operator node's own ``name`` attribute.
        """
        # Check alias edges: if any ast[callee] child identifier has an
        # outgoing alias edge, use the resolved_name directly.
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                tvid = e.target
                for ae in self.graph.es.select(_source=tvid, label="alias"):
                    resolved_name = _vattr(ae, "resolved_name", "")
                    # Sanity check: resolved_name must look like a valid
                    # function name (no spaces, no SQL keywords, etc.)
                    if resolved_name and " " not in resolved_name:
                        return resolved_name
        callee_names: list[tuple[str, int]] = []  # (name, target_vid)
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                t = self.graph.vs[e.target]
                name = _vattr(t, "name") or _vattr(t, "value")
                if name:
                    callee_names.append((name, t.index))
        # Check alias on function node via use edge — if alias builder
        # already resolved the callee (e.g. func_ptr → system), use it
        # directly instead of tracing DFG through member edges.
        for e in self.graph.es.select(_source=op_vid, label="use"):
            for ae in self.graph.es.select(_source=e.target, label="alias"):
                resolved_name = _vattr(ae, "resolved_name", "")
                if resolved_name and " " not in resolved_name:
                    return resolved_name
        # Prefer the last identifier callee (actual method name in chains)
        for name, tvid in reversed(callee_names):
            if _vattr(self.graph.vs[tvid], "label") == "identifier":
                vtype = _vattr(self.graph.vs[tvid], "type", "")
                # Property-type identifiers (member access like obj.method)
                # are method names, not variables — return directly.
                # Only attempt variable resolution for variable-type callees
                # (e.g., PHP $func = 'system'; $func()).
                if vtype == "property":
                    return name
                resolved = self._resolve_variable_callee(tvid, name)
                if resolved:
                    return resolved
                return name
        # No identifier callee found — return the last callee name overall
        if callee_names:
            return callee_names[-1][0]
        # Fallback: use edge target — check alias first, then variable callee
        for e in self.graph.es.select(_source=op_vid, label="use"):
            # Check alias edges on the function target
            for ae in self.graph.es.select(_source=e.target, label="alias"):
                resolved_name = _vattr(ae, "resolved_name", "")
                if resolved_name and " " not in resolved_name:
                    return resolved_name
            name = _vattr(self.graph.vs[e.target], "name")
            resolved = self._resolve_variable_callee(e.target, name)
            if resolved:
                return resolved
            return name
        # Last resort: operator's own name
        name = _vattr(self.graph.vs[op_vid], "name")
        if name:
            # Only trace DFG for variable-like callees (e.g. $func in PHP)
            # Skip language constructs (isset, echo, array_key_exists, etc.)
            # whose DFG upstream contains arg nodes, not callee definitions.
            if name.startswith('$') or not name[0].isalpha():
                resolved = self._resolve_variable_callee(op_vid, name)
                if resolved:
                    return resolved
        # Fallback: 检查节点自身的 callee 属性（PHP normalizer 同时写 name 和 callee）
        callee_attr = _vattr(self.graph.vs[op_vid], "callee", "")
        if callee_attr and isinstance(callee_attr, str):
            return callee_attr
        return name

    def _resolve_variable_callee(self, start_vid: int, var_name: str, max_depth: int = 5) -> str | None:
        """Resolve variable callee name through DFG backward tracking.

        For indirect function calls like ``$func($cmd)`` or JS ``f(userInput)``
        where ``f = eval``, traces DFG edges backward to find the assigned
        literal value.

        Supports multi-level indirection::

            $func2 = $func;  $func = 'system';  $func2($cmd)
            const f = eval; f(x)

        Args:
            start_vid: The callee identifier vertex index.
            var_name: Variable/function name.
            max_depth: Max hops to follow (default 5).

        Returns:
            Resolved literal callee name, or None.
        """
        if not var_name:
            return None

        visited: set[int] = set()
        current_vid = start_vid

        for _ in range(max_depth):
            if current_vid in visited:
                break
            visited.add(current_vid)

            # Follow DFG edges backward from this identifier
            resolved = False
            for src_vid in self._get_dfg_sources(current_vid):
                sv = self.graph.vs[src_vid]
                slabel = _vattr(sv, "label", "")
                sname = _vattr(sv, "name", "")

                if slabel == NodeLabel.CONST.value and sname:
                    # Strip quotes from string literals
                    return sname.strip("'\"")

                if slabel == NodeLabel.FUNCTION.value and sname:
                    # Direct function reference: f = eval (function node)
                    return sname

                if slabel == NodeLabel.IDENTIFIER.value and sname:
                    # Check if this identifier has further DFG upstream
                    if list(self._get_dfg_sources(src_vid)):
                        # Multi-level: follow the chain
                        current_vid = src_vid
                        resolved = True
                        break
                    else:
                        # Leaf identifier (no DFG upstream) —
                        # treat as function name reference (e.g. const f = eval)
                        return sname

            if not resolved:
                break

        return None

    def _find_identifier_by_name(self, name: str,
                                  context_vid: int | None = None) -> int | None:
        """Find identifier vertex by name, preferring same-file matches.

        When *context_vid* is None (no scope restriction), candidates without
        a real *file_path* (library stubs, decompiled helpers) are excluded to
        avoid cross-project false positives.

        Replaced O(V) full scan with O(1) dict lookup using prebuilt indexes
        (_nfile, _nname).
        """
        scope = None
        if context_vid is not None:
            scope = _vattr(self.graph.vs[context_vid], "file_path", None)
        if scope:
            key = (NodeLabel.IDENTIFIER.value, name, scope)
            vids = self._nfile.get(key, [])
            if vids:
                # Prefer candidates in the same function scope as context_vid
                if context_vid is not None:
                    ctx_func = self._get_enclosing_func_vid(context_vid)
                    if ctx_func is not None:
                        scoped = [v for v in vids
                                  if self._get_enclosing_func_vid(v) == ctx_func]
                        if scoped:
                            return scoped[0]
                return vids[0]
        return None

    def _find_enclosing_branches(self, vid: int) -> list[int]:
        """Find all branch ancestor nodes via own edges."""
        result: list[int] = []
        cur, seen = vid, set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            if _vattr(self.graph.vs[cur], "label") == NodeLabel.BRANCH.value:
                result.append(cur)
            inc = self.graph.es.select(_target=cur, label="own")
            cur = inc[0].source if inc else None
        return result

    @staticmethod
    def _has_strict_regex(condition: str) -> bool:
        """Check if condition contains a strict anchored regex (no wildcard .)."""
        m = re.search(r"""['"](/[^'"]*?)['"]""", condition)
        if not m:
            return False
        pat = m.group(1)
        if len(pat) < 4 or not pat.startswith("^") or not pat.endswith("$"):
            return False
        return "." not in pat[1:-1].replace("\\.", "")

    def reset(self) -> None:
        """Clear decision cache and call stack."""
        self._decision_cache.clear()
        self._call_stack.clear()
        logger.debug("GraphAnalyzer state reset")
