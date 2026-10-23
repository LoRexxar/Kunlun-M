"""Graph-based vulnerability backtracking analyzer.

Operates on an already-built igraph AST graph (with ast/own/use/cg/dfg edges)
to perform taint analysis.  Graph-native replacement for the legacy
``_parameters_back_impl`` and ``function_back`` in php/parser.py.
"""

from __future__ import annotations

import logging
import os
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
logger = logging.getLogger("KunlunLog")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPERGLOBALS: frozenset[str] = frozenset({
    # PHP superglobals ($_SESSION excluded — server-side session data, not direct user input)
    # ($argc/$argv excluded — CLI-only sources, not web-controllable)
    # ($_SERVER removed — mixed controllability, handled per-key by _SERVER_UNCONTROLLED_KEYS)
    # ($_ENV excluded — OS-level environment variables, not HTTP-client controllable)
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
    "$_HTTP_RAW_POST_DATA",
    # Python web framework sources (object names)
    "request.GET", "request.POST", "request.REQUEST", "request.COOKIES",
    "request.FILES", "request.data", "request.body", "request.query_params",
    "request.query_string", "request.form",
    # Flask/WSGI
    "flask.request", "django.http.HttpRequest",
})

# Java known request variable name prefixes — gates suffix fallback in
# _is_source_variable so tree.getParameter doesn't match getParameter.
_JAVA_REQUEST_PREFIXES: frozenset[str] = frozenset({
    "request", "req", "httpRequest", "httpServletRequest",
    "servletRequest", "httpReq",
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

# \$_FILES keys that are NOT user-controlled (server-generated metadata).
# 'name' is the client-side original filename, not a server-side path;
# it should not be treated as a source for path traversal / RFI rules.
# Keys not in this set ('type') are treated as user-controlled sources.
_FILES_NON_SOURCE_MEMBERS: frozenset[str] = frozenset({
    "tmp_name", "size", "error", "full_path", "name",
})

# \$_FILES member keys that ARE user-controlled (MIME type only).
# \$_FILES without these keys in the member chain is NOT a valid source.
_FILES_SOURCE_MEMBERS: frozenset[str] = frozenset({
    "type",
})

# JS/TS source roots — kept EMPTY intentionally.
# Bare identifiers like "location", "document", "window" are NOT valid
# taint sources.  They cause FP when user code uses them as variable/param
# names.  All legitimate JS/TS sources (location.hash, document.cookie,
# window.name, process.env, etc.) are registered in SourceRegistry and
# matched via the dotted-path check below.
_JS_SOURCE_ROOTS: frozenset[str] = frozenset()

_REPAIR_FUNCTIONS: frozenset[str] = frozenset({
    # PHP — well-known sanitizer/encoding functions
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
    # CMS Made Simple — framework sanitizer (full HTML entity encode)
    "cleanValue",
    # Python
    "shlex.quote", "shlex.quote_plus",
    "html.escape", "html.unescape",
    "re.escape", "urllib.parse.quote", "urllib.parse.quote_plus",
    "cgi.escape", "markupsafe.escape",
    "os.path.basename", "os.path.realpath",
    "int", "float", "str",
    "json.dumps", "json.loads",
    "pickle.dumps", "pickle.loads",
    "reverse",  # Django URL reverse — returns fixed internal path
    "url_for",  # Flask URL builder — returns fixed internal path
    # NOTE: "path" and "save" removed — too generic, caused TP suppression
    # Java — canonical path normalization (path traversal guard)
    # Also used in branch conditions: if (!x.getCanonicalPath().equals(...))
    "getCanonicalPath",
    "java.io.File.getCanonicalPath",
    # Java
    "StringEscapeUtils.escapeSql",
    "org.apache.commons.lang3.StringEscapeUtils.escapeSql",
    "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4",
    "org.apache.commons.lang3.StringEscapeUtils.escapeHtml3",
    "org.apache.commons.lang3.StringEscapeUtils.escapeXml11",
    "org.apache.commons.text.StringEscapeUtils.escapeHtml4",
    "org.apache.owasp.esapi.ESAPI.encoder.encodeForHTML",
    "org.apache.owasp.esapi.ESAPI.encoder.encodeForHTMLAttribute",
    "org.apache.owasp.esapi.ESAPI.encoder.encodeForJavaScript",
    "org.apache.owasp.esapi.ESAPI.encoder.encodeForURL",
    "org.apache.owasp.esapi.ESAPI.encoder.encodeForSQL",
    "org.apache.tomcat.util.security.Escape.htmlElementContent",
    "Escape.htmlElementContent",
    "org.apache.tomcat.util.security.Escape.xml",
    "Escape.xml",
    # Parameterized query APIs (taint bound as parameters, not concatenated)
    "NamedParameterJdbcTemplate.query",
    "NamedParameterJdbcTemplate.queryForObject",
    "NamedParameterJdbcTemplate.queryForList",
    "NamedParameterJdbcTemplate.update",
    "SqlParameterSource.addValue",
    # NOTE: OFBiz delegator/query functions removed — they can return
    # user-influenced data. resolveLocation/getURL/getLocation removed
    # for the same reason.
    # OFBiz path normalization
    "FileUtil.createFileWithNormalizedPath",
    "createFileWithNormalizedPath",
    "SecuredUpload.isValidFile",
    "isValidFile",
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
    # Rails ActionView helpers — auto HTML-escape content
    "content_tag", "tag", "safe_join", "safe_concat",
    "sanitize", "strip_links", "strip_tags",
    "truncate", "excerpt", "word_wrap", "simple_format",
    # Django open-redirect guard
    "url_has_allowed_host_and_scheme", "is_safe_url",
    # NOTE: expandString, getProperty, getPropertyValue, getSignature,
    # getStaticPart, get_success_url, get_absolute_url, get_redirect_url
    # are now in builtin_knowledge (safe=True) and resolved automatically
    # by _is_repair_function via that knowledge base.
    # Framework-specific sanitizer aliases
    "getParser.filter",  # e107 e107::getParser()->filter() -- official
    "$tp.filter",  # e107 $tp->filter() input filter (file/text types)
    "hsc",  # DokuWiki htmlspecialchars alias
    "htmlchars",  # osTicket Format::htmlchars — array-recursive htmlspecialchars
    "Format.htmlchars",  # qualified static call (dotted fullname on the wire)
    "Format.input",  # osTicket Format::input — alias of Format::htmlchars
    #    (NEVER add bare "input": it would match Laravel $request->input etc.)
    "esc_html", "esc_attr", "esc_js", "esc_url", "esc_textarea",  # WordPress
    "sanitize_file_name", "sanitize_title", "sanitize_text_field",  # WordPress
    "sanitize_url",  # WordPress (alias of esc_url since WP 5.3)
    "wp_kses", "wp_filter_post_kses", "wp_kses_post",  # WordPress
    # Java type conversions — numeric/hash output cannot carry payload
    "Long.parseLong", "Integer.parseInt", "Double.parseDouble",
    "UUID.nameUUIDFromBytes",
    "getWebSocketAccept",  # Tomcat SHA1+Base64 hash transformation
    "canonicalize",  # Path canonicalization — prevents directory traversal
    # Python URL/path safety validators
    "get_next_path", "is_safe_url", "is_safe_redirect",
})

# Format-string sanitizers: sanitized ONLY when the format constant (arg0)
# contains no string-passthrough conversion (%s/%f/%e/%g/%u).  Checked
# per-call by _format_string_arg0 — never add these to _REPAIR_FUNCTIONS,
# because sprintf('%s', $x) passes taint straight through.
_FORMAT_STRING_SANITIZERS: frozenset[str] = frozenset({
    "sprintf", "printf", "vsprintf", "fprintf",
})

# Fix 14: PHP type cast operators that sanitize taint.
# (int), (float), (bool), (array) casts destroy string content,
# making XSS/SQLi/injection impossible through the cast result.
_TYPE_CAST_SAFE: frozenset[str] = frozenset({
    "int", "integer", "float", "double", "real",
    "bool", "boolean", "array", "object",
})

# Fix 21b-2: PHP functions whose result elements pass through a caller-
# supplied CALLBACK (arg0).  If the callback is provably safe, the whole
# result is sanitized (code=2) regardless of the passthrough annotation.
_ARRAY_CALLBACK_FUNCS: frozenset[str] = frozenset({
    "array_map", "array_filter", "array_walk", "array_walk_recursive",
    "usort", "uasort", "uksort",
})

_SINK_FUNCTIONS: frozenset[str] = frozenset({
    "system", "exec", "passthru", "shell_exec", "popen", "proc_open", "pcntl_exec", "expect_popen",
    "eval", "create_function",
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
    # *http.Request removed: only specific methods (r.URL.Query.Get, r.FormValue, etc.) are sources
    # The type itself is not a source - framework internal handling
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
    "preg_match",  # PHP regex validation (whitelist/guard pattern)
    "check_input_parameter",  # PHP custom parameter validation (Piwigo, etc.)
    # Project-level whitelist validators (common helper names).  These take
    # the value and return true only for a restricted charset, so a value
    # that passes them cannot carry injection payloads:
    #   is_version        — numeric + decimal (pts_strings, Phoronix)
    #   is_alnum/is_alpha — alphanumeric / alphabetic wrappers
    "is_version", "is_alnum", "is_alpha", "is_alphanumeric",
    # Python
    "isinstance", "issubclass", "hasattr", "callable",
    "isdigit", "isalpha", "isalnum", "isdecimal", "isnumeric",
    "isupper", "islower", "istitle", "isspace",
    "isascii", "isidentifier", "isprintable",
    "isfinite", "isinf", "isnan",
    # Django open-redirect / URL validation guards
    "url_has_allowed_host_and_scheme", "is_safe_url",
    "validate_unicode_slug", "iri_to_uri",
    # Java — canonical path validation (path traversal guard)
    "getCanonicalPath",
})

# Fix 20b regression guard: existence/emptiness checks.  Their
# builtin_knowledge entries carry safe=True (the *return value* is safe),
# but they prove nothing about the *argument's* content, so they must never
# satisfy the Fix 20a safe-predicate branch guard.
_EXISTENCE_CHECK_FUNCS: frozenset[str] = frozenset({
    # PHP
    "isset", "empty", "is_null", "array_key_exists", "property_exists",
    "in_array",  # membership only — content unchanged
    # Python
    "hasattr",
    # Java
    "containsKey", "containsValue", "contains",
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
                 source_registry=None, framework_method_sinks: set[str] | None = None) -> None:
        self.graph = graph
        self.language = language
        self._decision_cache: dict[int, AnalysisResult] = {}
        self._builtin_knowledge_cache: dict | None = None
        self._call_stack: list[str] = []
        self._source_registry = source_registry
        # Framework method sinks: short method names from tamper EXTRA_SINKS
        # that are safe to match without qualified-name resolution because they
        # come from framework tamper configuration (e.g. Laravel DB::raw →
        # method 'raw' on Eloquent Builder, WordPress $wpdb->query → 'query').
        # These are receiver-type-agnostic: any ->raw() / ->query() call is a
        # potential sink regardless of the object's resolved type.
        self._framework_method_sinks: set[str] = framework_method_sinks or set()

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

        # _nfile 索引延迟构建：只在 _find_identifier_by_name 首次调用时构建
        self._nfile: dict[tuple[str, str, str], list[int]] | None = None

        # 文件级索引：(label, file) → [(lineno, vid), ...] sorted by lineno
        # 用于 _has_function_level_guard 等函数的快速局部查找
        self._nfile_lineno: dict[tuple[str, str], list[tuple[int, int]]] = {}
        for v in graph.vs:
            vl = _vattr(v, 'label', '') or ''
            vf = _vattr(v, 'file_path', '') or _vattr(v, 'path', '')
            vln = int(_vattr(v, 'lineno', 0) or 0)
            if vl and vf:
                self._nfile_lineno.setdefault((vl, vf), []).append((vln, v.index))
        for key in self._nfile_lineno:
            self._nfile_lineno[key].sort()

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
        try:
            for e in self.graph.es.select(label="ast"):
                if _vattr(e, "role") == "callee":
                    callee_targets.add(e.target)
        except KeyError:
            pass  # graph has no edges or no 'label' attribute
        # Identify callee_targets with their own args
        for ct_vid in callee_targets:
            try:
                has_arg = any(
                    _vattr(e, "role") == "arg"
                    for e in self._edge_out(ct_vid, "ast")
                )
            except KeyError:
                has_arg = False
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
                            for e in self._edge_out(v.index, "ast"))):
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
            _is_qualified_match = False

            # Sink matching strategy (by call type):
            #
            # call (global function): callee_name IS the fullname.
            #   → direct match against sink_set is safe.
            #
            # method_call / static_call: callee_name is a short method name
            #   (e.g. "apply", "system").  Short names are ambiguous — many
            #   unrelated classes have methods with the same name.  These
            #   MUST be resolved via the use-edge to the function definition
            #   node, whose fullname encodes the receiver type (e.g.
            #   "BiFunction.apply", "Runtime.exec").  Only the fullname is
            #   matched against the sink_set.
            #
            #   Exception: if the callee_name already contains "." or "::",
            #   it is a qualified name from the source text (e.g.
            #   "document.write") and can be matched directly.
            call_type = _vattr(v, "type", "")
            _is_bare_call = call_type in (OperatorType.CALL.value, OperatorType.NEW.value)
            # Build a list of candidate names to try for direct match.
            # op_name may carry the qualified expression (e.g. "document.write")
            # even when _resolve_callee_name only returns "write".
            _candidates = []
            if op_name and op_name != normalized_callee:
                _candidates.append(op_name.replace("::", "."))
            _candidates.append(normalized_callee)

            if _is_bare_call:
                # Global function / constructor: callee_name IS the fullname.
                # Direct match any candidate (short or qualified).
                for _cand in _candidates:
                    if _cand in normalized_set:
                        matched_name = _cand
                        callee_name = _cand
                        _is_qualified_match = "." in _cand or "::" in _cand
                        break
                    if _cand.lower() in normalized_lower:
                        matched_name = _cand
                        callee_name = _cand
                        _is_qualified_match = "." in _cand or "::" in _cand
                        break
            else:
                # method_call / static_call: only match QUALIFIED candidates.
                # Bare short names (e.g. "apply") must go through Path B
                # (use-edge fullname) to resolve the receiver type.
                for _cand in _candidates:
                    if "." not in _cand and "::" not in _cand:
                        continue
                    if _cand in normalized_set:
                        matched_name = _cand
                        callee_name = _cand
                        _is_qualified_match = True
                        break
                    if _cand.lower() in normalized_lower:
                        matched_name = _cand
                        callee_name = _cand
                        _is_qualified_match = True
                        break

            if not matched_name:
                # Path B: qualified fullname match via use-edge function node.
                # This is the ONLY path for bare method_call/static_call.
                for ue in self._edge_out(v.index, "use"):
                    tgt = self.graph.vs[ue.target]
                    if _vattr(tgt, "label") != NodeLabel.FUNCTION.value:
                        continue
                    tgt_fullname = _vattr(tgt, "fullname", "")
                    if not tgt_fullname:
                        continue
                    norm_fn = tgt_fullname.replace("::", ".")
                    # Fix 14: A bare fullname (no "." or "::") provides no
                    # receiver-type resolution for method_call/static_call.
                    # Without a qualifier, the match is indistinguishable from a
                    # global function call — e.g. $db->exec() resolving to a
                    # builtin stub named "exec" instead of the real method.
                    # Skip to prevent PHP method calls on objects (PDO::exec,
                    # Redis::exec, etc.) from matching bare "exec" sinks.
                    if "." not in norm_fn and "::" not in norm_fn and not _is_bare_call:
                        continue
                    if norm_fn == normalized_callee and not _is_bare_call:
                        # fullname same as short name, no additional info
                        continue
                    if norm_fn in normalized_set:
                        matched_name = norm_fn
                        callee_name = tgt_fullname
                        _is_qualified_match = True
                        break
                    if norm_fn.lower() in normalized_lower:
                        matched_name = norm_fn
                        callee_name = tgt_fullname
                        _is_qualified_match = True
                        break

            # Path C: framework method sink — short name whitelist.
            # Framework tamper EXTRA_SINKS define method-call sinks like
            # ->query(), ->raw(), ->render() that are receiver-type-agnostic.
            # These cannot be resolved via use-edge (no user-defined function
            # node), so they need an explicit short-name match path.
            if not matched_name and self._framework_method_sinks:
                # Short-name match: compare the BARE method name (last
                # dotted segment).  _resolve_callee_name returns the
                # receiver-qualified form ("_session.fetch_token"), and a
                # strict whole-string compare made every qualified call
                # miss the whitelist.  The whitelist's contract is
                # receiver-agnostic ("any .fetch_token(...) call").
                _short_lower = normalized_callee.lower().rsplit(".", 1)[-1]
                if _short_lower in self._framework_method_sinks:
                    matched_name = normalized_callee
                    _is_qualified_match = False

            # Path D: dynamic dispatch — `$obj->{$expr}(...)` (PHP) or
            # computed member calls.  The callee name is an EXPRESSION
            # string (e.g. "ArrayOffset(Variable('$src_item'), 'prop')"),
            # never a plain identifier, so every name-based path above
            # misses.  CVE-2026-110895: `$mainobj->{$src_item['prop']}(...)`
            # dispatches to like/order_by with attacker-chosen names.
            # Semantics: the possible targets include every method the
            # project defines; expand the call into one virtual sink per
            # FRAMEWORK-WHITELISTED method that actually exists in the
            # graph.  Downstream taint analysis (pb on arg_vids) filters
            # harmless cases, exactly like Path C.
            _is_dyn_expr_name = bool(callee_name) and (
                "(" in callee_name or ")" in callee_name or " " in callee_name.strip())
            if (not matched_name and _is_dyn_expr_name
                    and self._framework_method_sinks
                    and _vattr(v, "type", "") == OperatorType.METHOD_CALL.value):
                # Fix 42t: narrow the expansion to the RECEIVER's class
                # closure (its class + base-class chain via 'crg' edges).
                # `$h->{$t}($t)` where $h = new DataHolder can only reach
                # DataHolder(+'bases) methods — expanding all 13
                # whitelist names produces FPs (synthetic f42t site 1).
                # Escape hatch: when the closure defines __call/__callStatic
                # (PHP magic forwarding, sgx ApbdWpsModel::__call), any
                # name is reachable — keep the full expansion.
                _wl_names = self._framework_method_sinks
                _recv_classes = self._dyn_call_receiver_classes(v.index)
                if _recv_classes is not None:
                    _closure: set[str] = set()
                    _has_magic = False
                    # Union every same-named class node: the crg edge may
                    # land on a per-file STUB (phply emits one empty
                    # class node per `extends X` reference, L=0, no own
                    # children) while the real definition with __call/
                    # methods lives on another node of the same name.
                    _names: set[str] = set()
                    for _cvid in _recv_classes:
                        _cn = str(_vattr(self.graph.vs[_cvid], "name", "")
                                  or _vattr(self.graph.vs[_cvid], "fullname", "")
                                  or "").strip("'\"").lower()
                        if _cn:
                            _names.add(_cn)
                    _name_to_vids: dict[str, list[int]] = {}
                    for cv2 in self._nlbl.get(NodeLabel.CLASS.value, []):
                        _cn2 = str(_vattr(self.graph.vs[cv2], "name", "")
                                   or _vattr(self.graph.vs[cv2], "fullname", "")
                                   or "").strip("'\"").lower()
                        if _cn2 in _names:
                            _name_to_vids.setdefault(_cn2, []).append(cv2)
                    for _cvid in _recv_classes:
                        _cn = str(_vattr(self.graph.vs[_cvid], "name", "")
                                  or _vattr(self.graph.vs[_cvid], "fullname", "")
                                  or "").strip("'\"").lower()
                        _vids = _name_to_vids.get(_cn, [_cvid])
                        for _vid2 in _vids:
                            for e in self._edge_out(_vid2, "own"):
                                tv = self.graph.vs[e.target]
                                if _vattr(tv, "label", "") != NodeLabel.FUNCTION.value:
                                    continue
                                _fn = _vattr(tv, "fullname", "") or ""
                                _short = _fn.replace("::", ".").rsplit(".", 1)[-1].lower()
                                _closure.add(_short)
                                if _short in ("__call", "__callstatic"):
                                    _has_magic = True
                    if not _has_magic:
                        _wl_names = {
                            m for m in self._framework_method_sinks
                            if m in _closure}
                _fn_short: set[str] = set()
                try:
                    for fvid in self._nlbl.get(NodeLabel.FUNCTION.value, []):
                        _fn = _vattr(self.graph.vs[fvid], "fullname", "")
                        if _fn:
                            _fn_short.add(_fn.replace("::", ".").rsplit(".", 1)[-1].lower())
                except Exception:
                    _fn_short = set()
                _dyn_targets = sorted(
                    m for m in _wl_names if m in _fn_short)
                if _dyn_targets:
                    # Collect shared sink fields once
                    _base = {
                        "lineno": _vattr(v, "lineno", 0),
                        "file_path": _vattr(v, "file_path", "") or _vattr(v, "path", ""),
                        "type": _vattr(v, "type", ""),
                    }
                    _arg_vids = [
                        e.target for e in self._edge_out(v.index, "ast")
                        if _vattr(e, "role") == "arg"
                    ]
                    if not _arg_vids:
                        for de in self._edge_in(v.index, "dfg"):
                            if _vattr(self.graph.vs[de.source], "label", "") == NodeLabel.OPERATOR.value:
                                continue
                            _arg_vids.append(de.source)
                    for _m in _dyn_targets:
                        results.append({
                            "vid": v.index, "name": _m,
                            "dynamic_dispatch": True,
                            "arg_vids": list(_arg_vids),
                            **_base,
                        })
                # Path D fully handles this node — skip default emission below
                matched_name = None
                if _dyn_targets:
                    continue

            if not matched_name:
                continue

            # Skip sinks inside dead-code branches (e.g. if (false) { ... })
            if self._is_in_dead_code(v.index):
                continue

            # Collect argument vids via ast[role=arg] edges
            arg_vids = [
                e.target for e in self._edge_out(v.index, "ast")
                if _vattr(e, "role") == "arg"
            ]
            # Only collect DFG sources if there are NO AST arg children.
            # When AST args exist (e.g., echo show($input)), DFG sources
            # may bypass safe function calls (show() → htmlspecialchars),
            # creating false positive taint chains. BFS from AST args will
            # correctly encounter the safe call node.
            if not arg_vids:
                for de in self._edge_in(v.index, "dfg"):
                    src = de.source
                    if src in arg_vids:
                        continue
                    src_label = _vattr(self.graph.vs[src], "label", "")
                    # Skip operator nodes: nested calls in the method chain
                    if src_label == NodeLabel.OPERATOR.value:
                        continue
                    # Skip identifier nodes matching the receiver name
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
                e.target for e in self._edge_out(v.index, "ast")
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
                e.target for e in self._edge_out(v.index, "ast")
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
                if lhs_label == "property":
                    # JS DOM property assignment (e.g. el.innerHTML = expr)
                    # Only property LHS qualifies — plain identifier LHS
                    # (e.g. Python `redirect = get_redirect(...)`) must NOT
                    # match, even if the variable name equals a sink name.
                    if lhs_vname in name_set:
                        lhs_name = lhs_vname
                        lhs_identifier_vid = lhs_vid
                        break
                elif lhs_label == "operator":
                    # LHS 是 operator（如 document.getElementById().innerHTML）
                    # 检查其 ast 子节点中是否有 identifier/property 匹配 sink
                    for ce in self._edge_out(lhs_vid, "ast"):
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
                e.target for e in self._edge_out(v.index, "ast")
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
                            for fe in self._edge_out(func_vid, "own"):
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
                        for e in self._edge_in(vid, "own")
                    )
                    if not has_func_scope:
                        continue
                    ret_arg_vids = [
                        e.target for e in self._edge_out(v.index, "ast")
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
        # @ResponseBody 默认通过 Jackson 序列化为 JSON（application/json），
        # 浏览器不会将 JSON 解析为 HTML，XSS 不成立。
        # 只有当方法显式声明 text/html Content-Type 时才 unsafe。
        is_json_ct = True
        for fe in self._edge_out(func_vid, "own"):
            child_name = _vattr(self.graph.vs[fe.target], 'name', '')
            for html_pat in ('TEXT_HTML_VALUE', 'text/html', '"text/html"'):
                if html_pat in child_name:
                    is_json_ct = False
                    break
            if not is_json_ct:
                break

        for fe in self._edge_out(func_vid, "own"):
            if _vattr(fe, 'scope') != 'function-return':
                continue
            ret_vid = fe.target
            ret_label = _vattr(self.graph.vs[ret_vid], 'label', '')
            if ret_label != NodeLabel.RETURN.value:
                continue
            ret_arg_vids = [
                e.target for e in self._edge_out(ret_vid, "ast")
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

    def _arg_sanitized_inside_callee(self, arg_vid: int) -> bool:
        """Fix 26: the argument's owning call invokes a user-defined function
        whose body re-assigns a same-named variable with a repair function
        (e.g. html::category($catid,$page) doing $page = intval($page)).
        In that case the callee never uses the raw argument value, so the
        call-site argument is sanitized regardless of where it came from.
        Graph shape (probe /tmp/t_pc_probe): call --use--> function;
        function --own--> assign(name=arg name) --ast--> [lhs var, rhs call
        to an _is_repair_function callee]."""
        sv = self.graph.vs[arg_vid]
        a_name = _vattr(sv, "name", "")
        if not a_name:
            return False
        # owning call: ast parent that is a call node
        call_vid = None
        for pe in self._edge_in(arg_vid, "ast"):
            pv = self.graph.vs[pe.source]
            if _vattr(pv, "type", "") in ("call", "method_call", "static_call"):
                call_vid = pe.source
                break
        if call_vid is None:
            return False
        a_file = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        # callee function definition via use edge
        fn_vids = [e.target for e in self.graph.es.select(
            _source=call_vid, label="use")
            if _vattr(self.graph.vs[e.target], "label") == "function"]
        # PHP normalizer often binds $obj->method() use edges to a
        # same-NAMED function in the caller's own file (phpcms probe:
        # $this->html->category(...) → create_html.php::category, while the
        # sanitizing definition lives in html.class.php).  Widen to all
        # same-name function nodes, mirroring the Rule 3a2 same-name lookup.
        if fn_vids:
            fname = _vattr(self.graph.vs[fn_vids[0]], "name", "")
            if fname:
                seen = set(fn_vids)
                for sv2 in self.graph.vs.select(name=fname, label="function"):
                    if sv2.index not in seen:
                        seen.add(sv2.index)
                        fn_vids.append(sv2.index)
        for fvid in fn_vids:
            # walk the callee's own subtree for a sanitizing re-assign
            own_ids = [e.target for e in self.graph.es.select(
                _source=fvid, label="own")]
            for oid in own_ids:
                ov = self.graph.vs[oid]
                if _vattr(ov, "type", "") != "assign":
                    continue
                if (_vattr(ov, "name", "") or "") != a_name:
                    continue
                kids = [e.target for e in self.graph.es.select(
                    _source=oid, label="ast")]
                for k in kids:
                    kv = self.graph.vs[k]
                    if _vattr(kv, "type", "") in ("call", "method_call"):
                        callee = self._resolve_callee_name(k) or ""
                        base = callee.rsplit(".", 1)[-1]
                        if base and self._is_repair_function(base):
                            return True
        return False

    def parameters_back(self, start_vid: int, context_vid: int | None = None,
                        max_depth: int = 50) -> AnalysisResult:
        """Public entry — runs the BFS impl, then applies Fix 20b two-pass
        redirect resolution."""
        # Fix 26: argument sanitized inside the callee (param re-assigned
        # Fix 26: argument sanitized inside the callee (param re-assigned
        # with a repair function in the function body) — no need to trace.
        try:
            if self._arg_sanitized_inside_callee(start_vid):
                return self._cached(
                    "pb_sanitized_callee:%s" % start_vid,
                    AnalysisResult(
                        code=2,
                        reason="argument sanitized inside callee (repair re-assign)",
                        chain=[{"step": "callee_sanitize", "vid": start_vid,
                                "name": _vattr(self.graph.vs[start_vid], "name", ""),
                                "code": 2}],
                        path=[start_vid],
                        expr_lineno=_vattr(self.graph.vs[start_vid], "lineno", 0)))
        except Exception:
            pass
        self._redirect_pin_ctx = bool(self._start_is_redirect_sink(start_vid))
        self._redirect_pin_vids = set()
        self._redirect_pin_blocked = set()

        # Fix 21a: negated safe-predicate predecessor guard (CouchCMS
        # whitelist form). Checked once up-front at the sink: an if-branch
        # BEFORE the sink in the same function whose negated predicate
        # (!in_array($v, <const whitelist>) or !safe_pred($v)) terminates
        # means reaching the sink proves the predicate TRUE — the argument
        # variable is whitelist-constrained, not attacker-controlled.
        # Probed against the path-variables of the sink expression itself;
        # BFS path-variable names are discovered per-node below via the
        # cheap identifier probe instead (avoids name mismatch param vs
        # caller var).
        _sv = self.graph.vs[start_vid]
        if (int(_vattr(_sv, "lineno", 0) or 0) > 0
                and not getattr(self, "_f21a_guard_cache", None)):
            self._f21a_guard_cache = {}
        _f21a_guard_cache = getattr(self, "_f21a_guard_cache", None)

        # Fix 23: fixed-host URL guard for curl_setopt(CURLOPT_URL, ...).
        # When the URL argument traces back to a concat whose leftmost leaf
        # is a string literal containing a complete scheme://host prefix,
        # attacker-controlled taint can only reach the query component —
        # the request destination host is pinned by the literal, so this is
        # not server-side request forgery.  (xoops protector stopforumspam
        # client: "http://www.stopforumspam.com/api?" . $query.)
        # A literal of just "http://" does NOT qualify — the host chars must
        # appear inside the same literal, otherwise the host itself is the
        # tainted part (true SSRF stays reported).
        _f23 = self._fixed_host_url_guard(start_vid)
        self._f23_guard_cache = _f23

        r1 = self._parameters_back_impl(start_vid, context_vid=context_vid,
                                        max_depth=max_depth)
        # Fix 28: urlencoded output guard (XSS echo context).  When the
        # tainted variable's defining assign wraps EVERY tainted operand
        # in urlencode()/rawurlencode() (output charset: alnum -_.~% —
        # no quotes, angle brackets, spaces), the echoed value cannot
        # escape an HTML attribute or inject markup (browsers do not
        # URL-decode before protocol parsing, so `%6A%61va...` stays
        # inert).  osticket dynamic-form.inc.php:7
        # `?id=" . urlencode($_REQUEST['id'])` echoed into action=.
        if self.language == "php" and r1.code == 1:
            _ue_reason = self._urlencoded_output_guard(start_vid, r1)
            if _ue_reason:
                return AnalysisResult(
                    code=-1,
                    reason=_ue_reason,
                    chain=[{"step": "urlencoded_output_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(
                        self.graph.vs[start_vid], "lineno", 0))
        pinned_seen = getattr(self, "_redirect_pin_vids", set())
        # Fix 21a: negated safe-predicate predecessor guard (CouchCMS
        # whitelist form).  The superglobal member feeding this path is
        # guarded by a terminating !pred() branch earlier in the same
        # function, so reaching the sink proves pred()==true —
        # whitelist-constrained, not attacker-controlled.
        # Fix 23: fixed-host CURLOPT_URL — pin verdict before BFS verdict.
        if self.language == "php" and r1.code == 1 and getattr(
                self, "_f23_guard_cache", False):
            return AnalysisResult(
                code=-1,
                reason="fixed host URL: taint reaches only the query "
                       "component of a literal scheme://host target",
                chain=[{"step": "fixed_host_url_guard",
                        "vid": start_vid, "code": -1}],
                path=list(r1.path), expr_lineno=_vattr(
                    self.graph.vs[start_vid], "lineno", 0))
        _sv = self.graph.vs[start_vid]
        if self.language == "php" and r1.code == 1:
            _guard_reason = self._negated_whitelist_guard_for_result(
                r1, sink_vid=start_vid)
            if _guard_reason:
                return AnalysisResult(
                    code=-1,
                    reason=_guard_reason,
                    chain=[{"step": "negated_whitelist_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(_sv, "lineno", 0))
        # Fix 21d: filesystem existence whitelist (getsimple theme-edit
        # form).  `if ($_GET[t] && is_dir(PREFIX . $_GET[t])) { $v =
        # $_GET[t]; } echo $v;` — the guard constrains the assigned value
        # to a REAL directory/file name under a constant prefix, so the
        # echo reflects a server-controlled name, not attacker input.
        if self.language == "php" and r1.code == 1:
            _ex_reason = self._existence_whitelist_guard_for_result(r1)
            if _ex_reason:
                return AnalysisResult(
                    code=-1,
                    reason=_ex_reason,
                    chain=[{"step": "existence_whitelist_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(_sv, "lineno", 0))
        # Fix 21f: XXE disabled by libxml_disable_entity_loader() (getsimple
        # api.php:19).  When a call to libxml_disable_entity_loader() precedes
        # an XML-parsing sink (simplexml_load_string/file, DOMDocument load,
        # xml_parse) earlier in the same file, external entity expansion is
        # off — the parsed content cannot dereference attacker file:// or
        # http:// entities, so the sink result is not an XXE vector.
        if self.language == "php" and r1.code == 1:
            _xxe_sink = None
            if (_vattr(_sv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(_sv, "name", "") in self._XXE_SINK_FUNCS):
                _xxe_sink = start_vid
            else:
                # scanner typically enters parameters_back at the sink's
                # ARG node — find an XML-parse call this node feeds as an
                # ast argument (api.php:29 enters at '$_POST[data]').
                for pe in self._edge_in(start_vid, "ast"):
                    if _vattr(pe, "role", "") != "arg":
                        continue
                    pv = self.graph.vs[pe.source]
                    if (_vattr(pv, "label") == NodeLabel.OPERATOR.value
                            and _vattr(pv, "name", "") in self._XXE_SINK_FUNCS):
                        _xxe_sink = pe.source
                        break
            if _xxe_sink is not None and self._xxe_disabled_before(_xxe_sink):
                return AnalysisResult(
                    code=-1,
                    reason="xxe disabled: libxml_disable_entity_loader() "
                           "precedes XML sink in same file",
                    chain=[{"step": "xxe_disabled_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(_sv, "lineno", 0))

        # Fix 21h-2: dead code after unconditional die/exit (imcat
        # userc.php).  A bare die()/exit() top-level statement before the
        # sink's statement makes the sink unreachable — any superglobal
        # taint flowing to it is vacuous.
        if self.language == "php" and r1.code == 1:
            if self._unconditional_terminate_before(start_vid):
                return AnalysisResult(
                    code=-1,
                    reason="dead code: unconditional die/exit precedes "
                           "this statement in the same scope",
                    chain=[{"step": "unconditional_terminate_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(_sv, "lineno", 0))

        # Fix 21h-3: constructor property-write whitelist guard (osTicket
        # $report->end).  The sink reads $obj->prop on a `new`-created
        # object whose constructor whitelists the stored value via
        # array_key_exists/in_array — the read cannot yield attacker
        # content.  Also probe path nodes feeding this sink (scanner may
        # enter at a superglobal member arg instead of the property read).
        if self.language == "php" and r1.code == 1:
            if self._ctor_property_whitelist_guard(start_vid):
                return AnalysisResult(
                    code=-1,
                    reason="constructor whitelist guard constrains this "
                           "property's stored value",
                    chain=[{"step": "ctor_property_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(_sv, "lineno", 0))
            # Fix 21h-3c: the scanner may enter at the object VARIABLE
            # (sink arg extraction picks the base identifier of
            # `$obj->prop`), not the property node itself.  Run the same
            # guard on every property read reached via a member edge from
            # this variable (dashboard.inc.php:178 entry shape).
            # Fix 21h-3d: scanner may enter AT the sink operator itself
            # (echo L178 vid 211620 — PB-EXIT log evidence).  Run the ctor
            # guard on every ast-arg child of the sink call/echo.
            if (_vattr(_sv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(_sv, "type", "") in _CALL_TYPES | {"echo"}):
                for _se in self.graph.es.select(
                        _source=start_vid, label="ast"):
                    if _vattr(_se, "role", "") != "arg":
                        continue
                    if self._ctor_property_whitelist_guard(_se.target):
                        return AnalysisResult(
                            code=-1,
                            reason="constructor whitelist guard constrains "
                                   "this property's stored value",
                            chain=[{"step": "ctor_property_guard",
                                    "vid": _se.target, "code": -1}],
                            path=list(r1.path),
                            expr_lineno=_vattr(_sv, "lineno", 0))
            for _me in self._edge_out(start_vid, "member"):
                if self._ctor_property_whitelist_guard(_me.target):
                    return AnalysisResult(
                        code=-1,
                        reason="constructor whitelist guard constrains this "
                               "property's stored value",
                        chain=[{"step": "ctor_property_guard",
                                "vid": _me.target, "code": -1}],
                        path=list(r1.path),
                        expr_lineno=_vattr(_sv, "lineno", 0))
            for _pe in self._edge_in(start_vid, "ast"):
                if _vattr(_pe, "role", "") != "arg":
                    continue
                _pv = self.graph.vs[_pe.source]
                if (_vattr(_pv, "label") == NodeLabel.OPERATOR.value
                        and _vattr(_pv, "type", "") in _CALL_TYPES):
                    continue
                if self._ctor_property_whitelist_guard(_pe.source):
                    return AnalysisResult(
                        code=-1,
                        reason="constructor whitelist guard constrains this "
                               "property's stored value",
                        chain=[{"step": "ctor_property_guard",
                                "vid": _pe.source, "code": -1}],
                        path=list(r1.path),
                        expr_lineno=_vattr(_sv, "lineno", 0))
            # Fix 21h-3b: entry IS a new-call arg (scanner's actual entry
            # for `new C($_POST[...], ...)` sites) — param i is stored via
            # a whitelist ternary, so taint through this arg is constrained.
            if self._new_arg_constrained_by_ctor(start_vid):
                return AnalysisResult(
                    code=-1,
                    reason="constructor parameter is whitelist-constrained "
                           "before storage",
                    chain=[{"step": "ctor_param_guard",
                            "vid": start_vid, "code": -1}],
                    path=list(r1.path), expr_lineno=_vattr(_sv, "lineno", 0))

        if not (self._redirect_pin_ctx and r1.code == 1 and pinned_seen):
            return r1
        # Pass 2: block pinned concats, see if a fully-controlled path survives
        self._redirect_pin_blocked = set(pinned_seen)
        try:
            # Invalidate pass-1 cache entries so pass 2 re-traverses
            for k in [k for k, v in self._decision_cache.items()
                      if getattr(v, "_redirect_pinned_seen", False)]:
                self._decision_cache.pop(k, None)
            self._decision_cache.pop((start_vid, context_vid), None)
            r2 = self._parameters_back_impl(
                start_vid, context_vid=context_vid, max_depth=max_depth)
        finally:
            self._redirect_pin_blocked = set()
        if r2 is not None and r2.code == 1:
            return r2
        return AnalysisResult(
            code=-1,
            reason="redirect target pinned to site-internal path by constant prefix",
            chain=[{"step": "redirect_pinned",
                    "vids": sorted(pinned_seen), "code": -1}],
            path=list(r1.path), expr_lineno=r1.expr_lineno)

    # -- Fix 21d: filesystem existence whitelist -----------------------------

    _FS_EXISTENCE_FUNCS = frozenset({"is_dir", "is_file", "file_exists"})

    def _ast_children_role(self, vid: int, role: str) -> list[int]:
        """Ast out-edges of vid with the given role."""
        out = []
        for e in self._edge_out(vid, "ast"):
            if (e["role"] or "") == role:
                out.append(e.target)
        return out

    def _subtree_contains_superglobal_member(
            self, root_vid: int, sg_name: str, prop_name: str,
            max_depth: int = 14) -> bool:
        """Does the subtree rooted at root_vid read <sg_name>[prop_name]?"""
        stack = [(root_vid, 0)]
        while stack:
            vid, depth = stack.pop()
            if depth > max_depth:
                continue
            v = self.graph.vs[vid]
            if (v["label"] == NodeLabel.IDENTIFIER.value
                    and _vattr(v, "name", "") == prop_name
                    and _vattr(v, "type", "") == "property"):
                for e in self._edge_in(vid, "member"):
                    src = self.graph.vs[e.source]
                    if (_vattr(src, "label", "") == NodeLabel.IDENTIFIER.value
                            and _vattr(src, "name", "") == sg_name):
                        return True
            for e in self._edge_out(vid, "ast"):
                stack.append((e.target, depth + 1))
        return False

    def _existence_whitelist_guard_for_result(self, result: AnalysisResult) -> str | None:
        """Fix 21d post-check: walk the result path; for a superglobal
        member read whose value was assigned inside a branch whose
        condition ran a filesystem existence check (is_dir/is_file/
        file_exists) over a path CONTAINING that same member, the
        assigned value is constrained to real filesystem entries under
        the checked prefix → reflect it = reflect a server-controlled
        name.  Returns a reason string when guarded, None otherwise.
        """
        if not result.path:
            return None
        for idx, pvid in enumerate(result.path):
            if not isinstance(pvid, int) or pvid >= self.graph.vcount():
                continue
            pv = self.graph.vs[pvid]
            if (_vattr(pv, "label", "") != NodeLabel.IDENTIFIER.value
                    or _vattr(pv, "type", "") != "property"):
                continue
            prop_name = _vattr(pv, "name", "")
            # superglobal owner of this property read
            sg_name = None
            for e in self._edge_in(pvid, "member"):
                src = self.graph.vs[e.source]
                n = _vattr(src, "name", "")
                if n.startswith("$") and n.upper() in (
                        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"):
                    sg_name = n
                    break
            if sg_name is None:
                continue
            # climb ast to the assign op that wrote this value, then own
            # to the guarding branch
            cur = pvid
            assign_vid = None
            for _ in range(8):
                ups = [e.source for e in self._edge_in(cur, "ast")]
                if not ups:
                    break
                cur = ups[0]
                cv = self.graph.vs[cur]
                if (_vattr(cv, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(cv, "type", "") == "assign"):
                    assign_vid = cur
                    break
            if assign_vid is None:
                continue
            guarded = False
            for own_src in self._edge_in(assign_vid, "own"):
                bv = self.graph.vs[own_src.source]
                if _vattr(bv, "label", "") != NodeLabel.BRANCH.value:
                    continue
                for cond_vid in self._ast_children_role(own_src.source, "condition"):
                    # every call in the condition subtree
                    stack = [(cond_vid, 0)]
                    while stack:
                        cvid, depth = stack.pop()
                        if depth > 12:
                            continue
                        cv = self.graph.vs[cvid]
                        if (_vattr(cv, "label", "") == NodeLabel.OPERATOR.value
                                and _vattr(cv, "type", "") == "call"):
                            callees = self._ast_children_role(cvid, "callee")
                            cname = _vattr(self.graph.vs[callees[0]], "name", "") if callees else ""
                            if cname in self._FS_EXISTENCE_FUNCS:
                                for ae in self._ast_children_role(cvid, "arg"):
                                    if self._subtree_contains_superglobal_member(
                                            ae, sg_name, prop_name):
                                        guarded = True
                                        break
                            if guarded:
                                break
                        for e in self._edge_out(cvid, "ast"):
                            stack.append((e.target, depth + 1))
                    if guarded:
                        break
                if guarded:
                    break
            if guarded:
                return (f"existence whitelist: '{sg_name}[{prop_name}]' value "
                        f"constrained by filesystem check before assignment")
        return None

    # Fix 21f: XML parsers whose external-entity exposure is neutralized
    # by a preceding libxml_disable_entity_loader() call.
    _XXE_SINK_FUNCS: frozenset[str] = frozenset({
        "simplexml_load_string", "simplexml_load_file",
        "domdocument_load", "domdocument_loadxml", "domdocument::load",
        "domdocument::loadxml", "load", "loadxml", "loadxmlhtml",
        "xml_parse", "xml_parse_into_struct",
    })

    def _xxe_disabled_before(self, sink_vid: int) -> bool:
        """Fix 21f: libxml_disable_entity_loader() precedes an XML sink.

        Scans call nodes in the SAME FILE as the sink for
        libxml_disable_entity_loader on a strictly earlier line.  The
        libxml disable call is process-global once executed, so any
        earlier straight-line execution in the file suffices (getsimple
        api.php calls it at L19 before every request dispatch).
        """
        sv = self.graph.vs[sink_vid]
        s_file = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        if not s_file:
            return False
        try:
            s_lineno = int(_vattr(sv, "lineno", 0) or 0)
        except (TypeError, ValueError):
            return False
        if s_lineno <= 0:
            return False
        for vid in range(self.graph.vcount()):
            v = self.graph.vs[vid]
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "name", "") != "libxml_disable_entity_loader":
                continue
            v_file = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            if v_file != s_file:
                continue
            try:
                v_lineno = int(_vattr(v, "lineno", 0) or 0)
            except (TypeError, ValueError):
                continue
            if 0 < v_lineno < s_lineno:
                return True
        return False

    def _negated_whitelist_guard_for_result(self, result: AnalysisResult,
                                            sink_vid: int | None = None) -> str | None:
        """Fix 21a post-check: walk the result path; for each tainted var
        name, ask whether a terminating negated whitelist guard on that
        name precedes the sink in the sink's function.  Returns a reason
        string when guarded, None otherwise.

        *sink_vid* is the actual sink node whose lineno orders the guard
        check.  The path often starts at nodes created BEFORE the guard
        (e.g. `$in` assigned at L31, guard at L35, sink echo at L43) —
        ordering each probe against the probe node itself would reject
        the very guard that protects the sink (Fix 21e: getsimple
        api.php).  Falls back to path[0] when sink_vid is unavailable.
        """
        start_vid = sink_vid
        if start_vid is None:
            start_vid = result.path[0] if result.path else None
        if start_vid is None:
            return None
        sink_lineno = int(_vattr(self.graph.vs[start_vid], "lineno", 0) or 0) or None
        seen_names = set()
        for pvid in result.path:
            if not isinstance(pvid, int) or pvid >= self.graph.vcount():
                continue
            pv = self.graph.vs[pvid]
            pname = _vattr(pv, "name", "")
            if (pname and pname.startswith("$")
                    and _vattr(pv, "label", "") == NodeLabel.IDENTIFIER.value):
                seen_names.add(pname)
        # also the member key form ($sResourceType guards $_GET['Type'] via
        # the caller-side variable; sink-side param names differ from
        # caller-side guarded names, so probe every $name on the path)
        for pname in seen_names:
            for probe_vid in result.path:
                if not isinstance(probe_vid, int) or probe_vid >= self.graph.vcount():
                    continue
                # sink_lineno only applies within the sink's OWN file: the
                # sink (basexml.php:57) can legitimately sit BEFORE a guard
                # living in another file (connector.php:61) of the same
                # call path — order each cross-file probe by its own
                # lineno (Fix 21e CouchCMS regression).
                probe_lineno = sink_lineno
                if probe_lineno is not None:
                    pv_file = _vattr(self.graph.vs[probe_vid], "file_path", "") \
                        or _vattr(self.graph.vs[probe_vid], "path", "")
                    sink_file = _vattr(self.graph.vs[start_vid], "file_path", "") \
                        or _vattr(self.graph.vs[start_vid], "path", "")
                    if pv_file != sink_file:
                        probe_lineno = None
                if self._negated_whitelist_guard_before(
                        probe_vid, pname, sink_lineno=probe_lineno):
                    return (f"whitelist guard: '{pname}' constrained by "
                            f"terminating negated predicate before sink")
        return None

    def _parameters_back_impl(self, start_vid: int, context_vid: int | None = None,
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

        # Pre-check: if start node is a call to a safe function, return not controllable.
        # This catches cases where sink arg is a method_call like $field->show($input)
        # where show() is a user-defined sanitizer (marked safe by function_summary).
        if (_vattr(sv, "label") == NodeLabel.OPERATOR.value and
                _vattr(sv, "type", "") in _CALL_TYPES):
            start_lang = _vattr(sv, "language", "")
            for ue in self._edge_out(start_vid, "use"):
                tgt = self.graph.vs[ue.target]
                if _vattr(tgt, "label") != NodeLabel.FUNCTION.value:
                    continue
                tgt_lang = _vattr(tgt, "language", "")
                if tgt_lang and tgt_lang != self.language:
                    continue
                if not tgt_lang and start_lang and start_lang != self.language:
                    continue
                tgt_taint = _vattr(tgt, "taint_type", "")
                if not tgt_lang:
                    tgt_file = _vattr(tgt, "file_path", "") or _vattr(tgt, "path", "")
                    if not tgt_file:
                        continue
                tgt_summary = _vattr(tgt, "func_summary_type", "")
                if tgt_taint == "safe" or tgt_summary == "safe":
                    return self._cached(cache_key, AnalysisResult(
                        code=-1,
                        reason=f"safe function '{_vattr(tgt, 'name', '')}' at sink arg",
                        chain=[{"step": "safe_func_precheck", "vid": start_vid,
                                "name": _vattr(tgt, "name", ""), "code": -1}],
                        path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
                break

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

        # Post-guard check: scan ALL branches in the same function for
        # guard functions (url_has_allowed_host_and_scheme, is_safe_url,
        # etc.) that reference this variable.  This catches patterns like:
        #   url = form.cleaned_data["url"]      # tainted
        #   if not url_has_allowed_host_and_scheme(url, ...):
        #       url = safe_default
        #   redirect(url)                       # guarded, but outside if
        if (_vattr(sv, "label") == NodeLabel.IDENTIFIER.value and sname
                and self.language in ("python", "php")):
            if self._has_function_level_guard(start_vid, sname):
                return self._cached(cache_key, AnalysisResult(
                    code=-1,
                    reason=f"post-guard: '{sname}' validated by guard function",
                    chain=[{"step": "post_guard", "vid": start_vid,
                            "name": sname, "code": -1}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # Quick checks on start node itself
        # $_SERVER as a whole is not a source — only specific keys are.
        # Specific keys are detected via the member-chain walk below, where
        # _SERVER_UNCONTROLLED_KEYS filters out server-config fields.
        if sname != "$_SERVER" and self._is_source_variable(sname):
            # Source-level guard check: before reporting a superglobal as
            # the taint source, verify it isn't guarded by a function-level
            # preg_match or type validation. This catches patterns like:
            #   if (preg_match('/^[a-z_]*$/', $_GET['page'])) {
            #       $x = load($_GET['page']);
            #   }
            #   echo $x;  ← $x derives from $_GET['page'], which is guarded
            # The guard fires even though $x itself is not in any branch.
            if self.language in ("python", "php"):
                # Extract the member key for superglobals (e.g. 'page' from $_GET['page'])
                _guard_name = sname
                _member_key = _vattr(sv, "member_key", "") or _vattr(sv, "name2", "")
                if not _member_key:
                    # PHP subscripts are member edges ($_POST --member--> key
                    # property node), not node attributes.
                    _member_key = self._extract_member_key(sv)
                if _member_key:
                    _guard_name = _member_key
                if self._has_function_level_guard(start_vid, _guard_name):
                    return self._cached(cache_key, AnalysisResult(
                        code=-1,
                        reason=f"source '{sname}' guarded by function-level validation",
                        chain=[{"step": "source_guard", "vid": start_vid,
                                "name": sname, "code": -1}],
                        path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
            # If this node was sanitized by a safe-function reassignment,
            # its taint_type was changed from 'source' to 'safe' by enrich_taint.
            if _vattr(sv, "taint_type", "") == "safe":
                return self._cached(cache_key, AnalysisResult(
                    code=-1,
                    reason=f"superglobal '{sname}' sanitized by safe-function reassignment",
                    chain=[{"step": "sanitized_source", "vid": start_vid,
                            "name": sname, "code": -1}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
            # BRANCH nodes (if/ternary/while/etc.) have their condition text
            # as 'name'. Don't treat the condition text as a source variable —
            # the condition controls execution, its value doesn't flow to sink.
            if _vattr(sv, "label", "") != NodeLabel.BRANCH.value:
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
                    if self._is_superglobal_member_blocked(start_vid):
                        pass
                    else:
                        # Guard check for property full_text superglobal source
                        if self.language in ("python", "php"):
                            _gname = sname.strip("'\"")
                            if self._has_function_level_guard(start_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=f"source '{full_text}' guarded by function-level validation",
                                    chain=[{"step": "source_guard", "vid": start_vid,
                                            "name": full_text, "code": -1}],
                                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
                        return self._cached(cache_key, AnalysisResult(
                            code=1, reason=f"'{full_text}' is a superglobal (via member '{sname}')",
                            chain=[{"step": "source", "vid": start_vid, "name": full_text, "code": 1}],
                            path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        if _vattr(sv, "label") == NodeLabel.CONST.value:
            # Ruby string interpolation: a const string with DFG edges from
            # interpolated variables (e.g. userInput → dfg → "User: #{userInput}").
            # Continue BFS through these incoming DFG edges instead of returning constant.
            has_dfg_in = False
            for e in self._edge_in(start_vid, "dfg"):
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
            # If this property is nested inside a safe function call's
            # AST subtree (e.g. echo checkbox(..., $_COOKIE["x"], ...)),
            # it is sanitized — skip the member-chain source check.
            if self._is_inside_safe_call_ast(start_vid):
                return self._cached(cache_key, AnalysisResult(
                    code=-1, reason="member access inside safe function call",
                    chain=[{"step": "safe_call_member", "vid": start_vid,
                            "name": sname, "code": -1}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
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
            chain_names_start: list[str] = [sname]
            for _ in range(10):
                member_edges = list(self._edge_in(cur_member, "member"))
                if not member_edges:
                    break
                obj_vid = member_edges[0].source
                obj_v = self.graph.vs[obj_vid]
                obj_name = _vattr(obj_v, "name", "")
                obj_label = _vattr(obj_v, "label", "")
                obj_type = _vattr(obj_v, "type", "")
                if obj_name and obj_name != chain_names_start[-1]:
                    chain_names_start.append(obj_name)
                if self._is_source_variable(obj_name):
                    # $_SERVER has mixed controllability — skip server-config keys
                    # $_FILES has mixed controllability — skip non-source sub-keys
                    # Use the generalized _is_superglobal_member_blocked which
                    # properly walks the member chain and checks all keys.
                    if self._is_superglobal_member_blocked(start_vid):
                        return self._cached(cache_key, AnalysisResult(
                            code=-1,
                            reason=f"superglobal member blocked (non-source key)",
                            chain=[{"step": "non_source_member", "vid": start_vid,
                                    "name": sname, "code": -1}],
                            path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
                    elif self._is_subscript_key_of_non_superglobal(obj_vid):
                        # Superglobal (e.g., $_GET['format']) appears as an
                        # array-offset subscript of a non-superglobal variable
                        # (e.g., $export_formats[$_GET['format']]). It selects
                        # a predefined value, so it is NOT a direct data source.
                        pass
                    else:
                        # If this node was sanitized by a safe-function
                        # reassignment, its taint_type was changed from
                        # 'source' to 'safe' by enrich_taint.
                        if _vattr(obj_v, "taint_type", "") == "safe":
                            pass
                        # Function-level guard: the superglobal member may be
                        # validated by a whitelist guard (is_version,
                        # preg_match, ...) in an enclosing branch.  Without
                        # this check the member-access path bypassed the
                        # source-level guard entirely.
                        elif self.language in ("python", "php"):
                            _gname = (self._extract_member_key(obj_vid)
                                      or obj_name).strip("'\"")
                            if self._has_function_level_guard(start_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=f"source '{obj_name}[{_gname}]' guarded by function-level validation",
                                    chain=[{"step": "source_guard", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=[start_vid, obj_vid],
                                    expr_lineno=_vattr(obj_v, "lineno", 0)))
                            # Interprocedural path-traversal jail (Fix 19b):
                            # caller file probed this member with strpos('../')
                            # + die. Values flowing on cannot traverse out.
                            if self._has_path_jail_guard(obj_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=(f"source '{obj_name}[{_gname}]' jailed by "
                                            f"path-traversal blacklist guard (strpos+die)"),
                                    chain=[{"step": "path_jail", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=[start_vid, obj_vid],
                                    expr_lineno=_vattr(obj_v, "lineno", 0)))
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"superglobal '{obj_name}' via member access",
                                chain=[{"step": "member_source", "vid": obj_vid,
                                        "name": obj_name, "code": 1}],
                                path=[start_vid, obj_vid],
                                expr_lineno=_vattr(obj_v, "lineno", 0)))
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

            # Fix 42: cross-file property store→load chaining.
            #
            # PHP plugin architecture (Support Genix CVE-2026-110895 shape):
            # the parent class file assigns a request-sourced value to an
            # instance property —
            #     class Apbd_Wps_APIBase {          // APIBase.php
            #         function LoadPayload() {
            #             self::$payload_obj = json_decode($_POST['payload'], true);
            #             $this->payload = &self::$payload_obj;   // WRITE
            #     } }
            # and a DIFFERENT file reads it —
            #     class ApbdWpsAPI_Ticket extends Apbd_Wps_APIBase {  // Ticket.php
            #         function grid() {
            #             $x = $this->payload['sort_by'][0]['prop'];   // READ
            #     } }
            #
            # The graph builder creates separate property nodes per file and
            # the dfg builder deliberately skips self/this member edges
            # (field-insensitivity FPs), so the store in APIBase.php has no
            # out-edge and the load in Ticket.php has no dfg in-edge — the
            # taint chain is severed at the file boundary.
            #
            # Fallback: when the member-chain walk above terminated without
            # finding a source, look for same-name property WRITE nodes
            # (assign lhs) in other files whose class is in an extends
            # relationship with the reader's class (either direction), and
            # trace the stored value with _trace_dfg_direct (bounded, no
            # recursion into parameters_back).
            if _vattr(sv, "type") in ("field", "property"):
                _r42 = self._cross_file_property_source(start_vid, sname)
                if _r42 is not None:
                    return self._cached(cache_key, _r42)
                # Fix 43: stored-XSS DB table bridge.  Property reads on
                # DB row objects ($h->nama where $h came from
                # db->get('t')->result()) trace to nothing (the DB is
                # outside the graph).  Bridge to db->insert('t', $data)
                # sites whose data array has the SAME key stored from a
                # superglobal.
                _r43 = self._db_table_bridge_source(start_vid, sname)
                if _r43 is not None:
                    return self._cached(cache_key, _r43)

        if _vattr(sv, "label") == NodeLabel.OPERATOR.value \
                and _vattr(sv, "type") in _CALL_TYPES:
            callee = self._resolve_callee_name(start_vid)
            if callee and self._is_repair_function(callee):
                return self._cached(cache_key, AnalysisResult(
                    code=2, reason=f"calls repair '{callee}'",
                    chain=[{"step": "repair", "vid": start_vid, "name": callee, "code": 2}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))
            # Format-string sanitizers: sprintf('%d', ...) with a constant
            # numeric-only format destroys string payload — result is clean.
            # %s/%f formats pass taint through — fall through to normal tracing.
            if callee and callee in _FORMAT_STRING_SANITIZERS:
                fmt_const = self._format_string_arg0(start_vid)
                if fmt_const is not None and not re.search(
                        r'''%s''' % (chr(39)) if False else r"%[-+ 0#]*[.]?\d*[sfeEgGu]", fmt_const):
                    return self._cached(cache_key, AnalysisResult(
                        code=2,
                        reason=f"format-string sanitizer '{callee}({fmt_const!r})' — numeric-only format",
                        chain=[{"step": "format_sanitizer", "vid": start_vid,
                                "name": callee, "code": 2}],
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
            chain_names_pre: list[str] = [sname]
            for _ in range(10):
                member_edges = list(self._edge_in(cur_member, "member"))
                if not member_edges:
                    break
                obj_vid = member_edges[0].source
                obj_v = self.graph.vs[obj_vid]
                obj_name = _vattr(obj_v, "name", "")
                obj_label = _vattr(obj_v, "label", "")
                obj_type = _vattr(obj_v, "type", "")
                if obj_name and obj_name != chain_names_pre[-1]:
                    chain_names_pre.append(obj_name)
                if self._is_source_variable(obj_name):
                    # $_SERVER has mixed controllability — skip server-config keys
                    # $_FILES has mixed controllability — skip non-source sub-keys
                    # Check ALL names in the member chain (not just start node),
                    # so that $_FILES['x']['tmp_name'][$n] is correctly rejected:
                    # 'tmp_name' is a non-source member even though $n is not.
                    if (obj_name == "$_SERVER" and any(n in _SERVER_UNCONTROLLED_KEYS for n in chain_names_pre)) \
                            or (obj_name == "$_FILES" and any(n in _FILES_NON_SOURCE_MEMBERS for n in chain_names_pre)):
                        pass
                    elif self._is_subscript_key_of_non_superglobal(obj_vid):
                        pass
                    else:
                        # If this node was sanitized by a safe-function
                        # reassignment, its taint_type was changed from
                        # 'source' to 'safe' by enrich_taint.
                        if _vattr(obj_v, "taint_type", "") == "safe":
                            pass
                        # Function-level guard: the superglobal member may be
                        # validated by a whitelist guard (is_version,
                        # preg_match, ...) in an enclosing branch.  Without
                        # this check the member-access path bypassed the
                        # source-level guard entirely.
                        elif self.language in ("python", "php"):
                            _gname = (self._extract_member_key(obj_vid)
                                      or obj_name).strip("'\"")
                            if self._has_function_level_guard(start_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=f"source '{obj_name}[{_gname}]' guarded by function-level validation",
                                    chain=[{"step": "source_guard", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=[start_vid, obj_vid],
                                    expr_lineno=_vattr(obj_v, "lineno", 0)))
                            # Interprocedural path-traversal jail (Fix 19b):
                            # caller file probed this member with strpos('../')
                            # + die. Values flowing on cannot traverse out.
                            if self._has_path_jail_guard(obj_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=(f"source '{obj_name}[{_gname}]' jailed by "
                                            f"path-traversal blacklist guard (strpos+die)"),
                                    chain=[{"step": "path_jail", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=[start_vid, obj_vid],
                                    expr_lineno=_vattr(obj_v, "lineno", 0)))
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"superglobal '{obj_name}' via member access",
                                chain=[{"step": "member_source", "vid": obj_vid,
                                        "name": obj_name, "code": 1}],
                                path=[start_vid, obj_vid],
                                expr_lineno=_vattr(obj_v, "lineno", 0)))
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

        # ── Fix 43j: CI view bridge, EARLY (pre-BFS) ──────────────────
        # Same predicate as the exhausted-tail bridge (Fix 43c) but fired
        # BEFORE the 50-hop BFS: a view-file variable with no DFG in-edge
        # can only resolve through the loader bridge, and running the full
        # BFS first costs O(sinks × 50 hops) for a guaranteed dead end.
        if self.language == "php":
            _sfp0 = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
            if (_sfp0 and "/views/" in _sfp0.replace("\\", "/")
                    and _vattr(sv, "label", "") == NodeLabel.IDENTIFIER.value
                    and _vattr(sv, "type", "") == "variable"
                    and not self._get_dfg_sources(start_vid)
                    and not getattr(self, "_in_view_bridge", False)):
                _v43j = self._ci_view_bridge_source(start_vid, _vattr(sv, "name", ""))
                if _v43j is not None and _v43j.code == 1:
                    return self._cached(cache_key, _v43j)

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
        inconclusive_fallback: AnalysisResult | None = None
        # Fix 21b-2: a proven sanitation stop (tt='safe' re-assign) — used
        # as the exhausted-fallback result when no route reaches a source.
        repaired_result: AnalysisResult | None = None
        crossed_function_boundary: bool = False
        # Fix 20b: pin-collection state is owned by the public driver
        # (parameters_back); recursive/impl invocations reuse whatever the
        # driver set.  Only collect pinned concats when the driver armed
        # the redirect context (avoids duplicate _start_is_redirect_sink
        # walks on every recursive call).
        _redirect_ctx = getattr(self, "_redirect_pin_ctx", False)
        if getattr(self, "_redirect_pin_vids", None) is None:
            self._redirect_pin_vids = set()

        while queue:
            cur_vid, depth, path = queue.popleft()
            # Fix 37a: Java this.<field> READ reached during backward trace
            # -- bridge to the constructor/method WRITE points of the same
            # field (field-load propagation).  Only fires for java
            # this.<name> method_call reads with a same-class field decl
            # hub; PHP/JS member chains are handled by the member-access
            # pre-check above.
            if (self.language == "java" and depth < max_depth - 1
                    and _vattr(self.graph.vs[cur_vid], "type", "") in ("method_call", "static_call")):
                # Fix 38: accumulator read (toString/build/...) -- bridge
                # to same-receiver write args (write/append/...).
                _frag = self._java_accum_read_sources(cur_vid)
                for _arg_vid, _wctx in _frag:
                    _fsub = self.parameters_back(_arg_vid, context_vid=_wctx,
                                                 max_depth=max_depth - depth - 1)
                    if _fsub is not None and _fsub.is_controllable:
                        _fsub.path = path + [cur_vid] + (_fsub.path or [])
                        return self._cached(cache_key, _fsub)
                _stores = self._java_field_store_sources(cur_vid)
                for _rhs_vid, _wctx in _stores:
                    _sub = self.parameters_back(_rhs_vid, context_vid=_wctx,
                                                max_depth=max_depth - depth - 1)
                    if _sub is not None and _sub.is_controllable:
                        _sub.path = path + [cur_vid] + (_sub.path or [])
                        return self._cached(cache_key, _sub)
                    # Fix 37a-2: stored value depends on the writer
                    # function's params (e.g. constructor param f in
                    # this.fld = f) -- resolve through the writer's call
                    # sites' actual args.
                    if (_sub is not None and _wctx is not None
                            and (_sub.has_deps
                                 or (_sub.code in (-1, 4)
                                     and "entry parameter" in (_sub.reason or "")))):
                        _dep_names = list(_sub.deps or [])
                        if not _dep_names and "entry parameter" in (_sub.reason or ""):
                            import re as _re37
                            _m37 = _re37.search(r"entry parameter '([^']+)'", _sub.reason or "")
                            if _m37:
                                _dep_names = [_m37.group(1)]
                        _resolved = self._resolve_java_param_deps(_dep_names, _wctx,
                                                                  max_depth - depth - 1)
                        if _resolved is not None:
                            _resolved.path = path + [cur_vid] + (_resolved.path or [])
                            return self._cached(cache_key, _resolved)
                    if _sub is not None and _sub.code == 3:
                        if inconclusive_fallback is None:
                            inconclusive_fallback = _sub
            # Check if cur_vid is an assign LHS identifier whose RHS is a
            # repair/safe function call. If so, taint stops here.
            if (_vattr(self.graph.vs[cur_vid], "label", "") == NodeLabel.IDENTIFIER.value
                    and not self._get_dfg_sources(cur_vid)):
                _rhs = self._find_assign_rhs_call(cur_vid)
                if _rhs is not None:
                    _rhs_callee = self._resolve_callee_name(_rhs)
                    if _rhs_callee and self._is_repair_function(_rhs_callee):
                        # Fix 34c: record the sanitation proof and CONTINUE
                        # the BFS instead of returning immediately.  This
                        # stop fires on any identifier whose assignment RHS
                        # is a repair call -- including sub-expressions of a
                        # larger concatenation.  CVE-2026-108970: in
                        # addNewUser, "INSERT ... VALUES('$username',...,
                        # $time, $branch)" concat contains $time=time();
                        # the $time route dead-ended here and returned
                        # safe for the WHOLE concat, hiding the unquoted
                        # $branch route.  Sibling routes must keep tracing;
                        # the proof is only returned if ALL routes end
                        # clean (exhausted fallback, same as Fix 21b-2).
                        if repaired_result is None:
                            repaired_result = AnalysisResult(
                                code=2, reason=f"assign RHS repair '{_rhs_callee}'",
                                chain=[{"step": "repair", "vid": _rhs,
                                        "name": _rhs_callee, "code": 2}],
                                path=path + [_rhs],
                                expr_lineno=_vattr(self.graph.vs[cur_vid], "lineno", 0))
                        continue
                    # Also check if RHS is a safe function call (sanitizer).
                    # When DFG cleanup has removed the safe function's
                    # arg→return edge, the LHS identifier has no DFG sources,
                    # and we can detect the sanitizer here.
                    if self._is_safe_function_call(_rhs):
                        return self._cached(cache_key, AnalysisResult(
                            code=-1, reason=f"assign RHS safe function '{_rhs_callee or _rhs}'",
                            chain=[{"step": "safe_rhs", "vid": _rhs,
                                    "name": _rhs_callee or "", "code": -1}],
                            path=path + [_rhs],
                            expr_lineno=_vattr(self.graph.vs[cur_vid], "lineno", 0)))
            for up_vid in self._get_dfg_sources(cur_vid):
                if up_vid in visited:
                    continue
                # Skip DFG edges marked as branch-safe (pre-processed).
                # (cur_vid) shares a branch scope with the sink.  Cross-scope
                # branch-safe marks should not block BFS traversal — e.g.
                # vid=28 (cmd in if-A) is marked branch-safe, but BFS from
                # vid=38 (cmd in if-B) must still traverse through vid=28
                # to reach the true source (argv).
                if self._is_dfg_branch_safe(up_vid, cur_vid):
                    cur_bc = self.get_branch_chain(cur_vid)
                    # Fix 34e: only trust the intersection when a shared
                    # branch actually has a condition.  Empty-condition
                    # branches (normalizer never filled type/condition --
                    # e.g. register()'s if-blocks in CVE-2026-108970) carry
                    # no constraint evidence; intersecting on their vids
                    # alone silently dropped the cross-function arg->param
                    # route and hid the SQL injection.
                    _shared_bc = set(cur_bc) & sink_branch_set
                    if cur_bc and _shared_bc and any(
                            _vattr(self.graph.vs[_b], 'condition', '')
                            for _b in _shared_bc):
                        continue
                visited.add(up_vid)
                uv = self.graph.vs[up_vid]
                # Safe node — taint propagation stops here
                up_taint = _vattr(uv, "taint_type", "")
                if up_taint == "safe":
                    # Fix 21b-2: remember the sanitation proof.  If ALL routes
                    # dead-end clean, the result is repaired (code=2), not
                    # inconclusive.  Only trust safe marks that a call node
                    # with a safe resolver backs (enrich_taint sets 'safe'
                    # exactly for safe-call reassignments).
                    if repaired_result is None:
                        repaired_result = AnalysisResult(
                            code=2,
                            reason=f"'{sname}' sanitized by safe reassignment "
                                   f"(vid={up_vid})",
                            chain=[{"step": "safe_reassign", "vid": up_vid,
                                    "name": _vattr(uv, "name", ""), "code": 2}],
                            path=path + [up_vid],
                            expr_lineno=_vattr(uv, "lineno", 0))
                    continue
                # Fix 14: type cast operators also sanitize taint.
                # (int), (float), (bool) etc. destroy string content.
                if _vattr(uv, "type", "") == "type_cast" and _vattr(uv, "name", "") in _TYPE_CAST_SAFE:
                    continue
                # Format-string sanitizer call node on the BFS path
                # (e.g. echo sprintf('%d', $x)): prune like a sanitizer when
                # the constant format is numeric-only.
                if (_vattr(uv, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(uv, "type", "") in _CALL_TYPES):
                    _fc = self._resolve_callee_name(up_vid)
                    if _fc and _fc in _FORMAT_STRING_SANITIZERS:
                        _ff = self._format_string_arg0(up_vid)
                        if _ff is not None and not re.search(
                                r"%[-+ 0#]*[.]?\d*[sfeEgGu]", _ff):
                            if repaired_result is None:
                                repaired_result = AnalysisResult(
                                    code=2,
                                    reason=f"format-string sanitizer '{_fc}({_ff!r})' — numeric-only format",
                                    chain=[{"step": "format_sanitizer", "vid": up_vid,
                                            "name": _fc, "code": 2}],
                                    path=path + [up_vid],
                                    expr_lineno=_vattr(uv, "lineno", 0))
                            continue
                uname = _vattr(uv, "name", "")
                ulabel = _vattr(uv, "label", "")
                utype = _vattr(uv, "type", "")
                new_path = path + [up_vid]

                # Rule 0: function parameter (entry point)
                if ulabel == "parameter":
                    crossed_function_boundary = True
                    # Python/Ruby: 'self' / 'this' parameter is the class
                    # instance, not user input. Skip it to avoid false
                    # positives where BFS traces self.attribute → self →
                    # request → POST.
                    if uname in ("self", "this") and self.language in ("python", "ruby"):
                        if param_fallback is None:
                            param_fallback = AnalysisResult(
                                code=-1,
                                reason=f"instance parameter '{uname}'",
                                chain=[{"step": "entry_param", "vid": up_vid,
                                        "name": uname, "code": -1}],
                                path=new_path, expr_lineno=_vattr(uv, "lineno", 0))
                        continue
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

                # Fix 42: property node reached mid-BFS — the member-access
                # pre-check at parameters_back entry never ran for it (the
                # trace started at a plain variable).  Run the cross-file
                # property store→load search here so `$q = ... $this->payload[...]`
                # chains resolve when BFS walks var -> property.
                if (_vattr(uv, "label", "") == NodeLabel.IDENTIFIER.value
                        and _vattr(uv, "type", "") in ("field", "property")
                        and uname):
                    _r42b = self._cross_file_property_source(up_vid, uname)
                    if _r42b is not None:
                        _r42b.path = (path + [cur_vid]
                                      + (_r42b.path or []))
                        return self._cached(cache_key, _r42b)

                # Rule 1: superglobal
                if self._is_source_variable(uname):
                    # $_SERVER/$_FILES have mixed controllability per key — check if all
                    # member children in this file are non-source keys
                    if self._is_superglobal_only_non_source_members(up_vid):
                        logger.debug("superglobal blocked: all member keys non-source, vid=%d", up_vid)
                        continue
                    # $_FILES bare form is an array, not a scalar source.
                    if uname == "$_FILES":
                        logger.debug("$_FILES blocked: bare form not a scalar source, vid=%d", up_vid)
                        continue
                    # Superglobal used as array-offset subscript key of a
                    # non-superglobal (e.g., $export_formats[$_GET['format']]).
                    # It selects a predefined value, not a direct data source.
                    if self._is_subscript_key_of_non_superglobal(up_vid):
                        continue
                    # Branch constraint check on the source variable itself.
                    # Even though the sink arg may have a different name, the
                    # source variable (e.g. $_GET['page']) might be directly
                    # constrained by an enclosing if(preg_match(...)) branch.
                    if uname and _vattr(uv, "label") == NodeLabel.IDENTIFIER.value:
                        src_branch_chain = self.get_branch_chain(up_vid)
                        if src_branch_chain:
                            for sbvid in src_branch_chain:
                                if self.check_branch_constraint(sbvid, uname):
                                    logger.debug(
                                        "source '%s' vid=%d blocked by branch constraint in %s('%s')",
                                        uname, up_vid,
                                        _vattr(self.graph.vs[sbvid], "type", ""),
                                        _vattr(self.graph.vs[sbvid], "condition", ""),
                                    )
                                    # This DFG path is safe — skip it, but
                                    # continue BFS in case other paths reach
                                    # an unconstrained source.
                                    break
                            else:
                                # No branch constraint blocked this source
                                # Function-level guard check (preg_match, etc.)
                                if self.language in ("python", "php") and uname.startswith("$"):
                                    _gname = self._extract_member_key(up_vid) or uname
                                    _gname = _gname.strip("'\"")
                                    if self._has_function_level_guard(up_vid, _gname):
                                        return self._cached(cache_key, AnalysisResult(
                                            code=-1,
                                            reason=f"source '{uname}' guarded by function-level validation",
                                            chain=[{"step": "source_guard", "vid": up_vid,
                                                    "name": uname, "code": -1}],
                                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))
                                # If this node was sanitized by a safe-function
                                # reassignment, its taint_type was changed from
                                # 'source' to 'safe' by enrich_taint.
                                if _vattr(uv, "taint_type", "") == "safe":
                                    pass
                                else:
                                    logger.debug("source found '%s' vid=%d", uname, up_vid)
                                    return self._cached(cache_key, AnalysisResult(
                                        code=1, reason=f"superglobal '{uname}'",
                                        chain=[{"step": "dfg", "vid": up_vid, "name": uname, "code": 1}],
                                        path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))
                        else:
                            # Function-level guard check (preg_match, etc.)
                            if self.language in ("python", "php") and uname.startswith("$"):
                                _gname = self._extract_member_key(up_vid) or uname
                                _gname = _gname.strip("'\"")
                                if self._has_function_level_guard(up_vid, _gname):
                                    return self._cached(cache_key, AnalysisResult(
                                        code=-1,
                                        reason=f"source '{uname}' guarded by function-level validation",
                                        chain=[{"step": "source_guard", "vid": up_vid,
                                                "name": uname, "code": -1}],
                                        path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))
                            # If this node was sanitized by a safe-function
                            # reassignment, its taint_type was changed from
                            # 'source' to 'safe' by enrich_taint.
                            if _vattr(uv, "taint_type", "") == "safe":
                                pass
                            else:
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
                            # Respect taint_type=safe from enrich_taint
                            if _vattr(uv, "taint_type", "") == "safe":
                                pass
                            elif self._get_member_chain_parent_taint(up_vid) == "safe":
                                pass
                            elif self._is_superglobal_member_blocked(up_vid):
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
                        # Respect taint_type=safe from enrich_taint.
                        # Check both this node and its superglobal parent.
                        if _vattr(uv, "taint_type", "") == "safe":
                            pass
                        elif self._get_member_chain_parent_taint(up_vid) == "safe":
                            pass
                        # $_SERVER/$_FILES have mixed controllability — check member chain
                        elif self._is_superglobal_member_blocked(up_vid):
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

                # Rule 2b: binary_op / subscript / call / statement (e.g., sys.argv[0],
                # arr[key], obj.method(), echo expr) — check ast children for source
                # variable (the object being indexed/called).  DFG only flows
                # from the operator to its result; the indexed/called object is
                # connected via ast edges, not dfg.
                if (ulabel == NodeLabel.OPERATOR.value and utype in (
                    "binary_op", "subscript", "call",
                )):
                    # Fix 20b: redirect target pinned by constant prefix.
                    # './user.php?id=' . $_GET['id'] → only the query string
                    # is attacker-controlled; the Location base is a site-
                    # internal relative path.  Record the pinned node instead
                    # of returning immediately: suppression happens in the
                    # instance-level _cached gate, which path-checks every
                    # code=1 result — sinks with a fully-controlled sibling
                    # caller stay code=1 (path-sensitive).
                    if (_redirect_ctx and utype == "binary_op"
                            and self._redirect_base_pinned_by_const(up_vid)):
                        if up_vid in self._redirect_pin_blocked:
                            # Pass 2: this concat is pinned — taint must NOT
                            # travel through it.  Skip this upstream entirely
                            # so only independent fully-controlled paths can
                            # produce a code=1 on the re-run.
                            continue
                        self._redirect_pin_vids.add(up_vid)
                    # When tracing into a call's arguments, respect builtin_knowledge
                    # passthrough: only trace args that are in the passthrough list.
                    # This prevents false taint from non-data args (e.g. apply_filters
                    # hook name in arg0 when only arg1 flows to return).
                    _bk_passthrough = None
                    _is_safe_call = False
                    if utype == "call":
                        _callee = self._resolve_callee_name(up_vid)
                        if _callee:
                            _bk = self._load_builtin_knowledge(self.language)
                            if _bk and _callee in _bk:
                                _entry = _bk[_callee]
                                if isinstance(_entry, dict):
                                    if _entry.get("safe"):
                                        _is_safe_call = True
                                    elif not _entry.get("safe"):
                                        _bk_passthrough = set(_entry.get("passthrough", []))
                        # Also check function summary (user-defined functions
                        # whose return value was determined safe by
                        # build_function_summaries, e.g. checkbox→h→htmlspecialchars)
                        if not _is_safe_call:
                            _up_taint = _vattr(uv, "taint_type", "")
                            if _up_taint == "safe":
                                _is_safe_call = True
                            else:
                                # Check func_summary_type via use edge
                                for _ue in self._edge_out(up_vid, "use"):
                                    _fvid = _ue.target
                                    if _fvid < self.graph.vcount():
                                        _fv = self.graph.vs[_fvid]
                                        if _vattr(_fv, "func_summary_type", "") == "safe":
                                            _is_safe_call = True
                                            break
                    for ae in self._edge_out(up_vid, "ast"):
                        # If this call's callee is a known safe function (sanitizer),
                        # skip all AST children — the return value is not tainted.
                        if _is_safe_call:
                            break
                        # Skip args not in passthrough when builtin_knowledge constrains flow
                        if _bk_passthrough is not None:
                            _role = _vattr(ae, "role", "")
                            _arg_idx = _vattr(ae, "arg_index", None)
                            if _role == "arg" and _arg_idx is not None and _arg_idx not in _bk_passthrough:
                                continue
                        child_vid = ae.target
                        cv = self.graph.vs[child_vid]
                        child_name = _vattr(cv, "name", "")
                        child_type = _vattr(cv, "type", "")
                        child_label = _vattr(cv, "label", "")
                        # Skip safe function call children — their arguments
                        # are sanitized, so $_GET inside them is not a source.
                        if child_label == NodeLabel.OPERATOR.value and child_type in ("call", "method_call", "static_call"):
                            if self._is_safe_function_call(child_vid):
                                continue
                        # Direct name check
                        if self._is_source_variable(child_name):
                            # Respect taint_type=safe from enrich_taint
                            if _vattr(cv, "taint_type", "") == "safe":
                                continue
                            if self._is_superglobal_member_blocked(child_vid):
                                pass
                            else:
                                # Guard check for direct superglobal subscript source
                                if self.language in ("python", "php"):
                                    _gname = child_name.rsplit(".", 1)[-1] if "." in child_name else child_name
                                    _gname = _gname.strip("'\"")
                                    # For bare superglobals (e.g. "$_GET"), try to
                                    # extract the subscript key from member children
                                    # so the guard matches by key name (e.g. "dl").
                                    if _gname.startswith("$"):
                                        _member_key = self._extract_member_key(child_vid)
                                        if _member_key:
                                            _gname = _member_key
                                    if self._has_function_level_guard(child_vid, _gname):
                                        return self._cached(cache_key, AnalysisResult(
                                            code=-1,
                                            reason=f"source '{child_name}' guarded by function-level validation",
                                            chain=[{"step": "source_guard", "vid": child_vid,
                                                    "name": child_name, "code": -1}],
                                            path=new_path + [child_vid],
                                            expr_lineno=_vattr(cv, "lineno", 0)))
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
                                # Respect taint_type=safe from enrich_taint.
                                # Check both the child (property) and the
                                # superglobal parent it chains to — enrich_taint
                                # marks the $_GET node as safe, not the property.
                                if _vattr(cv, "taint_type", "") == "safe":
                                    continue
                                _sg_parent_taint = self._get_member_chain_parent_taint(child_vid)
                                if _sg_parent_taint == "safe":
                                    continue
                                if self._is_superglobal_member_blocked(child_vid):
                                    pass
                                else:
                                    # Guard check: verify this superglobal member
                                    # isn't validated by a function-level preg_match
                                    # or type validation before reporting it as source.
                                    if self.language in ("python", "php"):
                                        # Extract member key from chain_name (e.g. "page" from "$_GET.page")
                                        _gname = chain_name.rsplit(".", 1)[-1] if "." in chain_name else chain_name
                                        _gname = _gname.strip("'\"")
                                        if self._has_function_level_guard(child_vid, _gname):
                                            return self._cached(cache_key, AnalysisResult(
                                                code=-1,
                                                reason=f"source '{chain_name}' guarded by function-level validation",
                                                chain=[{"step": "source_guard", "vid": child_vid,
                                                        "name": chain_name, "code": -1}],
                                                path=new_path + [child_vid],
                                                expr_lineno=_vattr(cv, "lineno", 0)))
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
                    # Rule 3a2: call to function with func_summary_type="safe"
                    # or taint_type="safe" on the function definition node.
                    # This catches user-defined sanitizer functions (e.g.,
                    # stripinput() that wraps htmlspecialchars) that were
                    # marked safe by build_function_summaries.
                    call_lang = _vattr(self.graph.vs[up_vid], "language", "")
                    for ue in self._edge_out(up_vid, "use"):
                        tgt = self.graph.vs[ue.target]
                        if _vattr(tgt, "label") != NodeLabel.FUNCTION.value:
                            continue
                        # In multi-language graphs, skip functions from
                        # other languages to prevent cross-language taint
                        # pollution (e.g. JS app.get safe blocking Python get).
                        tgt_lang = _vattr(tgt, "language", "")
                        if tgt_lang and tgt_lang != self.language:
                            continue
                        if not tgt_lang and call_lang and call_lang != self.language:
                            continue
                        # Skip functions with no file_path in multi-lang graphs;
                        # they are often cross-language ghost nodes (e.g. JS app.get
                        # linked to Python request.GET.get via name matching).
                        if not tgt_lang:
                            tgt_file = _vattr(tgt, "file_path", "") or _vattr(tgt, "path", "")
                            if not tgt_file:
                                continue
                        tgt_taint = _vattr(tgt, "taint_type", "")
                        tgt_summary = _vattr(tgt, "func_summary_type", "")
                        if tgt_taint == "safe" or tgt_summary == "safe":
                            return self._cached(cache_key, AnalysisResult(
                                code=2, reason=f"safe function '{_vattr(tgt, 'name', '')}'",
                                chain=[{"step": "dfg", "vid": up_vid,
                                        "name": _vattr(tgt, "name", ""), "code": 2}],
                                path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))
                        # Check all same-name function nodes for safe summary.
                        # PHP normalizer sometimes creates duplicate function
                        # nodes (definition vs reference). If ANY same-name
                        # node has summary=safe, treat as safe.
                        tgt_name = _vattr(tgt, "name", "")
                        if tgt_name and tgt_summary != "safe" and tgt_taint != "safe":
                            for sv in self.graph.vs.select(name=tgt_name, label=NodeLabel.FUNCTION.value):
                                sv_lang = _vattr(sv, "language", "")
                                if sv_lang and sv_lang != self.language:
                                    continue
                                if _vattr(sv, "func_summary_type", "") == "safe" or _vattr(sv, "taint_type", "") == "safe":
                                    return self._cached(cache_key, AnalysisResult(
                                        code=2, reason=f"safe function '{tgt_name}' (via same-name lookup)",
                                        chain=[{"step": "dfg", "vid": up_vid,
                                                "name": tgt_name, "code": 2}],
                                        path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))
                        break  # only check first function target

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
                    if node_taint == "source" or node_taint == "source:user":
                        # For user-defined source producers, try inline return
                        # analysis — the function body may sanitize the source
                        # (basename, md5, whitelist) before returning.
                        if node_taint == "source:user":
                            # Find function def via use edge
                            func_def_vid = None
                            for ue in self._edge_out(up_vid, "use"):
                                if _vattr(self.graph.vs[ue.target], "label") == NodeLabel.FUNCTION.value:
                                    func_def_vid = ue.target
                                    break
                            if func_def_vid is not None:
                                ret = self.analyze_function_return(up_vid, func_def_vid)
                                if ret is not None and not ret.is_controllable:
                                    return self._cached(cache_key, ret)
                                if ret is not None and ret.is_controllable:
                                    return self._cached(cache_key, ret)
                                # Inconclusive → fall through to default
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"source function '{uname}'",
                            chain=[{"step": "taint_source", "vid": up_vid,
                                    "name": uname, "code": 1}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 4: function call — cg → function(taint_type) → parameter(passthrough_arg)
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    callee = self._resolve_callee_name(up_vid)

                    # Count actual args at the call site for overload resolution.
                    call_arg_count = 0
                    for _ae in self._edge_out(up_vid, "ast"):
                        if _vattr(_ae, "role", "") == "arg":
                            call_arg_count += 1

                    # 沿 use 边找到 function 定义节点，读 taint_type
                    func_taint = ""
                    func_vid = None
                    # Iterate ALL use-edge targets, prefer a function node
                    # that has a non-empty taint_type.  A call may have
                    # multiple use edges (e.g. a placeholder/external node
                    # plus the real definition); taking the first one blindly
                    # can miss safe/passthrough annotations on the real def.
                    # Also resolve overloads: prefer function defs whose
                    # parameter count matches the call site.
                    use_targets = list(self._edge_out(up_vid, "use"))
                    # Partition: matching param count vs non-matching
                    matching_arity = []
                    other = []
                    for ce in use_targets:
                        fv = self.graph.vs[ce.target]
                        if _vattr(fv, "label") != NodeLabel.FUNCTION.value:
                            continue
                        # Count function def parameters
                        param_count = sum(
                            1 for pe in self._edge_out(ce.target, "own")
                            if _vattr(self.graph.vs[pe.target], "label", "") == "parameter"
                        )
                        if param_count == call_arg_count:
                            matching_arity.append(ce)
                        else:
                            other.append(ce)
                    # Search matching-arity targets first, then fall back
                    for ce in matching_arity + other:
                        fv = self.graph.vs[ce.target]
                        ft = _vattr(fv, "taint_type", "")
                        if ft:
                            # Found an annotated function — use it
                            func_vid = ce.target
                            func_taint = ft
                            break
                        # Remember the first unannotated function as fallback
                        if func_vid is None:
                                func_vid = ce.target

                    # If the use-edge target has no taint annotation, follow
                    # alias edges to find the real function definition that
                    # does (e.g. placeholder node → alias → Core_Upgrader.upgrade).
                    if not func_taint and func_vid is not None:
                        for ae in self._edge_out(func_vid, "alias"):
                            av = self.graph.vs[ae.target]
                            if _vattr(av, "label") == NodeLabel.FUNCTION.value:
                                at = _vattr(av, "taint_type", "")
                                if at:
                                    func_vid = ae.target
                                    func_taint = at
                                    break

                    # 如果 use 边没找到 function 定义，检查 call 节点自身的 taint 属性
                    # （builtin 函数调用被 enrich_taint 直接标注在 call 节点上）
                    if not func_taint:
                        func_taint = _vattr(uv, "taint_type", "")
                        if func_taint:
                            func_vid = up_vid

                    # 4a: source — 函数本身产生可控数据
                    if func_taint == "source" or func_taint == "source:user":
                        # For user-defined source producers, try inline return analysis
                        if func_taint == "source:user" and func_vid is not None:
                            ret = self.analyze_function_return(up_vid, func_vid)
                            if ret is not None and not ret.is_controllable:
                                return self._cached(cache_key, ret)
                            if ret is not None and ret.is_controllable:
                                return self._cached(cache_key, ret)
                            # Inconclusive → fall through to default
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

                        # Fix 21b-2: array-callback functions (array_map etc.)
                        # pass elements through their CALLBACK (arg0).  When
                        # that callback resolves to a safe function (builtin
                        # safe like htmlspecialchars, or func_summary safe
                        # like dokuwiki hsc), every element of the result is
                        # sanitized — the passthrough route from arg1 must
                        # report repaired, not controllable.
                        if (callee in _ARRAY_CALLBACK_FUNCS
                                and self._callback_arg_is_safe(up_vid)):
                            return self._cached(cache_key, AnalysisResult(
                                code=2,
                                reason=(f"array elements sanitized by safe "
                                        f"callback through '{callee}'"),
                                chain=[{"step": "array_callback_safe",
                                        "vid": up_vid,
                                        "name": callee, "code": 2}],
                                path=new_path,
                                expr_lineno=_vattr(uv, "lineno", 0)))

                        # 位置参数 passthrough：读 function 节点的常驻属性
                        tp = _vattr(self.graph.vs[func_vid], "taint_passthrough", [])
                        pt_param_indices: set[int] = set(
                            int(i) for i in tp if isinstance(i, int)
                        )
                        # 映射到 call 的实参
                        if pt_param_indices:
                            arg_counter = 0
                            for ae in self._edge_out(up_vid, "ast"):
                                if _vattr(ae, "role") != "arg":
                                    continue
                                idx = _vattr(ae, "index")
                                actual_idx = int(idx) if idx else arg_counter
                                if actual_idx in pt_param_indices:
                                    arg_vid = ae.target
                                    # Fix 42h: skip PHP array-literal pseudo-calls
                                    # ('array()' renders as a call node).  A
                                    # literal default like GetPayload(k, [])
                                    # carries no taint; tracing it only wedges
                                    # the BFS on the 'array' empty shell and
                                    # masks the receiver-member route the 4d
                                    # body trace would find.
                                    _av_type = _vattr(self.graph.vs[arg_vid], "type", "")
                                    _av_name = _vattr(self.graph.vs[arg_vid], "name", "")
                                    if (self.language == "php"
                                            and _av_type in ("call", "method_call")
                                            and _av_name == "array"):
                                        arg_counter += 1
                                        continue
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

                    # 4d-pre: For method calls, check if the callee's member chain
                    # root is a registered framework source (e.g. request.input,
                    # $request.query).  If so, the return value is controllable —
                    # no need to trace into the (unresolvable) framework method.
                    if (utype in ("method_call", "static_call")
                            and self._source_registry is not None):
                        _callee_vid = None
                        for _ae in self._edge_out(up_vid, "ast"):
                            if _vattr(_ae, "role") == "callee":
                                _callee_vid = _ae.target
                                break
                        if _callee_vid is not None:
                            _src_chain = self._is_source_via_member_chain(
                                _callee_vid, callee)
                            if _src_chain:
                                return self._cached(cache_key, AnalysisResult(
                                    code=1,
                                    reason=f"framework source '{_src_chain}'",
                                    chain=[{"step": "framework_source",
                                            "vid": up_vid,
                                            "name": _src_chain, "code": 1}],
                                    path=new_path,
                                    expr_lineno=_vattr(uv, "lineno", 0)))

                    # 4d: graph-based function trace (unknown or no taint attribute)
                    # Skip if use-edge already resolved the callee — re-searching by
                    # short-name search would match unrelated same-named methods across classes.
                    # BUT: if use-edge found a placeholder node (no taint annotation),
                    # still try find_function_def to locate the real definition.
                    # Fix 42g: also admit PASSTHROUGH callees.  The positional
                    # passthrough summary ([1] for GetPayload) only covers the
                    # $default fallback arg; when every pt arg traces
                    # inconclusive (e.g. GetPayload('src_by', []) → array()),
                    # the real taint route is the function BODY's receiver
                    # member read ($this->payload[$key]) — reachable only via
                    # analyze_function_return.  Arriving here already means no
                    # pt arg was controllable (4c returns immediately on
                    # controllable), so the body trace can only add signal.
                    # Fix 42v: preg_replace with a whitelist charset-strip
                    # pattern ('#[^a-z0-9@ _\-\.]#i') is a sanitizer — the
                    # output only contains characters from the class, so no
                    # attacker-controlled metacharacters survive.  Detect
                    # BEFORE the general function trace so the call's DFG
                    # upstream (the tainted subject) is NOT followed.
                    if (callee == "preg_replace"
                            and self._preg_replace_whitelist_pattern(up_vid)):
                        return self._cached(cache_key, AnalysisResult(
                            code=2,
                            reason="whitelist charset strip (preg_replace "
                                   "negated-charclass pattern) sanitizes input",
                            chain=[{"step": "sanitizer", "vid": up_vid,
                                    "name": "preg_replace", "code": 2}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))
                    if callee and callee not in self._call_stack and (
                            func_vid is None or not func_taint
                            or func_taint == "passthrough"):
                        # Prefer the use-edge-resolved func_vid when available —
                        # it's the precise target of this call.  Only fall back
                        # to short-name search when no use-edge target exists.
                        # Fix 42f: PHP method calls often bind their use edge
                        # to a bare-name placeholder stub (no taint, no body)
                        # while the real definition — an inherited base-class
                        # method like Apbd_Wps_APIBase.GetPayload — carries the
                        # passthrough/safe annotation.  When the use-edge
                        # target is an unannotated empty shell, also search by
                        # short name and prefer an annotated definition;
                        # identical-arity same-file defs still win (overloads).
                        if func_vid is not None:
                            _fv_is_shell = not func_taint and not any(
                                True for _pe in self.graph.es.select(
                                    _source=func_vid, label="own")
                                if _vattr(self.graph.vs[_pe.target], "label", "")
                                in ("return", "parameter"))
                            if _fv_is_shell and self.language == "php":
                                # callee may be receiver-qualified ('$this.
                                # GetPayload') — strip to the bare method
                                # name for the definition search.
                                _bare = callee.rsplit(".", 1)[-1]
                                _extra = [fv for fv in self.find_function_def(
                                    _bare, from_vid=up_vid)
                                    if fv != func_vid
                                    and _vattr(self.graph.vs[fv], "taint_type", "")]
                                if _extra:
                                    func_vid = _extra[0]
                                    func_taint = _vattr(
                                        self.graph.vs[func_vid], "taint_type", "")
                            func_vids = [func_vid]
                        else:
                            func_vids = self.find_function_def(callee, from_vid=up_vid)
                        if func_vids:
                            # 引用参数（如 &$option）的值来自调用者，
                            # analyze_function_return 会从 return 值追溯函数内部
                            # 导致调用者变量通过引用参数的错误跨参数 taint 传播。
                            _has_ref_param = any(
                                _vattr(self.graph.vs[pv], "is_reference", "")
                                for pv in self._esrc.get("own", {}).get(func_vids[0], [])
                                if _vattr(self.graph.vs[pv], "label", "") == "parameter"
                            )
                            if _has_ref_param:
                                # Treat like inconclusive: stop taint propagation
                                if inconclusive_fallback is None:
                                    inconclusive_fallback = AnalysisResult(
                                        code=3,
                                        reason=f"function '{callee}' has reference param — skip inline return trace",
                                        chain=[{"step": "ref_param_skip", "vid": up_vid,
                                                "name": callee, "code": 3}],
                                        path=new_path,
                                        expr_lineno=_vattr(uv, "lineno", 0))
                                continue
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
                            # Rule 4d-2: if analyze_function_return returned
                            # inconclusive because the function def is an
                            # empty shell (no return nodes, no params), this
                            # is an unresolved external/framework method call.
                            # Its return value should NOT inherit taint from
                            # its call arguments — doing so causes false
                            # positives where e.g. $entity = $repo->find($id)
                            # inherits taint from $id (which traces back to
                            # $request) even though find() queries the
                            # database and returns a fresh object.
                            if (ret.code == 3 and func_vid is not None
                                    and not ret.reason.startswith("No return")):
                                pass  # has return nodes but inconclusive — allow fallthrough
                            elif ret.code == 3 and func_vid is not None:
                                # Empty shell: no return, no params, no taint
                                # annotation. Stop taint propagation through
                                # this call's DFG upstream.
                                if inconclusive_fallback is None:
                                    inconclusive_fallback = AnalysisResult(
                                        code=3,
                                        reason=f"unresolved method '{callee}' — return inconclusive",
                                        chain=[{"step": "unresolved_method", "vid": up_vid,
                                                "name": callee, "code": 3}],
                                        path=new_path,
                                        expr_lineno=_vattr(uv, "lineno", 0))
                                continue  # skip DFG upstream of this call node

                    # Rule 4e: unknown function call — the callee is not in
                    # builtin_knowledge and analyze_function_return was
                    # inconclusive.  Don't continue BFS through this call
                    # operator's DFG upstream (function arguments are NOT
                    # automatically the return value's data-flow source).
                    # This prevents false positives where an unknown lookup
                    # function (e.g. getItem(userKey)) causes the key's taint
                    # to propagate to the return value.
                    if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES and crossed_function_boundary:
                        # Check both callee short name and qualified op_name
                        # against builtin_knowledge to avoid false positives
                        # on known functions like os.path.join.
                        _op_name = _vattr(uv, "name", "")
                        _known = self._is_known_callee(callee) or self._is_known_callee(_op_name)
                        # If callee came from an ambiguous alias (multiple
                        # different resolved_names), don't trust it as known
                        # — the real callee might be different.
                        if _known and callee:
                            for ue in self._edge_out(up_vid, "use"):
                                _an = set()
                                for ae in self._edge_out(ue.target, "alias"):
                                    rn = _vattr(ae, "resolved_name", "")
                                    if rn and " " not in rn:
                                        _an.add(rn)
                                if len(_an) > 1:
                                    _known = False
                                    break
                        if not _known:
                            if inconclusive_fallback is None:
                                inconclusive_fallback = AnalysisResult(
                                    code=3,
                                    reason=f"unknown function '{callee}' — return inconclusive",
                                    chain=[{"step": "unknown_func", "vid": up_vid,
                                            "name": callee, "code": 3}],
                                    path=new_path,
                                    expr_lineno=_vattr(uv, "lineno", 0))
                            continue  # skip DFG upstream of this call node

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
                        # Scope gate: skip if no shared branch with start,
                        # EXCEPT when the BFS already crossed a function
                        # boundary (Fix 20a): the caller-side guard branch
                        # wraps the *argument* node feeding the callee —
                        # e.g. if(path_is_safe($target)) { delete_folder(
                        # $target); } — and the sink lives in a different
                        # file, so branch chains can never intersect there.
                        if not (set(cur_branch_chain) & sink_branch_set) \
                                and not crossed_function_boundary:
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
                        member_edges = list(self._edge_in(cur_member, "member"))
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
                            # Subscript key of non-superglobal (e.g., $arr[$_GET['x']])
                            if self._is_subscript_key_of_non_superglobal(obj_vid):
                                break
                            # If this node was sanitized by a safe-function
                            # reassignment, its taint_type was changed from
                            # 'source' to 'safe' by enrich_taint.
                            if _vattr(obj_v, "taint_type", "") == "safe":
                                break
                            # Function-level guard: superglobal member may be
                            # validated by a whitelist guard in an enclosing
                            # branch — check before reporting member source.
                            _gname = (self._extract_member_key(obj_vid)
                                      or obj_name).strip("'\"")
                            if self.language in ("python", "php") and _gname and \
                                    self._has_function_level_guard(start_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=f"source '{obj_name}[{_gname}]' guarded by function-level validation",
                                    chain=[{"step": "source_guard", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=new_path + [obj_vid],
                                    expr_lineno=_vattr(obj_v, "lineno", 0)))
                            if self._has_path_jail_guard(obj_vid, _gname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=(f"source '{obj_name}[{_gname}]' jailed by "
                                            f"path-traversal blacklist guard (strpos+die)"),
                                    chain=[{"step": "path_jail", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=new_path + [obj_vid],
                                    expr_lineno=_vattr(obj_v, "lineno", 0)))
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"superglobal '{obj_name}' via member access",
                                chain=[{"step": "member_source", "vid": obj_vid,
                                        "name": obj_name, "code": 1}],
                                path=new_path + [obj_vid],
                                expr_lineno=_vattr(obj_v, "lineno", 0)))
                        if obj_label == NodeLabel.IDENTIFIER.value and obj_type in ("field", "property"):
                            cur_member = obj_vid
                            continue
                        # Fix 43b: stored-XSS DB bridge from the BFS path —
                        # the member walk dead-ended at a non-superglobal
                        # object (e.g. foreach row var $h in $h->nama).
                        # Try the db->insert/db->get table bridge; guards
                        # inside _db_table_bridge_source (same-function
                        # foreach sibling, same-file insert data var,
                        # same-key superglobal write) provide precision.
                        if self.language == "php" and depth < max_depth - 1:
                            _p43 = self._db_table_bridge_source(
                                cur_member,
                                _vattr(self.graph.vs[cur_member], "name", ""))
                            if _p43 is not None and _p43.code == 1:
                                _p43.path = new_path + (_p43.path or [])
                                return self._cached(cache_key, _p43)
                        break

        start_fp = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        # ── Fix 43c: CodeIgniter view bridge (stored/echo XSS final hop) ──
        # View files (e.g. views/contact/bg_home.php) receive their variables
        # through $this->load->view('contact/bg_home', $d) — no DFG crosses
        # that boundary, so `echo $data_retrieve` in the view dead-ends even
        # when the controller stored a tainted value at $d['data_retrieve'].
        # When the start node is a view-file variable with no DFG in-edge,
        # locate the loader call whose view name matches this file and pb()
        # the same-key array write in the controller.
        if (self.language == "php" and start_fp
                and _vattr(sv, "label", "") == NodeLabel.IDENTIFIER.value
                and _vattr(sv, "type", "") == "variable"
                and not self._get_dfg_sources(start_vid)
                and not getattr(self, "_in_view_bridge", False)):
            _v43c = self._ci_view_bridge_source(start_vid, _vattr(sv, "name", ""))
            if _v43c is not None and _v43c.code == 1:
                return self._cached(cache_key, _v43c)

        # Before returning Inconclusive, try "same-name variable def-chaining":
        # SSA-like graphs create separate identifier nodes per assignment.
        # When $target = str_replace(..., $target) forms a DFG cycle, BFS
        # visits vid=14953→14954→14960→14953 and exhausts without reaching
        # vid=14947 ($target = $_REQUEST['ip'], the real source).
        # Fix: collect all identifier names in visited, find same-name
        # identifier nodes in the same file not in visited, and recursively
        # check if they lead to a controllable source.
        # Fix 42l: PHP foreach use-points have NO dfg in-edge (the graph
        # only links the foreach-header def site), so the BFS exhausts at
        # depth 0 (visited == {start}) and never reaches the def-chain
        # below.  Admit a single-node visited set for identifier starts —
        # the def-chain's own guards (same file/function, earlier line,
        # branch scope, SSA-kill, loop-admit 42k) provide the precision.
        _defchain_min_visited = 1 if self.language == "php" else 3
        if start_fp and len(visited) >= _defchain_min_visited:
            if not hasattr(self, "_in_defchain_fallback"):
                self._in_defchain_fallback = False
            # Collect identifier names encountered during BFS
            visited_idents: dict[str, list[int]] = {}
            for up_vid in visited:
                uv = self.graph.vs[up_vid]
                if _vattr(uv, "label") != NodeLabel.IDENTIFIER.value:
                    continue
                # Skip safe-tainted identifiers — already sanitized
                if _vattr(uv, "taint_type", "") == "safe":
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
                    # Line-number constraint: a variable at the sink position
                    # can only receive values from assignments that appear
                    # BEFORE it in the source code (lower line number).
                    cand_lineno = _vattr(self.graph.vs[cand], "lineno", 0)
                    start_lineno = _vattr(self.graph.vs[start_vid], "lineno", 0)
                    if start_lineno > 0 and cand_lineno > start_lineno:
                        continue
                    # Function scope check: def-chain should not cross
                    # function boundaries. Variables with the same name
                    # in different functions are unrelated.
                    cand_func = self._get_enclosing_func_vid(cand)
                    start_func = self._get_enclosing_func_vid(start_vid)
                    if cand_func is not None and start_func is not None:
                        if cand_func != start_func:
                            continue
                    elif cand_func is None or start_func is None:
                        # Cannot determine function scope for one or both
                        # nodes.  In Go, the normalizer doesn't connect
                        # receiver identifiers in closures to their
                        # enclosing function via own/ast edges — def-
                        # chaining across functions is the #1 source of
                        # FP, so skip conservatively.  In other languages
                        # (PHP/JS/Java), fall back to line-distance heuristic
                        # because variables in global scope or short scripts
                        # may legitimately lack own/ast parents.
                        if self.language == "go":
                            continue
                        if abs(cand_lineno - start_lineno) > 200:
                            continue
                    # SSA kill check: if a same-name variable is re-defined
                    # between the candidate and the sink, the candidate's
                    # data flow is broken (killed by the re-definition).
                    continue_outer = False
                    # Fix 42m: PHP foreach iteration variables are re-bound
                    # by the loop itself on every iteration — same-name
                    # nodes INSIDE the loop body are USE points, not kills
                    # (there is no explicit re-assignment).  When the
                    # candidate's innermost branch is the foreach header
                    # owning this binding, skip the kill check entirely.
                    _cand_chain0 = self.get_branch_chain(cand)
                    _loop_owner = bool(
                        _cand_chain0
                        and self.language == "php"
                        and (_vattr(self.graph.vs[_cand_chain0[0]], "type", "") or "").lower()
                        in ("foreach", "for", "while"))
                    if not _loop_owner:
                        # Fix 42p: the 42n recursion loses the ORIGINAL use
                        # point's line — an inner def-chain hop links defs
                        # that were killed by defs BETWEEN the outer use and
                        # the inner start (variable reuse, hms doctor-panel
                        # L332 const $query chained back to L9 $_GET).
                        # Track the outermost use line during the recursion
                        # and use it as the SSA interval bound.
                        _upper = start_lineno
                        _outer = getattr(self, "_defchain_outer_use", None)
                        if _outer is not None and _outer > _upper:
                            _upper = _outer
                        # Fix 42r: a same-name node is a KILL witness only
                        # if it is the LHS of a real assignment whose RHS
                        # does NOT reference the same variable.  Plain USE
                        # points (foreach bodies, mysqli_query args) rebind
                        # nothing; flow-through reassignments ($x = f($x))
                        # propagate rather than kill.  Without this, nodes
                        # visited by the BFS (the reaching def itself) were
                        # exempted via `in visited` and variable-reuse
                        # chained across redefinitions (hms doctor-panel
                        # L332→L280→L186 all named $query).
                        def _snv_kills(snv: int) -> bool:
                            assign_vid = None
                            snv_v = self.graph.vs[snv]
                            if (_vattr(snv_v, "label", "") == NodeLabel.OPERATOR.value
                                    and _vattr(snv_v, "type", "") == "assign"):
                                assign_vid = snv
                            else:
                                for pe in self._edge_in(snv, "ast"):
                                    pv = self.graph.vs[pe.source]
                                    if (_vattr(pv, "label", "") == NodeLabel.OPERATOR.value
                                            and _vattr(pv, "type", "") == "assign"
                                            and _vattr(pe, "role", "") == "lhs"):
                                        assign_vid = pe.source
                                        break
                            if assign_vid is None:
                                return False  # plain use point, not a kill
                            # RHS subtree must not reference the same name
                            # (flow-through like `$x = f($x)` is not a kill)
                            stack = [assign_vid]
                            seen_s = {assign_vid}
                            for _ in range(200):
                                if not stack:
                                    break
                                cur = stack.pop()
                                for ce in self._edge_out(cur, "ast"):
                                    if _vattr(ce, "role", "") == "lhs":
                                        continue
                                    if ce.target in seen_s:
                                        continue
                                    seen_s.add(ce.target)
                                    cv2 = self.graph.vs[ce.target]
                                    if (_vattr(cv2, "label", "") == NodeLabel.IDENTIFIER.value
                                            and _vattr(cv2, "name", "") == u_name):
                                        return False  # flow-through
                                    stack.append(ce.target)
                            return True

                        for snv in self._nname.get(
                                (NodeLabel.IDENTIFIER.value, u_name), []):
                            if snv == cand or snv in checked:
                                continue
                            snv_fp = _vattr(self.graph.vs[snv], "file_path", "") or _vattr(self.graph.vs[snv], "path", "")
                            if snv_fp and snv_fp != start_fp:
                                continue
                            snv_lineno = _vattr(self.graph.vs[snv], "lineno", 0)
                            if cand_lineno < snv_lineno < _upper:
                                snv_func = self._get_enclosing_func_vid(snv)
                                shared_func = cand_func or start_func
                                if shared_func is not None and snv_func is not None and snv_func != shared_func:
                                    continue
                                if not _snv_kills(snv):
                                    continue
                                # Re-definition found between candidate and sink
                                continue_outer = True
                                break
                    if continue_outer:
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
                            # Fix 42k: PHP foreach loop variables.  A use
                            # inside a nested if/else (branch chain stops at
                            # the else — negated branches don't inherit the
                            # parent if) shares no ancestor with the foreach
                            # def site, yet the iteration variable IS the
                            # foreach's value binding.  Admit the candidate
                            # when: same function, candidate line strictly
                            # earlier, and the candidate's innermost branch
                            # is a loop-shaped branch (foreach/for/while)
                            # whose header lexically encloses earlier lines.
                            _admit = False
                            if (cand_chain and self.language == "php"
                                    and cand_func is not None
                                    and cand_func == start_func):
                                _inner = self.graph.vs[cand_chain[0]]
                                _ibtype = (_vattr(_inner, "type", "") or "").lower()
                                if _ibtype in ("foreach", "for", "while"):
                                    _admit = True
                            if not _admit:
                                continue
                    # Check if this candidate has DFG sources to trace
                    if self._get_dfg_sources(cand):
                        # Use _trace_dfg_direct to avoid recursive
                        # parameters_back calling def-chain again
                        r = self._trace_dfg_direct(cand, max_depth=20, file_path=start_fp)
                        # Fix 42n: the weak tracer resolves only raw dfg
                        # chains — it does not follow method-call returns
                        # (foreach var ← GetPayload(...) ← $this->payload ←
                        # $_POST).  On a None outcome, fall back to ONE
                        # full parameters_back recursion guarded by an
                        # anti-reentry flag; the def-chain's own scope
                        # guards keep the recursion bounded.
                        # Fix 42q: gate the recursion to LOOP-OWNED
                        # candidates (foreach/for/while iteration vars).
                        # Plain variable reuse (hms doctor-panel $query
                        # redefined at L9/L278/L331) must NOT chain defs
                        # across reassignments — that's the SSA-kill
                        # contract, and the weak tracer's None there is
                        # the CORRECT inconclusive answer.
                        if (r is None and _loop_owner
                                and not self._in_defchain_fallback):
                            self._in_defchain_fallback = True
                            _saved_outer = getattr(self, "_defchain_outer_use", None)
                            if _saved_outer is None or start_lineno > _saved_outer:
                                self._defchain_outer_use = start_lineno
                            try:
                                sub_r = self.parameters_back(cand, context_vid=None,
                                                             max_depth=max_depth - 10)
                            finally:
                                self._in_defchain_fallback = False
                                self._defchain_outer_use = _saved_outer
                            if sub_r is not None and sub_r.is_controllable:
                                # Fix 42w: field-store kill — a sanitized
                                # per-field store (e.g. $b['val'] =
                                # preg_replace(...)) between this candidate
                                # def and the sink use means the sink reads
                                # the NEW field value, not the candidate's
                                # old container taint. The store lhs is
                                # taint=safe (enrich_taint) and its line
                                # sits strictly between cand and sink.
                                if self._defchain_field_store_killed(
                                        cand, start_vid, u_name):
                                    continue
                                return self._cached(cache_key, AnalysisResult(
                                    code=1,
                                    reason=f"def-chain '{u_name}' → {sub_r.reason}",
                                    chain=sub_r.chain,
                                    path=sub_r.path,
                                    expr_lineno=sub_r.expr_lineno))
                        if r is not None and r.is_controllable:
                            if self._defchain_field_store_killed(
                                    cand, start_vid, u_name):
                                continue
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"def-chain '{u_name}' → {r.reason}",
                                chain=r.chain,
                                path=r.path,
                                expr_lineno=r.expr_lineno))

        # Exhausted
        if inconclusive_fallback is not None:
            return self._cached(cache_key, inconclusive_fallback)
        if param_fallback is not None:
            return self._cached(cache_key, param_fallback)
        if repaired_result is not None:
            return self._cached(cache_key, repaired_result)
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
        for ae in self._edge_out(call_vid, "ast"):
            if _vattr(ae, "role") == "arg":
                callee_arg_vids.add(ae.target)
        for e in self._edge_in(call_vid, "dfg"):
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
        for e in self._edge_out(call_vid, "ast"):
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
            for e in self._edge_in(current, "member"):
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


    def _java_field_store_sources(self, read_vid: int) -> list[tuple[int, int]]:
        """Fix 37a: Java field-load propagation (constructor-write ->
        getter-read).  The java normalizer emits a shared field-declaration
        node (label=function, lineno=0) as the *use* hub for every
        this.<field> access in the class.  Given a this.<field> READ
        (method_call node), find all WRITE points (assign LHS of the same
        field) and return [(rhs_vid, write_func_vid), ...] so the caller
        can trace each stored value.  Scoped to same class (same field
        decl via use edges) -- no cross-class guessing."""
        v = self.graph.vs[read_vid]
        if _vattr(v, "type", "") != "method_call":
            return []
        base_ids = [e.source for e in self._edge_in(read_vid, "member")
                    if (_vattr(self.graph.vs[e.source], "name", "") or "") == "this"]
        if not base_ids:
            return []
        for e in self._edge_in(read_vid, "ast"):
            if _vattr(e, "role", "") == "lhs":
                return []
        decl_vids = [e.target for e in self._edge_out(read_vid, "use")
                     if _vattr(self.graph.vs[e.target], "label", "") == NodeLabel.FUNCTION.value
                     and not int(_vattr(self.graph.vs[e.target], "lineno", 0) or 0)]
        if not decl_vids:
            return []
        decl = decl_vids[0]
        results: list[tuple[int, int]] = []
        for e in self._edge_in(decl, "use"):
            w = e.source
            wv = self.graph.vs[w]
            if _vattr(wv, "type", "") != "method_call":
                continue
            for ae in self._edge_in(w, "ast"):
                if _vattr(ae, "role", "") != "lhs":
                    continue
                assign_vid = ae.source
                for re_ in self._edge_out(assign_vid, "ast"):
                    if _vattr(re_, "role", "") == "rhs":
                        wfunc = None
                        for oe in self._edge_in(assign_vid, "own"):
                            pn = self.graph.vs[oe.source]
                            if _vattr(pn, "label", "") == NodeLabel.FUNCTION.value:
                                wfunc = oe.source
                                break
                        results.append((re_.target, wfunc if wfunc is not None else assign_vid))
        return results


    def _resolve_java_param_deps(self, dep_names: list[str], writer_func_vid: int,
                                 max_depth: int) -> "AnalysisResult | None":
        """Fix 37a-2: dep names that are the writer function's formal
        params -- resolve each through the writer's call sites (cg in
        edges), taking the actual arg vid at each site and tracing it."""
        param_by_name: dict[str, int] = {}
        for pvid in self._find_own_children(writer_func_vid, child_label=NodeLabel.PARAMETER.value):
            pn = _vattr(self.graph.vs[pvid], "name", "")
            if pn:
                param_by_name[pn] = pvid
        param_list = sorted(param_by_name.items(), key=lambda kv: kv[1])
        for dn in (dep_names or []):
            if dn not in param_by_name:
                continue
            pidx = None
            for i, (pn, pvid) in enumerate(param_list):
                if pn == dn:
                    pidx = _vattr(self.graph.vs[pvid], "index", i)
                    try:
                        pidx = int(pidx) if str(pidx) != "" else i
                    except (TypeError, ValueError):
                        pidx = i
                    break
            _call_sites: list[int] = []
            for ce in self._edge_in(writer_func_vid, "cg"):
                call_vid = ce.source
                if _vattr(self.graph.vs[call_vid], "label", "") == NodeLabel.OPERATOR.value:
                    _call_sites.append(call_vid)
            if not _call_sites:
                # Fix 37a-2b: constructor call sites may connect via use
                # edges (new T references the constructor def) instead of cg.
                for ue in self._edge_in(writer_func_vid, "use"):
                    call_vid = ue.source
                    if _vattr(self.graph.vs[call_vid], "label", "") == NodeLabel.OPERATOR.value:
                        _call_sites.append(call_vid)
            for call_vid in _call_sites:
                for ae in self._edge_out(call_vid, "ast"):
                    if _vattr(ae, "role", "") != "arg":
                        continue
                    aidx = _vattr(ae, "index", None)
                    try:
                        aidx_i = int(aidx) if aidx is not None and str(aidx) != "" else None
                    except (TypeError, ValueError):
                        aidx_i = None
                    if pidx is not None and aidx_i is not None and aidx_i != int(pidx):
                        continue
                    sub = self.parameters_back(ae.target, max_depth=max_depth)
                    if sub is not None and sub.is_controllable:
                        return sub
        return None


    _JAVA_ACCUM_READS = frozenset({
        "toString", "toStringBuilder", "build", "getBuffer", "string",
        "value", "getQuery", "getSql", "getText", "getBody",
    })
    _JAVA_ACCUM_WRITES = frozenset({"write", "append", "add", "put",
                                    "addBatch", "concat", "insert", "addSql"})

    def _java_accum_read_sources(self, read_call_vid: int) -> list[tuple[int, int]]:
        """Fix 38: Java accumulator-object flow (write-side -> read-side).

        Builder/Writer objects accumulate fragments via mutating calls
        (write/append/...) whose ARGUMENTS carry taint; the assembled
        string is read back via toString()/build()/... on the same
        receiver.  The graph gives each such call a dotted full name
        ('this.out.write'), so read and write calls of the same
        accumulator share the dotted prefix.  Match on that prefix,
        take each write's non-constant dfg arg as a taint source.
        Same-file only; constant fragments contribute nothing."""
        rv = self.graph.vs[read_call_vid]
        if _vattr(rv, "type", "") not in ("method_call", "static_call"):
            return []
        rname = (_vattr(rv, "name", "") or "")
        rparts = rname.split(".")
        rshort = rparts[-1].strip("'\"")
        if rshort not in self._JAVA_ACCUM_READS or len(rparts) < 2:
            return []
        rprefix = ".".join(rparts[:-1])
        read_file = _vattr(rv, "file_path", "") or ""
        results: list[tuple[int, int]] = []
        for w in self._nlbl.get(NodeLabel.OPERATOR.value, []):
            wv = self.graph.vs[w]
            wname = (_vattr(wv, "name", "") or "")
            wparts = wname.split(".")
            if len(wparts) < 2:
                continue
            wshort = wparts[-1].strip("'\"")
            if wshort not in self._JAVA_ACCUM_WRITES:
                continue
            if ".".join(wparts[:-1]) != rprefix:
                continue
            wf = _vattr(wv, "file_path", "") or ""
            if wf and read_file and wf != read_file:
                continue
            wfunc = None
            for oe in self._edge_in(w, "own"):
                pn = self.graph.vs[oe.source]
                if _vattr(pn, "label", "") == NodeLabel.FUNCTION.value:
                    wfunc = oe.source
                    break
            for de in self._edge_in(w, "dfg"):
                av = self.graph.vs[de.source]
                if _vattr(av, "label", "") == NodeLabel.CONST.value:
                    continue
                aname = (_vattr(av, "name", "") or "")
                if aname == rprefix:
                    continue  # receiver node itself
                results.append((de.source, wfunc if wfunc is not None else w))
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
        depth_guard_43g: set[str] = set()

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
        for e in self._edge_out(call_vid, "ast"):
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
            for e in self._edge_out(ret_vid, "ast"):
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
            if not sub.is_controllable:
                # Fix 42j: PHP ternary returns render as a branch node
                # whose BFS doesn't descend into iftrue/iffalse children
                # (e.g. GetPayload: !empty($this->payload[$key]) ?
                # $this->payload[$key] : $default).  Trace each ast
                # sub-branch directly — any controllable arm makes the
                # return controllable.
                if _vattr(ev, "label") == NodeLabel.BRANCH.value or _vattr(ev, "type") in ("ternary", "if"):
                    for be in self._edge_out(expr_vid, "ast"):
                        if _vattr(be, "role") not in ("iftrue", "iffalse", "value"):
                            continue
                        arm = self.parameters_back(be.target, context_vid=func_vid, max_depth=20)
                        if arm.is_controllable:
                            return arm
            if sub.is_controllable:
                return sub
            if sub.has_deps:
                caller_deps.extend(sub.deps)

            # Fix 43g: SSA break fallback — `return $x` where the return's
            # $x node has no dfg in-edge (foreach-built values link their
            # aug_assign rhs subtrees, not the return use-site).  Retry via
            # every same-name variable's assign/aug_assign RHS inside this
            # function; the rhs subtree is where stored-XSS table bridges
            # and view bridges fire.  (CVI-115534: generate_index_contact
            # returns $hasil but only the L867 concat rhs carries taint.)
            if ename and ename not in depth_guard_43g:
                depth_guard_43g.add(ename)
                fn_fp = _vattr(self.graph.vs[func_vid], "file_path", "") or ""
                fn_ln0 = _vattr(self.graph.vs[func_vid], "lineno", 0)
                for sib in self._nname.get(("identifier", ename), []):
                    svv = self.graph.vs[sib]
                    if (_vattr(svv, "file_path", "") or "") != fn_fp:
                        continue
                    _ln = _vattr(svv, "lineno", 0) or 0
                    if _ln < (fn_ln0 or 0):
                        continue
                    for le in self._edge_in(sib, "ast"):
                        if _vattr(le, "role", "") != "lhs":
                            continue
                        av = self.graph.vs[le.source]
                        if _vattr(av, "type", "") not in ("assign", "aug_assign"):
                            continue
                        for re_ in self._edge_out(le.source, "ast"):
                            if _vattr(re_, "role", "") != "rhs":
                                continue
                            r43g = self.parameters_back(re_.target, context_vid=func_vid, max_depth=20)
                            if r43g is not None and r43g.is_controllable:
                                r43g.reason = (f"return '{ename}' ← same-name "
                                               f"assign rhs: {r43g.reason}")
                                return r43g

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
            for e in self._edge_out(cur_vid, "dfg"):
                tgt = e.target
                if tgt not in visited:
                    visited.add(tgt)
                    queue.append((tgt, depth + 1, path + [tgt]))
        return results

    # --- Internal helpers -------------------------------------------------

    # ── Fix 43i: O(deg) adjacency index (built lazily once) ──────────
    # igraph's es.select(_source=X, label=L) scans ALL edges — O(E) per
    # query.  The stored-XSS bridges (Fix 43) fire hundreds of such
    # queries per sink, turning a 5-minute scan into 80+ minutes.  Build
    # outgoing/incoming maps keyed by (label, vid) ONCE and reuse.
    def _edge_out(self, vid: int, label: str):
        idx = getattr(self, "_adj_out", None)
        if idx is None:
            idx = {}
            for _e in self.graph.es:
                idx.setdefault((_e["label"], _e.source), []).append(_e)
            self._adj_out = idx
        return idx.get((label, vid), ())

    def _edge_in(self, vid: int, label: str):
        idx = getattr(self, "_adj_in", None)
        if idx is None:
            idx = {}
            for _e in self.graph.es:
                idx.setdefault((_e["label"], _e.target), []).append(_e)
            self._adj_in = idx
        return idx.get((label, vid), ())

    def _cached(self, key, result: AnalysisResult) -> AnalysisResult:
        # Fix 20b: when a pinned concat was traversed on the way to a CTRL
        # decision, remember it.  The verdict itself is resolved by the
        # two-pass logic at the Exhausted block of _parameters_back_impl
        # (path-sensitive: a surviving fully-controlled path stays code=1).
        pin_vids = getattr(self, "_redirect_pin_vids", None)
        if (getattr(self, "_redirect_pin_ctx", False) and result is not None
                and result.code == 1 and pin_vids):
            result._redirect_pinned_seen = bool(pin_vids)
        self._decision_cache[key] = result
        return result

    # ── Fix 42: cross-file property store→load chaining ──────────────────
    #
    # Graph reality: `$this->prop = X` in file A and `$this->prop` read in
    # file B create disjoint property nodes (dfg builder intentionally
    # skips self/this member edges).  This fallback connects a property
    # READ in the reader file to property WRITES (assign lhs) stored in
    # another file, then traces the stored value to a controllable source
    # with _trace_dfg_direct.
    #
    # Precision guards (all must hold):
    #   G1. reader and writer are in DIFFERENT files
    #   G2. property names match exactly
    #   G3. the writer's enclosing class and the reader's enclosing class
    #       are connected by an extends relationship (either direction) —
    #       resolved via class nodes' inherits_from attr / crg edges, with
    #       a same-identifier fallback when class nodes are unavailable
    #   G4. the writer's stored value actually reaches a controllable
    #       source (bounded _trace_dfg_direct, no parameters_back recursion)
    #   G5. the property write is not inside a constructor whitelist guard
    #       (Fix 21h-3 family) — reuse existing guards by keeping this a
    #       plain source search; guards evaluate inside _trace_dfg_direct.
    def _cross_file_property_source(self, start_vid: int, prop_name: str):
        if not prop_name:
            return None
        sv = self.graph.vs[start_vid]
        reader_fp = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        if not reader_fp:
            return None

        reader_class = self._get_enclosing_class_name(start_vid)
        reader_file_classes = self._file_class_names(reader_fp)

        # Iterate same-name property nodes across the whole graph.
        for cand in self._nname.get(("identifier", prop_name), []):
            if cand == start_vid:
                continue
            cv = self.graph.vs[cand]
            if _vattr(cv, "type", "") not in ("field", "property"):
                continue
            cand_fp = _vattr(cv, "file_path", "") or _vattr(cv, "path", "")
            if not cand_fp:
                continue
            same_file = (cand_fp == reader_fp)
            # G1: cross-file is the primary (SSA-split) case.  Fix 42i:
            # same-file reader/writer pairs (store in LoadPayload L58,
            # read in GetPayload L83 — both inside Apbd_Wps_APIBase.php)
            # are EQUALLY valid property flows; the dfg builder skips
            # this/self member edges there too.  Admit them, but under a
            # stricter contract: G3 inheritance must hold via the
            # resolved enclosing classes (no file-level fallback, which
            # would be vacuous inside one file).
            if same_file and not self._classes_inherit(
                    reader_class, self._get_enclosing_class_name(cand)):
                continue  # G1'
            # must be a WRITE: has an assign parent via ast[lhs]
            is_write = False
            rhs_vid = None
            for e in self._edge_in(cand, "ast"):
                if _vattr(e, "role") != "lhs":
                    continue
                op = self.graph.vs[e.source]
                if (_vattr(op, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(op, "type", "") == OperatorType.ASSIGN.value):
                    is_write = True
                    for re_ in self.graph.es.select(
                            _source=e.source, label="ast"):
                        if _vattr(re_, "role") == "rhs":
                            rhs_vid = re_.target
                            break
                    break
            if not is_write or rhs_vid is None:
                continue
            # G3: inheritance link between reader class and writer class.
            writer_class = self._get_enclosing_class_name(cand)
            if not self._classes_inherit(reader_class, writer_class):
                # Fallback: writer file declares a class the reader extends,
                # or vice versa (helps when enclosing-class resolution
                # failed for one side, e.g. trait/abstract shapes).
                writer_file_classes = self._file_class_names(cand_fp)
                linked = bool(
                    (reader_file_classes & writer_file_classes)
                    or (writer_class and writer_class in reader_file_classes)
                    or (reader_class and reader_class in writer_file_classes)
                )
                if not linked:
                    continue
            # G4: does the stored value derive from a controllable source?
            # Three passes:
            #   a) subtree scan of the assign RHS for any superglobal read
            #      (catches `$_POST[...]` stored directly through wrappers)
            #   b) static/var def-chain: the RHS is often a plain static or
            #      variable read (`$this->payload = &self::$payload_obj`).
            #      Find same-name assign-lhs nodes in the writer's file and
            #      subtree-scan THOSE rhs values — catches branch-merged
            #      stores (if-branch stores $_POST via json_decode, else
            #      branch stores php://input, merged read later)
            #   c) bounded dfg trace as fallback (catches stores whose
            #      source enters via intermediate variables)
            hit = self._store_value_hits_superglobal(rhs_vid)
            if not hit:
                hit = self._same_name_store_hits_superglobal(rhs_vid)
            if hit:
                return AnalysisResult(
                    code=1,
                    reason=(f"cross-file property store '{prop_name}' → "
                            f"superglobal '{hit}' via member access"),
                    chain=[{"step": "xfile_prop_store", "vid": cand,
                            "name": prop_name, "code": 1}],
                    path=[start_vid, cand, rhs_vid],
                    expr_lineno=_vattr(sv, "lineno", 0))
            r = self._trace_dfg_direct(rhs_vid, max_depth=20)
            if r is not None and r.is_controllable:
                return AnalysisResult(
                    code=1,
                    reason=(f"cross-file property store '{prop_name}' → {r.reason}"),
                    chain=[{"step": "xfile_prop_store", "vid": cand,
                            "name": prop_name, "code": 1}] + (r.chain or []),
                    path=[start_vid, cand] + (r.path or []),
                    expr_lineno=_vattr(sv, "lineno", 0))
        return None

    # ── Fix 43: stored-XSS DB table bridge ──────────────────────────────
    #
    # Graph reality: stored-XSS splits source and sink across a database.
    #   WRITE: contact.php kirim() { $in['nama'] = $_POST['nama'];
    #                                 $this->db->insert('dlmbg_contact', $in); }
    #   READ:  app_global_admin_model.php generate_index_contact() {
    #                                 $w = $this->db->get('dlmbg_contact',...);
    #                                 foreach ($w->result() as $h)
    #                                     $hasil .= "<td>".$h->nama."</td>"; }
    # The DB is outside the taint graph, so $h->nama traces to code=3
    # exhausted.  Bridge: when a property read's base variable derives
    # from db->get('t') (same-table literal), search the graph for
    # db->insert('t', $data) calls and check whether $data (or its
    # same-name key write, e.g. $in['nama'] = $_POST['nama']) holds a
    # superglobal-sourced value.
    #
    # Precision guards (all must hold):
    #   H1. reader base derives from a db->get/query/get_where whose table
    #       literal matches the writer db->insert table literal exactly
    #   H2. writer insert's data argument contains the SAME key name as the
    #       read property (nama == nama) sourced from a superglobal —
    #       either directly ($in['nama'] = $_POST['nama']) or via a
    #       bounded subtree scan of the array-variable's writes
    #   H3. both sites are inside functions/methods (not top-level noise)
    #   H4. the reported reason names both ends for auditability
    def _ci_view_bridge_source(self, var_vid: int, var_name: str):
        """Fix 43c: CodeIgniter load->view boundary bridge.
        var_vid is a variable node inside a view file with no DFG in-edge.
        Find loader calls `load->view('<name>', $arr)` whose <name> matches
        the view file, then array-key writes `$arr[<var_name minus $>] =
        <rhs>` in the same controller function, and pb() the rhs."""
        _ck = ("_view_bridge", var_vid)
        if _ck in self._decision_cache:
            return self._decision_cache[_ck]
        # Fix 43h: recursion brake — bridging a view var whose controller
        # value is ITSELF a bridged view var (multi-view controller methods)
        # cascades bridge-in-bridge chains. Cap active bridge depth at 2.
        _d = getattr(self, "_view_bridge_depth", 0)
        if _d >= 2:
            return None
        self._view_bridge_depth = _d + 1
        try:
            _r = self._ci_view_bridge_source_uncached(var_vid, var_name)
        finally:
            self._view_bridge_depth = _d
        self._decision_cache[_ck] = _r
        return _r

    def _ci_view_bridge_source_uncached(self, var_vid: int, var_name: str):
        if not var_name or not var_name.startswith("$"):
            return None
        key = var_name[1:]
        sv = self.graph.vs[var_vid]
        view_fp = _vattr(sv, "file_path", "") or ""
        if not view_fp or "/views/" not in view_fp.replace("\\", "/"):
            return None
        # view name candidates from the file path:
        # .../views/contact/bg_home.php → {'contact/bg_home', 'bg_home'}
        rel = view_fp.replace("\\", "/").split("/views/")[-1]
        if rel.endswith(".php"):
            rel = rel[:-4]
        rel_short = rel.rsplit("/", 1)[-1]
        # Fix 43h: precomputed loader index (built once per analyzer)
        if getattr(self, "_view_loader_index", None) is None:
            idx: dict[str, list[tuple[int, str]]] = {}
            for lvv2 in self._nname.get(("operator", "view"), []):
                vv2 = self.graph.vs[lvv2]
                if _vattr(vv2, "type", "") != "method_call":
                    continue
                lfp2 = _vattr(vv2, "file_path", "") or ""
                if not lfp2 or "/views/" in lfp2.replace("\\", "/"):
                    continue
                _a2 = [e2.target for e2 in self._edge_out(lvv2, "ast")
                       if _vattr(e2, "role") == "arg"]
                if not _a2:
                    continue
                _n2 = str(_vattr(self.graph.vs[_a2[0]], "name", "")).strip("'\"")
                if _n2:
                    idx.setdefault(_n2, []).append((lvv2, lfp2))
            self._view_loader_index = idx
        # candidate loaders: exact rel match + bare-name matches filtered
        # by module dir below (Fix 43f)
        cand_loaders = list(self._view_loader_index.get(rel, []))
        for _bn, _lst in self._view_loader_index.items():
            if "/" not in _bn and _bn == rel_short:
                cand_loaders.extend(_lst)
        for lv, lfp in cand_loaders:
            lvv = self.graph.vs[lv]
            if lfp == view_fp:
                continue
            args = [e.target for e in self._edge_out(lv, "ast")
                    if _vattr(e, "role") == "arg"]
            if not args:
                continue
            a0 = self.graph.vs[args[0]]
            vname = str(_vattr(a0, "name", "")).strip("'\"")
            if vname != rel and vname.rsplit("/", 1)[-1] == rel_short:
                # bare-name loader ('bg_input') hits view files in ANY
                # module's views dir — require the loader's module dir to
                # match the view file's module dir (Fix 43f).
                _vm = view_fp.replace("\\", "/").split("/views/")[0].rsplit("/", 1)[-1]
                _lm = lfp.replace("\\", "/").split("/modules/")[-1].split("/")[0] \
                    if "/modules/" in lfp.replace("\\", "/") else _vm
                if _vm != _lm:
                    continue
                vname = rel
            if vname != rel and vname != rel_short:
                # qualified loader name must equal the full relative path
                if "/" in vname:
                    continue
                vname = rel
            # data array arg: $d (or $data).  The graph often omits the
            # second loader arg (only the view-name const survives), so
            # when absent fall back to ANY array variable in the loader's
            # enclosing function that stores this key.
            data_arr = None
            if len(args) >= 2:
                dv = self.graph.vs[args[1]]
                if _vattr(dv, "type", "") == "variable":
                    data_arr = _vattr(dv, "name", "")
            # same enclosing function: array-key writes $data_arr[key]=rhs
            _lf = self._get_enclosing_function_name(lv)
            for kv in self._nname.get(("identifier", key), []):
                kvv = self.graph.vs[kv]
                kfp = _vattr(kvv, "file_path", "") or ""
                if kfp != lfp:
                    continue
                if _lf and self._get_enclosing_function_name(kv) not in ("", _lf):
                    continue
                for me in self._edge_in(kv, "member"):
                    arr_v = self.graph.vs[me.source]
                    if data_arr and _vattr(arr_v, "name", "") != data_arr:
                        continue
                    # the stored value: array var's dfg in-edge source.
                    # For a method_call value (e.g. generate_index_contact()),
                    # pb() traces the CALL ARGS, not the return — use the
                    # function-return analyzer for those (Fix 43e).
                    for de in self._edge_in(me.source, "dfg"):
                        _dvv = self.graph.vs[de.source]
                        if _vattr(_dvv, "type", "") in ("method_call", "static_call", "call"):
                            sub = None
                            _fn = self._resolve_callee_name(de.source) or ""
                            for _fv2 in self._nname.get(("function", _fn.rsplit(".", 1)[-1]), []):
                                sub = self.analyze_function_return(de.source, _fv2)
                                if sub is not None:
                                    break
                            if sub is None:
                                # callee unresolved in graph — fall back to pb
                                sub = self.parameters_back(de.source, context_vid=kv)
                        else:
                            sub = self.parameters_back(de.source, context_vid=kv)
                        if sub is not None and sub.code == 1:
                            sub.reason = (f"CI view bridge '{vname}' key "
                                          f"'{key}' → {sub.reason}")
                            sub.path = [var_vid] + (sub.path or [])
                            return sub
        return None

    def _db_table_bridge_source(self, start_vid: int, prop_name: str):
        _ck = ("_db_bridge", start_vid, prop_name)
        if _ck in self._decision_cache:
            return self._decision_cache[_ck]
        _r = self._db_table_bridge_source_uncached(start_vid, prop_name)
        self._decision_cache[_ck] = _r
        return _r

    def _db_table_bridge_source_uncached(self, start_vid: int, prop_name: str):
        if not prop_name:
            return None
        sv = self.graph.vs[start_vid]
        # Base variable: member in-edge chain start_vid <- base (e.g. $h)
        base_vid = None
        for e in self._edge_in(start_vid, "member"):
            bv = self.graph.vs[e.source]
            if _vattr(bv, "type", "") == "variable":
                base_vid = e.source
                break
        if base_vid is None:
            return None
        # The use-site SSA node ($h@L867) may have no dfg in-edge while the
        # foreach VALUE node ($h@L865, dfg <- result()) does.  Try the base
        # itself first, then same-name SSA siblings in the same file whose
        # dfg in-edge comes from a result() call (the foreach value site) —
        # this keeps the table lookup anchored to the same loop instead of
        # grabbing an unrelated same-name get() elsewhere in the file.
        base_name = _vattr(self.graph.vs[base_vid], "name", "")
        base_fp = _vattr(self.graph.vs[base_vid], "file_path", "") or ""
        cand_bases = [base_vid]
        if base_name and base_fp:
            for sib in self._nname.get(("identifier", base_name), []):
                if sib == base_vid:
                    continue
                svv = self.graph.vs[sib]
                if _vattr(svv, "type", "") != "variable":
                    continue
                if (_vattr(svv, "file_path", "") or "") != base_fp:
                    continue
                # same enclosing function as the read site — the same
                # file hosts ~26 generate_index_* helpers each with its
                # own $h loop; only the read site's own function counts
                _bf = self._get_enclosing_function_name(base_vid)
                if _bf:
                    _sf = self._get_enclosing_function_name(sib)
                    if _sf and _sf != _bf:
                        continue
                is_foreach_value = False
                for de in self._edge_in(sib, "dfg"):
                    dv = self.graph.vs[de.source]
                    if _vattr(dv, "label", "") == NodeLabel.OPERATOR.value \
                            and _vattr(dv, "type", "") == "method_call" \
                            and (self._resolve_callee_name(de.source) or "").rsplit(".", 1)[-1] == "result":
                        is_foreach_value = True
                        break
                if is_foreach_value:
                    cand_bases.insert(0, sib)  # foreach-value site wins
        # Collect every candidate table reachable from the base's SSA
        # siblings (same-name foreach values) and try each — the first
        # sibling with a table might be an unrelated loop in the same
        # file (dlmbg_ruang's raw-SQL get); only a table whose insert
        # actually superglobal-stores THIS key counts.
        table_lits = []
        seen_tl = set()
        for cb in cand_bases:
            tl = self._base_table_literal(cb)
            if tl:
                tl = tl.strip("'\"")
                if tl not in seen_tl:
                    seen_tl.add(tl)
                    table_lits.append(tl)
        if not table_lits:
            return None
        # Find db->insert('<same table>', $data) call sites.
        for table_lit in table_lits:
            for cand in self._nname.get(("operator", "insert"), []):
                    cv = self.graph.vs[cand]
                    if _vattr(cv, "type", "") not in ("method_call",):
                        continue
                    # receiver chain must end with 'db' (this->db->insert)
                    recv_ok = False
                    for re_ in self._edge_out(cand, "ast"):
                        if _vattr(re_, "role") == "callee":
                            callee_v = self.graph.vs[re_.target]
                            if _vattr(callee_v, "type", "") in ("field", "property") \
                                    and _vattr(callee_v, "name", "") == "insert":
                                recv_ok = True
                            break
                    if not recv_ok:
                        continue
                    # arg0 must be the same table literal
                    args = [e_.target for e_ in self._edge_out(cand, "ast")
                            if _vattr(e_, "role") == "arg"]
                    if not args:
                        continue
                    arg0 = self.graph.vs[args[0]]
                    if _vattr(arg0, "label", "") != NodeLabel.CONST.value:
                        continue
                    cand_table = str(_vattr(arg0, "name", "")).strip("'\"")
                    if cand_table != table_lit:
                        continue
                    # H2: data argument holds a superglobal-sourced write at the
                    # same key (prop_name).  arg1 is typically a variable ($in):
                    # look for same-name array-key writes $in[<prop_name>] whose
                    # value subtree hits a superglobal.
                    if len(args) < 2:
                        continue
                    data_v = self.graph.vs[args[1]]
                    dname = _vattr(data_v, "name", "")
                    if not dname or _vattr(data_v, "type", "") != "variable":
                        continue
                    for kv in self._nname.get(("identifier", prop_name), []):
                        kvv = self.graph.vs[kv]
                        if _vattr(kvv, "type", "") != "const_key" and _vattr(kvv, "label", "") != "identifier":
                            continue
                        # array-key write $dname[<prop>] = RHS : the key node's
                        # enclosing assign must reference the data variable
                        hit = self._array_key_write_hits_superglobal(kv, dname, _vattr(data_v, "file_path", "") or "")
                        if hit:
                            return AnalysisResult(
                                code=1,
                                reason=(f"stored-XSS DB bridge table '{table_lit}' "
                                        f"key '{prop_name}' → superglobal '{hit}' "
                                        f"(db->insert write, db->get read)"),
                                chain=[{"step": "db_bridge", "vid": cand,
                                        "name": f"{table_lit}.{prop_name}", "code": 1}],
                                path=[start_vid, cand],
                                expr_lineno=_vattr(sv, "lineno", 0))
        return None

    def _base_table_literal(self, base_vid: int):
        """base_vid (e.g. $h) derives from db->get('t')…->result() —
        the foreach value variable often has NO dfg in-edge, so walk a
        wider neighbourhood: dfg in-edges, plus same-function variables
        feeding a ->result() call whose receiver reaches db->get('t').
        Returns the table literal name or None."""
        visited = {base_vid}
        frontier = [base_vid]
        for _ in range(10):
            nxt = []
            for fv in frontier:
                # dfg in-edges
                for e in self._edge_in(fv, "dfg"):
                    if e.source in visited:
                        continue
                    visited.add(e.source)
                    src = self.graph.vs[e.source]
                    if _vattr(src, "label", "") == NodeLabel.OPERATOR.value \
                            and _vattr(src, "type", "") == "method_call":
                        callee = self._resolve_callee_name(e.source)
                        if callee == "result":
                            # result()'s receiver var — continue from it
                            for me in self._edge_in(e.source, "dfg"):
                                if me.source not in visited:
                                    nxt.append(me.source)
                            continue
                        if callee in ("get", "get_where", "query"):
                            args = [x.target for x in self.graph.es.select(
                                _source=e.source, label="ast")
                                if _vattr(x, "role") == "arg"]
                            if args:
                                a0 = self.graph.vs[args[0]]
                                nm = _vattr(a0, "name", "")
                                if nm and _vattr(a0, "label", "") == NodeLabel.CONST.value:
                                    return nm
                    nxt.append(e.source)
                # member in-edges (property reads on this base, e.g.
                # $w->result() links result call to $w) — skip, handled
                # via the result() receiver above
            frontier = list(set(nxt))
            if not frontier:
                break
        # foreach-value fallback: base has no dfg in-edge but a sibling
        # variable in the same function assigns from db->get('t') and the
        # foreach source is <sibling>->result().  Find method_call 'result'
        # nodes in the same file, walk recv → SSA var → assign(lhs)→rhs
        # method_call, and accept db-qualified callees ('db.get').
        base_fp = _vattr(self.graph.vs[base_vid], "file_path", "") or ""
        if not base_fp:
            return None
        _DB_READERS = ("get", "get_where", "query")

        def _is_db_read(callee_name):
            if not callee_name:
                return False
            bare = callee_name.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
            return bare in _DB_READERS

        for rv in self._nname.get(("operator", "result"), []):
            rvv = self.graph.vs[rv]
            if _vattr(rvv, "type", "") != "method_call":
                continue
            rfp = _vattr(rvv, "file_path", "") or ""
            if rfp != base_fp:
                continue
            # scope to the same enclosing function as the property read
            # (same file hosts many generate_index_* helpers; without
            # this the first sibling match wins and picks the wrong
            # table — dlmbg_user instead of dlmbg_contact)
            _base_fn = self._get_enclosing_function_name(base_vid) \
                if hasattr(self, "_get_enclosing_function_name") else None
            if _base_fn:
                _rv_fn = self._get_enclosing_function_name(rv)
                if _rv_fn and _rv_fn != _base_fn:
                    continue
            # receiver variables of result(): dfg in-edge sources
            recv_vars = [e.source for e in self._edge_in(rv, "dfg")
                         if _vattr(self.graph.vs[e.source], "type", "") == "variable"]
            # BFS from receivers through: dfg in-edges (SSA chain) and
            # assign(lhs)→rhs edges, bounded
            seen = set(recv_vars)
            frontier = list(recv_vars)
            for _ in range(6):
                nxt = []
                for fv in frontier:
                    # assign(lhs)→rhs: fv is an assign lhs whose rhs is a
                    # db read call with a const table arg
                    for le in self._edge_in(fv, "ast"):
                        if _vattr(le, "role") != "lhs":
                            continue
                        av = self.graph.vs[le.source]
                        if _vattr(av, "type", "") != "assign":
                            continue
                        for re_ in self._edge_out(le.source, "ast"):
                            if _vattr(re_, "role") != "rhs":
                                continue
                            rhs_v = self.graph.vs[re_.target]
                            if _vattr(rhs_v, "label", "") == NodeLabel.OPERATOR.value \
                                    and _vattr(rhs_v, "type", "") == "method_call" \
                                    and _is_db_read(self._resolve_callee_name(re_.target)):
                                args = [x.target for x in self.graph.es.select(
                                    _source=re_.target, label="ast")
                                    if _vattr(x, "role") == "arg"]
                                if args:
                                    a0 = self.graph.vs[args[0]]
                                    nm = _vattr(a0, "name", "")
                                    if nm and _vattr(a0, "label", "") == NodeLabel.CONST.value:
                                        return nm
                    # SSA chain: continue through dfg in-edges
                    for de in self._edge_in(fv, "dfg"):
                        if de.source not in seen:
                            seen.add(de.source)
                            nxt.append(de.source)
                frontier = nxt
        return None

    def _array_key_write_hits_superglobal(self, key_vid: int, arr_name: str, scope_fp: str = "") -> str:
        """key_vid is an identifier node used as an array key.  Find the
        enclosing assign whose lhs contains this key AND the array
        variable arr_name; return the superglobal hit from the RHS.
        Fallback: array keys often have NO ast parent (they attach via
        member edges to the array variable).  In that case the array
        variable's dfg in-edge sources ARE the stored values — scan
        those subtrees for a superglobal read, but only accept a hit
        whose key name matches key_vid's name (dlmbg_user.nama stores
        $_POST['nama'] but so does dlmbg_contact — the key gate lives
        in the caller; here we just confirm a superglobal flows into
        the array through this key's member site)."""
        key_name = _vattr(self.graph.vs[key_vid], "name", "")
        # Path A: key has an ast parent assign (direct lhs/rhs shapes).
        # Guard: skip self-reference (the $_POST['nama'] key node IS the
        # ast-rhs child of the $in['nama'] assign — rhs == key_vid is the
        # value side, not a stored-array key), and require the assign to
        # live in the same file as the db->insert data arg.
        for pe in self._edge_in(key_vid, "ast"):
            pv = self.graph.vs[pe.source]
            if _vattr(pv, "label", "") != NodeLabel.OPERATOR.value:
                continue
            ptype = _vattr(pv, "type", "")
            if ptype not in ("assign", "binary_op"):
                continue
            if scope_fp and (_vattr(pv, "file_path", "") or "") != scope_fp:
                continue
            # lhs side must reference arr_name variable, rhs checked for superglobal
            lhs_has_arr = False
            rhs_vid = None
            for ce in self._edge_out(pe.source, "ast"):
                role = _vattr(ce, "role", "")
                if role == "lhs":
                    cv = self.graph.vs[ce.target]
                    if _vattr(cv, "name", "") == arr_name:
                        lhs_has_arr = True
                elif role == "rhs":
                    rhs_vid = ce.target
            if lhs_has_arr and rhs_vid is not None and rhs_vid != key_vid:
                hit = self._store_value_hits_superglobal(rhs_vid)
                if hit:
                    return hit
        # Path B: key attaches via member edge to the array variable.
        # The array variable's dfg in-edge source is the stored value
        # node (e.g. $_POST['nama'] key node feeding $in).  Require the
        # stored node's own key/name to match key_name so cross-key
        # stores don't false-bridge.
        if key_name:
            for me in self._edge_in(key_vid, "member"):
                arr_v = self.graph.vs[me.source]
                if _vattr(arr_v, "name", "") != arr_name:
                    continue
                # Fix 43 precision: the array variable must live in the same
                # file as the db->insert data arg ($in is a common name --
                # contact.php's $in is unrelated to data_status.php's $in)
                if scope_fp and (_vattr(arr_v, "file_path", "") or "") != scope_fp:
                    continue
                for de in self._edge_in(me.source, "dfg"):
                    dv = self.graph.vs[de.source]
                    dn = _vattr(dv, "name", "")
                    if _vattr(dv, "type", "") in ("field", "property") and dn == key_name:
                        # this stored value IS <superglobal>[key_name]:
                        # its member in-edge source must be a superglobal
                        for se in self._edge_in(de.source, "member"):
                            sgv = self.graph.vs[se.source]
                            sgn = _vattr(sgv, "name", "")
                            if sgn and sgn in _SUPERGLOBALS:
                                return sgn
        return ""

    def _store_value_hits_superglobal(self, rhs_vid: int,
                                      max_depth: int = 14) -> str:
        """Subtree scan: does the AST subtree at rhs_vid read any known
        superglobal directly?  Returns the superglobal name or ''.

        Superglobal reads surface as a property/offset node whose MEMBER
        in-edge comes from the superglobal variable (e.g. ``$_POST`` is
        connected to ``payload`` via a member edge, NOT via ast), so the
        scan follows both ast children and member in-edges."""
        stack = [(rhs_vid, 0)]
        while stack:
            vid, depth = stack.pop()
            if depth > max_depth:
                continue
            v = self.graph.vs[vid]
            nm = _vattr(v, "name", "")
            if nm and nm in _SUPERGLOBALS:
                return nm
            # member in-edge: $sg --member--> prop/node reads $sg[...]
            for e in self._edge_in(vid, "member"):
                src = self.graph.vs[e.source]
                snm = _vattr(src, "name", "")
                if snm and snm in _SUPERGLOBALS:
                    return snm
            for e in self._edge_out(vid, "ast"):
                stack.append((e.target, depth + 1))
        return ""

    def _same_name_store_hits_superglobal(self, rhs_vid: int) -> str:
        """Def-chain pass: rhs_vid is a variable/static read (e.g.
        ``self::$payload_obj``).  Find every same-name identifier in the
        same file that is the LHS of an assignment, and subtree-scan that
        assignment's RHS for superglobal reads.  This bridges SSA-style
        per-assignment node splits across if/else branches."""
        rv = self.graph.vs[rhs_vid]
        rname = _vattr(rv, "name", "")
        rlabel = _vattr(rv, "label", "")
        rfp = _vattr(rv, "file_path", "") or _vattr(rv, "path", "")
        if not rname or not rfp:
            return ""
        for cand2 in self._nname.get((rlabel, rname), []):
            if cand2 == rhs_vid:
                continue
            c2 = self.graph.vs[cand2]
            c2_fp = _vattr(c2, "file_path", "") or _vattr(c2, "path", "")
            if c2_fp != rfp:
                continue
            # cand2 must be an assign lhs
            for e in self._edge_in(cand2, "ast"):
                if _vattr(e, "role") != "lhs":
                    continue
                op = self.graph.vs[e.source]
                if (_vattr(op, "label", "") != NodeLabel.OPERATOR.value
                        or _vattr(op, "type", "") != OperatorType.ASSIGN.value):
                    continue
                for re_ in self._edge_out(e.source, "ast"):
                    if _vattr(re_, "role") == "rhs":
                        hit = self._store_value_hits_superglobal(re_.target)
                        if hit:
                            return hit
                        break
                break
        return ""

    def _get_enclosing_function_name(self, vid: int) -> str:
        """Nearest FUNCTION ancestor name (climb ast to the own chain, then
        own parents to the first function/method node)."""
        cur = vid
        for _ in range(24):
            if list(self._edge_in(cur, "own")):
                break
            ast_sel = list(self._edge_in(cur, "ast"))
            if not ast_sel:
                return ""
            cur = ast_sel[0].source
        for _ in range(16):
            own_sel = list(self._edge_in(cur, "own"))
            if not own_sel:
                return ""
            parent = self.graph.vs[own_sel[0].source]
            if _vattr(parent, "label", "") == NodeLabel.FUNCTION.value:
                return _vattr(parent, "name", "") or ""
            cur = own_sel[0].source
        return ""

    def _get_enclosing_class_name(self, vid: int) -> str:
        """Nearest CLASS ancestor: property/identifier nodes attach via ast
        edges to statement operators (assign), which then hang off the own
        chain (file→class→method→stmt).  Climb ast first to reach the own
        chain, then walk own parents level by level to the first CLASS."""
        cur = vid
        # Phase 1: climb ast in-edges (bounded) until a vertex has an own
        # in-edge.  Property reads (ast/rhs of an assign) reach the assign
        # operator, whose own parent is the enclosing statement/branch.
        for _ in range(8):
            if list(self._edge_in(cur, "own")):
                break
            ast_sel = list(self._edge_in(cur, "ast"))
            if not ast_sel:
                return ""
            cur = ast_sel[0].source
        # Phase 2: walk own parents upward; return the first CLASS name.
        for _ in range(12):
            own_sel = list(self._edge_in(cur, "own"))
            if not own_sel:
                return ""
            parent = self.graph.vs[own_sel[0].source]
            if _vattr(parent, "label", "") == NodeLabel.CLASS.value:
                return _vattr(parent, "name", "") or ""
            cur = own_sel[0].source
        return ""

    def _file_class_names(self, file_path: str) -> set[str]:
        """Class names declared in a file (via class-node file_path attr)."""
        _ck = ("_fcls", file_path)
        if _ck in self._decision_cache:
            return self._decision_cache[_ck]
        out: set[str] = set()
        if not file_path:
            return out
        for v in self.graph.vs.select(label=NodeLabel.CLASS.value):
            fp = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            if fp == file_path and v["name"]:
                out.add(v["name"])
        self._decision_cache[_ck] = out
        return out

    def _classes_inherit(self, cls_a: str, cls_b: str) -> bool:
        """True when a and b are non-empty and equal, or linked by an
        extends crg edge / inherits_from chain (either direction)."""
        if not cls_a or not cls_b:
            return False
        if cls_a == cls_b:
            return True
        for base, other in ((cls_a, cls_b), (cls_b, cls_a)):
            # direct attr check
            for v in self.graph.vs.select(
                    label=NodeLabel.CLASS.value, name=base):
                if _vattr(v, "inherits_from", "") == other:
                    return True
            # crg extends edges
            for e in self.graph.es.select(label="crg"):
                if _vattr(e, "type", "") != "extends":
                    continue
                s = self.graph.vs[e.source]
                t = self.graph.vs[e.target]
                if (_vattr(s, "name", "") == base
                        and _vattr(t, "name", "") == other):
                    return True
        return False

    def _defchain_field_store_killed(self, cand_vid: int, sink_vid: int,
                                     var_name: str) -> bool:
        """Fix 42w: detect a sanitized per-field store (``$b['val'] =
        preg_replace(...)``) on *var_name* whose line sits strictly between
        the def-chain candidate def and the sink use.

        The store's LHS identifier node carries taint_type='safe' (set by
        enrich_taint's safe-callee reassign marking) and is the direct DFG
        source of the sink's container variable. When such a store exists,
        the sink reads the NEW (sanitized) field value — the candidate's
        old container taint is dead. Used to suppress the def-chain fallback
        re-introducing taint that a field-sensitive store already killed.
        """
        try:
            sink_line = int(_vattr(self.graph.vs[sink_vid], "lineno", 0) or 0)
            cand_line = int(_vattr(self.graph.vs[cand_vid], "lineno", 0) or 0)
            if sink_line <= 0 or cand_line <= 0 or cand_line >= sink_line:
                return False
            # Same function scope requirement — mirror the def-chain guards
            _cf = self._get_enclosing_func_vid(cand_vid)
            _sf = self._get_enclosing_func_vid(sink_vid)
            if _cf is not None and _sf is not None and _cf != _sf:
                return False
            # Candidate must be a container def the sink's container reads
            # through: walk same-name identifier nodes with a safe-taint
            # lhs whose line is strictly between cand and sink lines.
            for snv in self._nname.get(
                    (NodeLabel.IDENTIFIER.value, var_name), []):
                if snv == cand_vid or snv == sink_vid:
                    continue
                snv_line = int(_vattr(self.graph.vs[snv], "lineno", 0) or 0)
                # Fix 42w: allow snv_line == cand_line — the store-RHS old-value
                # USE node (e.g. vid19 $b inside preg_replace(..., $b['val']))
                # sits on the SAME line as the store lhs. Its taint is exactly
                # what the store kills; a candidate at that line is the old
                # value, not a live def reaching the sink.
                if not (cand_line <= snv_line < sink_line):
                    continue
                if _vattr(self.graph.vs[snv], "taint_type", "") != "safe":
                    continue
                # The safe node must be the LHS of an assignment whose LHS
                # form is a field/element store (e.g. '$b[val]'), not a
                # whole-variable reassign (that case is handled by the
                # plain SSA kill in the def-chain itself).
                for pe in self._edge_in(snv, "ast"):
                    pv = self.graph.vs[pe.source]
                    if (_vattr(pv, "label", "") == NodeLabel.OPERATOR.value
                            and _vattr(pv, "type", "") in ("assign", "aug_assign")
                            and _vattr(pe, "role", "") == "lhs"):
                        # '$b[val]' style name marks an element store;
                        # whole-var assigns normalize name to '$b' exactly.
                        if _vattr(pv, "name", "") != var_name:
                            return True
                        break
            return False
        except Exception:
            return False

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
                # Format-string sanitizer call node on the BFS path
                # (e.g. echo sprintf('%d', $x)): prune like a sanitizer when
                # the constant format is numeric-only.
                if (_vattr(uv, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(uv, "type", "") in _CALL_TYPES):
                    _fc = self._resolve_callee_name(up_vid)
                    if _fc and _fc in _FORMAT_STRING_SANITIZERS:
                        _ff = self._format_string_arg0(up_vid)
                        if _ff is not None and not re.search(
                                r"%[-+ 0#]*[.]?\d*[sfeEgGu]", _ff):
                            if repaired_result is None:
                                repaired_result = AnalysisResult(
                                    code=2,
                                    reason=f"format-string sanitizer '{_fc}({_ff!r})' — numeric-only format",
                                    chain=[{"step": "format_sanitizer", "vid": up_vid,
                                            "name": _fc, "code": 2}],
                                    path=path + [up_vid],
                                    expr_lineno=_vattr(uv, "lineno", 0))
                            continue
                uname = _vattr(uv, "name", "")
                ulabel = _vattr(uv, "label", "")
                utype = _vattr(uv, "type", "")
                # Source variable
                if self._is_source_variable(uname):
                    if self._is_superglobal_only_non_source_members(up_vid):
                        continue
                    # $_FILES bare form is an array, not a scalar source.
                    # Only $_FILES[x]['name'] or $_FILES[x]['type'] are user-controlled.
                    # Block $_FILES itself; member-chain sources (via Rule 1b/5)
                    # will be caught separately with _is_superglobal_member_blocked.
                    if uname == "$_FILES":
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
                    for me in self._edge_in(up_vid, "member"):
                        obj_vid = me.source
                        obj_name = _vattr(self.graph.vs[obj_vid], "name", "")
                        if self._is_source_variable(obj_name):
                            # $_SERVER has mixed controllability — check member chain
                            if self._is_superglobal_member_blocked(up_vid):
                                pass
                            elif self._is_subscript_key_of_non_superglobal(obj_vid):
                                pass
                            elif _vattr(self.graph.vs[obj_vid], "taint_type", "") == "safe":
                                # Sanitized by safe-function reassignment
                                pass
                            # Function-level guard: superglobal member may be
                            # validated by a whitelist guard in an enclosing
                            # branch — check before reporting member source.
                            elif self.language in ("python", "php") and (
                                    self._extract_member_key(obj_vid) or obj_name).strip("'\"") and \
                                    self._has_function_level_guard(
                                        start_vid,
                                        (self._extract_member_key(obj_vid) or obj_name).strip("'\"")):
                                _gname = (self._extract_member_key(obj_vid) or obj_name).strip("'\"")
                                return AnalysisResult(
                                    code=-1,
                                    reason=f"source '{obj_name}[{_gname}]' guarded by function-level validation",
                                    chain=[{"step": "source_guard", "vid": obj_vid,
                                            "name": obj_name, "code": -1}],
                                    path=[start_vid, up_vid, obj_vid],
                                    expr_lineno=_vattr(self.graph.vs[obj_vid], "lineno", 0))
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
        for e in self._edge_out(param_vid, "own"):
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

        for e in self._edge_out(param_vid, "own"):
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
        # JS/TS: bare "location"/"document"/"window" are NOT sources (FP guard).
        # All legitimate JS/TS sources are registered in SourceRegistry (e.g.
        # location.hash, document.cookie, window.name, process.env).
        if self.language in ("javascript", "typescript"):
            if name in _JS_SOURCE_ROOTS:
                return True
        # C: argv/argc is CLI-only, not web-controllable (removed from sources)
        # SourceRegistry: builtin source members for all languages
        # (e.g., Go: os.Args, os.Getenv; C: argv, getenv; Python: sys.argv, os.environ)
        if self._source_registry is not None:
            try:
                if self._source_registry.is_source_member(name):
                    # Java: bare method names like "getParameter" / "getCookies"
                    # are in source_members for suffix fallback, but exact
                    # match on bare names bypasses the _JAVA_REQUEST_PREFIXES
                    # prefix gate (Direction 1).  Require the name to contain
                    # at least one "." (qualified name) for direct match, or
                    # fall through to Direction 1/2 which enforce the prefix.
                    if self.language == 'java' and '.' not in name:
                        pass  # fall through to Direction 1/2 with prefix gate
                    else:
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
                                # Java: suffix match alone is too broad (e.g.
                                # tree.getParameter matches getParameter).
                                # Require prefix (root object) to be a known
                                # request type. Apply to ALL suffix positions,
                                # not just the last segment — otherwise
                                # nameToken.getInputStream.getSourceName
                                # matches getInputStream at position i=1
                                # without checking that nameToken is a request.
                                if self.language == 'java':
                                    prefix = parts[0]
                                    if prefix not in _JAVA_REQUEST_PREFIXES:
                                        continue
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
                                        # Java: bare names matched via Direction 2
                                        # also need prefix guard to prevent
                                        # context.getParameter() matching
                                        # request.getParameter.
                                        if self.language == 'java' and '.' not in name:
                                            # For bare names, require that
                                            # the original caller prefix
                                            # (parts[0]) is a known request.
                                            if parts[0] not in _JAVA_REQUEST_PREFIXES:
                                                continue
                                        return True
                        except (AttributeError, TypeError):
                            pass
                        break
            except Exception:
                pass
        return False

    def _is_subscript_key_of_non_superglobal(self, vid: int) -> bool:
        """Check if a superglobal node (e.g., $_GET['format']) is used as an
        array-offset subscript of a non-superglobal variable.

        When ``$export_formats[$_GET['format']]['extension']`` is modeled in
        the graph, the member chain is:

            $export_formats --member(array_offset)--> $_GET[format]
                                              --member(array_offset)--> extension

        The superglobal ``$_GET[format]`` appears as a *child* (via array_offset
        member edge) of ``$export_formats`` — meaning it is a subscript key
        selector, not a direct data source. The returned value comes from the
        predefined ``$export_formats`` array, not from user input.

        Returns True if this node has an incoming member edge with
        ``access_type == 'array_offset'`` from a non-superglobal parent.
        """
        if not self.graph:
            return False
        for e in self._edge_in(vid, "member"):
            at = e["access_type"] if "access_type" in e.attribute_names() else ""
            if at != "array_offset":
                continue
            parent_name = _vattr(self.graph.vs[e.source], "name", "")
            if parent_name and not self._is_source_variable(parent_name):
                return True
        return False

    def _is_superglobal_member_blocked(self, vid: int) -> bool:
        """Generalized version of _is_server_member_blocked.
        Checks member chains on $_SERVER and $_FILES for non-source keys."""
        if not self.graph:
            return False
        cur_vid = vid
        chain_names = []
        for _ in range(10):
            member_in = list(self._edge_in(cur_vid, "member"))
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
                has_source_member = False
                for key in chain_names:
                    if key in _FILES_SOURCE_MEMBERS:
                        has_source_member = True
                    if key in _FILES_NON_SOURCE_MEMBERS:
                        return True
                # $_FILES requires a source member (name/type) in the chain.
                # Bare $_FILES[key] with a dynamic key is not a scalar source.
                if not has_source_member:
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
        for e in self._edge_out(sg_vid, "member"):
            child_name = _vattr(self.graph.vs[e.target], "name", "")
            if child_name and child_name not in non_source_set:
                return False
        return True

    def _is_server_only_uncontrolled_members(self, server_vid: int) -> bool:
        return self._is_superglobal_only_non_source_members(server_vid)

    def _extract_member_key(self, vid: int) -> str:
        """Extract the first subscript key from a superglobal variable.

        For ``$_GET['dl']`` — given the ``$_GET`` vid — returns ``"dl"``.
        Returns ``""`` if no member child is found.
        """
        for e in self.graph.es.select(_source=vid, label=EdgeLabel.MEMBER.value):
            _mn = _vattr(self.graph.vs[e.target], "name", "")
            if _mn:
                return _mn.strip("'\"")
        return ""

    # --- Path-traversal jail guard (strpos blacklist + die/exit) ----------

    _PATH_JAIL_PROBE_FUNCS = frozenset({
        "strpos", "str_contains", "substr_count", "stripos", "strripos",
        "strncmp", "substr", "mb_strpos", "mb_substr_count",
    })
    _PATH_JAIL_CONSTS = ("../", "..\\", "./", ".\\", "/", "\\")

    def _branch_is_path_jail(self, branch_vid: int, member_key: str) -> bool:
        """Check if a branch condition is a path-traversal blacklist jail for
        ``<superglobal>[member_key]`` and the branch body terminates execution
        (die/exit).

        Recognized pattern (Responsive FileManager execute.php and many
        PHP file managers)::

            if (strpos($_POST['path'], '../') !== FALSE
                || strpos($_POST['path'], '/') === 0
                || ...) {
                die('wrong path');
            }

        A value that reaches code after this block cannot contain ``../`` —
        downstream file operations on it are jailed to the base directory.

        Args:
            branch_vid: branch node vid (type ``if``).
            member_key: subscript key of the superglobal in the taint chain
                        (e.g. ``"path"``, ``"path_thumb"``).

        Returns True if the condition probes the same superglobal member with
        a blacklist const AND the body contains die/exit.
        """
        if not member_key:
            return False

        cond_vid = self._get_condition_root(branch_vid)
        if cond_vid is None:
            return False

        # 1. Condition must contain a jail probe call on the same member key.
        probe_found = False
        stack = [cond_vid]
        visited = set()
        while stack:
            sv = stack.pop()
            if sv in visited:
                continue
            visited.add(sv)
            v = self.graph.vs[sv]
            if (_vattr(v, "label") == NodeLabel.OPERATOR.value
                    and _vattr(v, "type", "") in _CALL_TYPES
                    and _vattr(v, "name", "") in self._PATH_JAIL_PROBE_FUNCS):
                # Look for a property child whose member-source is a superglobal
                # with the matching key, plus a blacklist const arg.
                has_member = False
                has_blacklist_const = False
                for ae in self._edge_out(sv, "ast"):
                    child = self.graph.vs[ae.target]
                    child_label = _vattr(child, "label", "")
                    if child_label == NodeLabel.IDENTIFIER.value:
                        cname = _vattr(child, "name", "")
                        ctype = _vattr(child, "type", "")
                        if ctype in ("property", "field", "const_fetch") or \
                                (cname and not cname.startswith("$")):
                            # property node: member edge FROM superglobal INTO
                            # this property node ($_POST --member--> 'path')
                            for me in self.graph.es.select(
                                    _target=ae.target,
                                    label=EdgeLabel.MEMBER.value):
                                msrc = self.graph.vs[me.source]
                                mname = str(_vattr(msrc, "name", ""))
                                if mname.startswith("$"):
                                    if _vattr(child, "name", "").strip("'\"") == member_key:
                                        has_member = True
                                        break
                        # direct superglobal (e.g. strpos($_GET, ...))
                        if cname in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
                                     "$_SERVER", "$_FILES", "$_SESSION"):
                            has_member = True
                    elif child_label == NodeLabel.CONST.value:
                        cval = str(_vattr(child, "value", "") or _vattr(child, "name", ""))
                        cval = cval.strip("'\"")
                        if cval in self._PATH_JAIL_CONSTS:
                            has_blacklist_const = True
                if has_member and has_blacklist_const:
                    probe_found = True
                    break
            for e in self._edge_out(sv, "ast"):
                stack.append(e.target)

        if not probe_found:
            return False

        # 2. Branch body must contain die/exit (terminate on blacklisted path).
        for oe in self.graph.es.select(_source=branch_vid, label=EdgeLabel.OWN.value):
            body_vid = oe.target
            body_stack = [body_vid]
            body_visited = set()
            while body_stack:
                bv = body_stack.pop()
                if bv in body_visited:
                    continue
                body_visited.add(bv)
                bv_node = self.graph.vs[bv]
                if (_vattr(bv_node, "label") == NodeLabel.OPERATOR.value
                        and _vattr(bv_node, "type", "") in _CALL_TYPES
                        and _vattr(bv_node, "name", "") in ("die", "exit")):
                    return True
                for e in self._edge_out(bv, "ast"):
                    body_stack.append(e.target)
                # own edges cover nested blocks
                for e in self.graph.es.select(_source=bv, label=EdgeLabel.OWN.value):
                    body_stack.append(e.target)
                # don't descend into nested branches' conditions — handled by
                # their own branch nodes (stop at first level of die search)
        return False

    def _has_path_jail_guard(self, source_vid: int, member_key: str) -> bool:
        """Check if the taint source ``<superglobal>[member_key]`` is jailed by
        a path-traversal blacklist guard in the same file before the source's
        lineno (file-scope code) or in the same function before it.

        This is the interprocedural counterpart of ``check_branch_constraint``:
        the guard runs in the caller (e.g. execute.php top-level code), while
        the sink is deep in a callee (e.g. utils.php deleteDir).  parameters_back
        crosses the call edge and reaches the superglobal; the guard on the
        superglobal member must be checked at the point where the taint
        originates.
        """
        sv = self.graph.vs[source_vid]
        src_file = (_vattr(sv, "file_path", "")
                    or _vattr(sv, "path", ""))
        if not src_file or not member_key:
            return False
        src_lineno = int(_vattr(sv, "lineno", 0) or 0)

        branch_list = self._nfile_lineno.get((NodeLabel.BRANCH.value, src_file), [])
        for b_lineno, bvid in branch_list:
            if b_lineno >= src_lineno:
                break  # guards must run BEFORE the tainted assignment
            btype = _vattr(self.graph.vs[bvid], "type", "")
            if btype != "if":
                continue
            if self._branch_is_path_jail(bvid, member_key):
                return True
        return False

    def _is_inside_safe_call_ast(self, vid: int) -> bool:
        """Check if *vid* is nested inside a safe function call's AST subtree.

        Walks up the AST parent chain from *vid*. If any ancestor is a call
        operator whose callee is a known safe function, returns True.
        """
        cur = vid
        for _ in range(15):  # max AST depth
            parents = [e.source for e in self._edge_in(cur, "ast")]
            if not parents:
                break
            for p_vid in parents:
                pv = self.graph.vs[p_vid]
                plabel = _vattr(pv, "label", "")
                ptype = _vattr(pv, "type", "")
                if plabel == NodeLabel.OPERATOR.value and ptype in ("call", "method_call", "static_call"):
                    if self._is_safe_function_call(p_vid):
                        return True
            cur = parents[0]
        return False

    _DEAD_CODE_FALSY = frozenset({"false", "0", "null", "nil", "none", "''", '""'})

    def _build_dead_code_index(self):
        """Pre-compute falsy BRANCH nodes grouped by file for O(1) lookup.

        Returns a dict: file_path -> list of (b_lineno, b_end) tuples.
        Called once and cached in ``self._dead_code_index``.
        """
        if hasattr(self, '_dead_code_index'):
            return self._dead_code_index

        index = {}  # file -> [(b_lineno, b_end), ...]
        for bv in self.graph.vs:
            if _vattr(bv, "label", "") != NodeLabel.BRANCH.value:
                continue
            cond = _vattr(bv, "condition", "").strip().lower()
            if cond not in self._DEAD_CODE_FALSY:
                continue
            b_lineno = int(_vattr(bv, "lineno", 0) or 0)
            if b_lineno <= 0:
                continue
            b_end = int(_vattr(bv, "end_lineno", 0) or 0)
            b_file = _vattr(bv, "file_path", "") or _vattr(bv, "path", "")

            # Compute b_end from body children if unknown
            if b_end <= 0:
                bvid = bv.index
                body_linenos = []
                _visited = {bvid}
                _queue = [bvid]
                while _queue:
                    _cur = _queue.pop(0)
                    for _ae in self.graph.es.select(_source=_cur):
                        _el = _vattr(_ae, "label", "")
                        if _el not in ("ast", "own"):
                            continue
                        _tgt = _ae.target
                        if _tgt in _visited:
                            continue
                        _visited.add(_tgt)
                        _child_ln = int(
                            _vattr(self.graph.vs[_tgt], "lineno", 0) or 0)
                        if _child_ln > 0:
                            body_linenos.append(_child_ln)
                        _queue.append(_tgt)
                if body_linenos:
                    b_end = max(body_linenos)
                else:
                    b_end = b_lineno + 3

            index.setdefault(b_file, []).append((b_lineno, b_end))

        self._dead_code_index = index
        return index

    def _is_in_dead_code(self, vid: int) -> bool:
        """Check if *vid* is inside a dead-code branch (e.g. ``if (false)``).

        Tries two methods:
        1. Walk up the AST parent chain to find a BRANCH with falsy condition.
        2. If no AST chain (orphan node), use the pre-computed dead-code index
           to check lineno overlap with falsy branches in the same file.
        """
        # Method 1: AST parent chain
        cur = vid
        for _ in range(20):
            parents = [(e.source, _vattr(e, "role", "")) for e in self._edge_in(cur, "ast")]
            if not parents:
                break
            for p_vid, edge_role in parents:
                pv = self.graph.vs[p_vid]
                if _vattr(pv, "label", "") == NodeLabel.BRANCH.value:
                    cond = _vattr(pv, "condition", "").strip().lower()
                    if cond in self._DEAD_CODE_FALSY:
                        if edge_role in ("body", "condition", ""):
                            return True
            cur = parents[0][0]

        # Method 2: use pre-computed index (O(branches_in_same_file) per call)
        try:
            sv = self.graph.vs[vid]
            s_lineno = int(_vattr(sv, "lineno", 0) or 0)
            s_file = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
            if s_lineno > 0:
                index = self._build_dead_code_index()
                for b_lineno, b_end in index.get(s_file, ()):
                    if b_lineno <= s_lineno <= b_end:
                        return True
        except Exception:
            pass

        return False

    def _is_safe_function_call(self, call_vid: int) -> bool:
        """Check if the call at *call_vid* targets a function whose return
        value is safe (sanitized).        Checks three sources in order:
        1. builtin_knowledge (safe=True)
        2. taint_type='safe' on the call node (set by enrich_taint)
        3. func_summary_type='safe' on the function node (set by
           build_function_summaries) via use edge
        """
        # 1. builtin_knowledge
        _callee = self._resolve_callee_name(call_vid)
        if _callee:
            _bk = self._load_builtin_knowledge(self.language)
            if _bk and _callee in _bk:
                _entry = _bk[_callee]
                if isinstance(_entry, dict) and _entry.get("safe"):
                    return True
        # 2. taint_type on call node
        cv = self.graph.vs[call_vid]
        if _vattr(cv, "taint_type", "") == "safe":
            return True
        # 3. func_summary_type via use edge
        for ue in self._edge_out(call_vid, "use"):
            fvid = ue.target
            if fvid < self.graph.vcount():
                fv = self.graph.vs[fvid]
                if _vattr(fv, "func_summary_type", "") == "safe":
                    return True
        return False

    def _callback_arg_is_safe(self, call_vid: int) -> bool:
        """Fix 21b-2: for an _ARRAY_CALLBACK_FUNCS call, resolve the callback
        (arg0) to its function definition and check safety via the same
        three sources as _is_safe_function_call. First-first-first semantics:
        string callback 'hsc' / first-class callable hsc(...) / arrow fn are
        resolved through ast[role=arg idx=0] then the callee name lookup.
        """
        callback_vid = None
        arg_counter = 0
        for ae in self._edge_out(call_vid, "ast"):
            if _vattr(ae, "role") != "arg":
                continue
            # index attr is '' on most graphs (probe 25); positional
            # enumeration with arg_index fallback mirrors Rule 4c.
            idx = _vattr(ae, "index")
            actual_idx = int(idx) if idx else arg_counter
            arg_counter += 1
            if actual_idx == 0:
                callback_vid = ae.target
                break
        if callback_vid is None:
            return False
        cb = self.graph.vs[callback_vid]
        # Case 1: first-class callable / direct call node — reuse the
        # standard safe-call check on the callback node itself.
        if _vattr(cb, "label") == NodeLabel.OPERATOR.value:
            return self._is_safe_function_call(callback_vid)
        # Case 2: bare identifier naming the callback (string 'hsc',
        # [Instance, 'method'] is not handled — conservative False).
        if _vattr(cb, "label") == NodeLabel.IDENTIFIER.value:
            cname = _vattr(cb, "name", "").lstrip("$'\"")
            if not cname:
                return False
            _bk = self._load_builtin_knowledge(self.language)
            if _bk:
                _entry = _bk.get(cname)
                if isinstance(_entry, dict) and _entry.get("safe"):
                    return True
            # func_summary safe via use edge from the OUTER call is for the
            # callee, not the callback — resolve callback def by name.
            for fv in self.graph.vs:
                if (_vattr(fv, "label") == NodeLabel.FUNCTION.value
                        and _vattr(fv, "name", "") == cname):
                    if _vattr(fv, "func_summary_type", "") == "safe":
                        return True
                    break
        return False

    def _condition_call_is_negated(self, call_vid: int, max_up: int = 3) -> bool:
        """Check if *call_vid* sits directly under a unary '!' / 'not' node.

        Used by the Fix 20a safe-predicate guard: entering the branch taken
        when ``!pred($x)`` means the predicate returned FALSE, so the call
        must NOT count as a satisfied guard.
        """
        cur = call_vid
        for _ in range(max_up):
            parents = [e.source for e in self._edge_in(cur, "ast")]
            if not parents:
                return False
            for p_vid in parents:
                pv = self.graph.vs[p_vid]
                if (_vattr(pv, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(pv, "type", "") == "unary_op"
                        and _vattr(pv, "name", "") in ("!", "not", "neg")):
                    return True
            # stop at binary ops — above that, negation context is gone
            pv0 = self.graph.vs[parents[0]]
            if _vattr(pv0, "label", "") == NodeLabel.OPERATOR.value and \
                    _vattr(pv0, "type", "") == "binary_op":
                return False
            cur = parents[0]
        return False

    # -- Fix 21a: negated safe-predicate predecessor guard --------------------

    _TERMINATOR_FUNCS = frozenset({"die", "exit"})

    def _array_literal_is_const_whitelist(self, call_vid: int) -> bool:
        """For ``in_array($var, <arg2>)`` — does arg2 resolve to a constant
        array literal (Fix 21-1 normalizer now keeps its elements)?

        Accepts:
        - the array() literal node itself (ast/arg children all CONST)
        - an identifier/subscript node (e.g. $Config['ConfigAllowedTypes'])
          whose DFG writer is such an array() literal
        Returns False when the candidate set is dynamic (variable array,
        function call return, etc.) — membership then proves nothing.
        """
        candidates = []
        for ae in self._edge_out(call_vid, "ast"):
            if _vattr(ae, "role", "") == "arg":
                candidates.append(ae.target)
        if len(candidates) < 2:
            return False
        wl_vid = candidates[1]
        wl = self.graph.vs[wl_vid]

        # Case 1: direct array() literal
        if (_vattr(wl, "label") == NodeLabel.OPERATOR.value
                and _vattr(wl, "name") == "array"):
            elems = [e.target for e in self.graph.es.select(
                _source=wl_vid, label="ast")
                if _vattr(e, "role", "") == "arg"]
            if not elems:
                return False
            return all(_vattr(self.graph.vs[el], "label")
                       == NodeLabel.CONST.value for el in elems)

        # Case 2: identifier/subscript → chase DFG upstream to the writer.
        # dfg edges point writer → reader, so follow INCOMING edges
        # (Bug C fix — b10 probe: chasing _source is a self-loop).
        seen = set()
        frontier = [wl_vid]
        for _ in range(6):
            nxt = []
            for fv in frontier:
                if fv in seen:
                    continue
                seen.add(fv)
                for de in self._edge_in(fv, "dfg"):
                    sv = de.source
                    svv = self.graph.vs[sv]
                    if (_vattr(svv, "label") == NodeLabel.OPERATOR.value
                            and _vattr(svv, "name") == "array"):
                        elems = [e.target for e in self.graph.es.select(
                            _source=sv, label="ast")
                            if _vattr(e, "role", "") == "arg"]
                        if elems and all(
                                _vattr(self.graph.vs[el], "label")
                                == NodeLabel.CONST.value for el in elems):
                            return True
                    elif _vattr(svv, "label", "") in (
                            NodeLabel.IDENTIFIER.value,):
                        nxt.append(sv)
            frontier = nxt
            if not frontier:
                break
        return False

    def _branch_body_always_terminates(self, branch_vid: int) -> bool:
        """Does the guarded branch body provably terminate execution?

        True when the body calls die/exit directly, or calls a function
        whose execution cannot return past its end (bare ``exit;``/
        ``die;`` as the final statement — e.g. CouchCMS SendError()).
        Returns False on any doubt (unknown callee, conditional exit).
        """
        stack = [branch_vid]
        seen = set()
        calls = []
        while stack:
            sv = stack.pop()
            if sv in seen:
                continue
            seen.add(sv)
            svv = self.graph.vs[sv]
            if (_vattr(svv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(svv, "type", "") in _CALL_TYPES):
                calls.append(sv)
            for ee in self._edge_out(sv, "own"):
                stack.append(ee.target)
            for ee in self._edge_out(sv, "ast"):
                stack.append(ee.target)
        if not calls:
            # Source-level goto fallback: the PHP graph builder drops
            # `goto label;` statements entirely, so a guard body of the form
            # `if (!pred($x) or !pred2($x)) { goto reject; }` looks empty
            # here and would be rejected as non-terminating — yet a goto IS
            # an unconditional control transfer out of the guard body
            # (izend fileupload.php:58-59).  When the branch body holds no
            # calls, check the source lines right after the branch for a
            # goto statement.
            bv = self.graph.vs[branch_vid]
            b_file = _vattr(bv, "file_path", "") or _vattr(bv, "path", "")
            b_lineno = int(_vattr(bv, "lineno", 0) or 0)
            if b_file and b_lineno and os.path.isfile(b_file):
                try:
                    with open(b_file, "r", encoding="utf-8",
                              errors="replace") as _fh:
                        for _ in range(3):
                            _line = _fh.readline()
                            if not _line:
                                break
                            _stripped = _line.strip()
                            if not _stripped or _stripped.startswith("<?php"):
                                continue
                            if re.match(r"goto \w\+\s*\;", _stripped):
                                return True
                            break
                except OSError:
                    pass
            return False
        for cv in calls:
            cname = _vattr(self.graph.vs[cv], "name", "")
            if cname in self._TERMINATOR_FUNCS:
                return True
            # one-level callee expansion: does control return past the
            # callee's end?  "Not" iff the callee's LAST top-level
            # statement is a bare die/exit call.
            for ue in self._edge_out(cv, "use"):
                # Bug A fix: wrap int index in Vertex — b15 trace showed
                # _vattr(int, "label") silently failing the FUNCTION check
                fv = self.graph.vs[ue.target]
                if _vattr(fv, "label") != NodeLabel.FUNCTION.value:
                    continue
                last_top_stmt = None
                top_stmts = []
                for oe in self._edge_out(fv, "own"):
                    top_stmts.append((int(_vattr(oe, "index", 0) or 0),
                                      oe.target))
                if not top_stmts:
                    continue
                top_stmts.sort()
                last_top_stmt = top_stmts[-1][1]
                lv = self.graph.vs[last_top_stmt]
                # bare exit/die call statement
                if (_vattr(lv, "label") == NodeLabel.OPERATOR.value
                        and _vattr(lv, "type", "") in _CALL_TYPES
                        and _vattr(lv, "name", "") in self._TERMINATOR_FUNCS):
                    return True
                # return-statement wrapper: return exit(); (rare)
                if _vattr(lv, "label") == NodeLabel.RETURN.value:
                    for re_ in self.graph.es.select(
                            _source=last_top_stmt, label="ast"):
                        rv = self.graph.vs[re_.target]
                        if (_vattr(rv, "label") == NodeLabel.OPERATOR.value
                                and _vattr(rv, "name", "")
                                in self._TERMINATOR_FUNCS):
                            return True
        # Fix 27c: a plain `return;` inside the guarded body is just as
        # terminating as die/exit — control cannot fall through to any
        # later sink (phplist3 configure.php:9
        # `if (!isset($default_config[$id])) { ...; return; }`).
        # Walk the branch subtree for a RETURN node.
        stack2 = [branch_vid]
        seen2 = set()
        while stack2:
            sv = stack2.pop()
            if sv in seen2:
                continue
            seen2.add(sv)
            if self.graph.vs[sv].attributes().get("label") == \
                    NodeLabel.RETURN.value:
                return True
            # Fix 42u: `continue` inside the guarded body terminates the
            # CURRENT LOOP ITERATION — for sinks later in the same loop
            # body the guard is just as absolute as die/exit (sgx-1.4.55
            # L93: `if (!is_array($src_item) || ... || !in_array(
            # $src_item['prop'], [...], true)) { continue; }` before the
            # L96 dynamic-dispatch sink).
            _sv_attrs = self.graph.vs[sv].attributes()
            if (_sv_attrs.get("label") == NodeLabel.OPERATOR.value
                    and _sv_attrs.get("type", "") == "continue"):
                return True
            for ee in self._edge_out(sv, "own"):
                stack2.append(ee.target)
            for ee in self._edge_out(sv, "ast"):
                stack2.append(ee.target)
        return False

    def _unconditional_terminate_before(self, sink_vid: int) -> bool:
        """Fix 21h-2: dead code after unconditional die/exit.

        True when, in the function (or file top-level scope) owning
        *sink_vid*, some top-level statement BEFORE the statement
        containing the sink unconditionally calls die()/exit() at its
        top level.  Execution can never reach the sink, so any taint
        verdict for it is vacuous (imcat userc.php: ``die();`` then
        ``print_r(@$_GET)`` etc.).
        Only BARE die/exit statements count — an exit inside an if-body
        is conditional and does NOT make later code unreachable.
        """
        sv = self.graph.vs[sink_vid]
        s_lineno = int(_vattr(sv, "lineno", 0) or 0)
        # owner: walk up via own AND ast edges (21a Bug B pattern)
        owner_vid = None
        cur = sink_vid
        for _ in range(30):
            up = None
            for e in self._edge_in(cur, "own"):
                up = e.source
                break
            if up is None:
                for e in self._edge_in(cur, "ast"):
                    up = e.source
                    break
            if up is None:
                break
            ulabel = _vattr(self.graph.vs[up], "label")
            if ulabel in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                owner_vid = up
                break
            cur = up
        if owner_vid is None:
            return False
        top_stmts = []
        for oe in self._edge_out(owner_vid, "own"):
            top_stmts.append((int(_vattr(oe, "index", 0) or 0), oe.target))
        if not top_stmts:
            return False
        top_stmts.sort()

        def _stmt_contains(vid: int, target: int) -> bool:
            stack = [vid]
            seen = set()
            while stack:
                w = stack.pop()
                if w in seen:
                    continue
                seen.add(w)
                if w == target:
                    return True
                for ee in self._edge_out(w, "own"):
                    stack.append(ee.target)
                for ee in self._edge_out(w, "ast"):
                    stack.append(ee.target)
            return False

        # which top-level statement contains the sink?  A sink sub-expression
        # can be owned by MORE than one top-level entry: the normalizer may
        # hoist an operand (e.g. the ``@`` unary_op of ``print_r(@$_GET)``)
        # as its own index=0 statement alongside the real call statement.
        # The real enclosing statement carries the LARGER own-index, so pick
        # the container with the max index, not the first match — otherwise
        # the truncated limit hides the die/exit that precedes the real
        # statement (imcat userc.php:9 FP survived exactly this way).
        sink_stmt_idx = None
        best_idx = -1
        for idx, (_i, stmt) in enumerate(top_stmts):
            if _stmt_contains(stmt, sink_vid) and _i > best_idx:
                best_idx = _i
                sink_stmt_idx = idx
        limit = sink_stmt_idx if sink_stmt_idx is not None else len(top_stmts)
        for idx in range(limit):
            lv = self.graph.vs[top_stmts[idx][1]]
            # bare terminator call as the statement itself.  Must have NO
            # ast parent: the normalizer hoists sub-expressions of
            # short-circuit guards (!defined(...) && die(...)) into their
            # own index=0 top-level entries, so a die/exit operand of
            # && would otherwise masquerade as a bare terminator
            # statement and kill every live sink after it (imcat
            # fields.php:24/25 TP regression).
            if (_vattr(lv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(lv, "type", "") in _CALL_TYPES
                    and _vattr(lv, "name", "") in self._TERMINATOR_FUNCS
                    and not self.graph.es.select(
                        _target=lv.index, label="ast")):
                return True
            # return-statement wrapper: return exit(); (rare, still bare)
            if _vattr(lv, "label") == NodeLabel.RETURN.value:
                for re_ in self.graph.es.select(
                        _source=top_stmts[idx][1], label="ast"):
                    rv = self.graph.vs[re_.target]
                    if (_vattr(rv, "label") == NodeLabel.OPERATOR.value
                            and _vattr(rv, "name", "")
                            in self._TERMINATOR_FUNCS):
                        return True
        return False

    # -- Fix 21h-3: constructor property-write whitelist guard ---------------

    def _ctor_property_whitelist_guard(self, sink_vid: int) -> bool:
        """True when *sink_vid* reads ``$obj->prop`` where $obj was created
        with ``new C(...)``, and C's constructor assigns ``$this->prop``
        under a whitelist ternary/conjunction on a constructor parameter
        (``$this->end = array_key_exists($end, choices) ? $end : 'now';``).

        The whitelist constrains the stored value regardless of what the
        caller passed, so the property read cannot return attacker
        content (osTicket dashboard.inc.php:178 ``echo $report->end``).
        """
        sv = self.graph.vs[sink_vid]
        prop_vid = sink_vid
        if _vattr(sv, "type", "") not in ("field", "property"):
            return False
        obj_vid = None
        for me in self._edge_in(sink_vid, "member"):
            obj_vid = me.source
            break
        if obj_vid is None:
            return False
        prop_name = _vattr(self.graph.vs[prop_vid], "name", "")
        if not prop_name:
            return False
        obj_name = _vattr(self.graph.vs[obj_vid], "name", "")
        if not obj_name:
            return False
        # find the assign whose LHS is this object variable.
        # The dfg edge lands on the LHS identifier node (e.g. 23 '$report'),
        # not the assign operator itself — climb to the ast parent and
        # verify the identifier is the assign's LHS child.
        def _assign_of_lhs(lhs_vid: int):
            for pe in self._edge_in(lhs_vid, "ast"):
                parent = pe.source
                pv = self.graph.vs[parent]
                if (_vattr(pv, "label") == NodeLabel.OPERATOR.value
                        and _vattr(pv, "type", "") == "assign"):
                    # confirm lhs role
                    for le in self._edge_out(parent, "ast"):
                        if (_vattr(le, "role", "") == "lhs"
                                and le.target == lhs_vid):
                            return parent
            return None

        ctor_fn = None
        for de in self._edge_in(obj_vid, "dfg"):
            src = de.source
            svv = self.graph.vs[src]
            assign_vid = None
            if (_vattr(svv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(svv, "type", "") == "assign"):
                assign_vid = src
            elif _vattr(svv, "label") == NodeLabel.IDENTIFIER.value:
                assign_vid = _assign_of_lhs(src)
            if assign_vid is None:
                continue
            src = assign_vid
            # RHS: new call with a linked ctor function
            for re_ in self._edge_out(src, "ast"):
                if _vattr(re_, "role", "") != "rhs":
                    continue
                rhs_v = self.graph.vs[re_.target]
                if (_vattr(rhs_v, "label") == NodeLabel.OPERATOR.value
                        and _vattr(rhs_v, "type", "") == "new"):
                    class_name = _vattr(rhs_v, "name", "")
                    for fe in self.graph.es.select(
                            _source=re_.target, label="use"):
                        fv = self.graph.vs[fe.target]
                        if _vattr(fv, "label") == NodeLabel.FUNCTION.value:
                            ctor_fn = fe.target
                            break
                    # Stub fallback: the use edge may land on an external
                    # stub (own_edges=0) when the class body lives in
                    # another file of the same graph.  Locate the real
                    # constructor by its qualified fullname
                    # '<Class>.__construct' (probe4: new OverviewReport
                    # → stub 1202, real ctor 293 in class.report.php).
                    if ctor_fn is not None and not any(
                            True for _ in self.graph.es.select(
                                _source=ctor_fn, label="own")):
                        ctor_fn = None
                    if ctor_fn is None and class_name:
                        want_fullname = f"{class_name.lstrip(chr(39)).rstrip(chr(39))}.__construct"
                        for fv in self.graph.vs:
                            if (_vattr(fv, "label")
                                    == NodeLabel.FUNCTION.value
                                    and _vattr(fv, "fullname", "")
                                    == want_fullname
                                    and any(True for _ in
                                            self.graph.es.select(
                                                _source=fv.index,
                                                label="own"))):
                                ctor_fn = fv.index
                                break
            if ctor_fn is not None:
                break
        if ctor_fn is None:
            return False
        # walk ctor body: find `$this->prop = ...` assign
        for oe in self._edge_out(ctor_fn, "own"):
            stack = [oe.target]
            seen = set()
            while stack:
                w = stack.pop()
                if w in seen:
                    continue
                seen.add(w)
                wv = self.graph.vs[w]
                if (_vattr(wv, "label") == NodeLabel.OPERATOR.value
                        and _vattr(wv, "type", "") == "assign"):
                    lhs_name = None
                    rhs_vid = None
                    for ae in self._edge_out(w, "ast"):
                        if _vattr(ae, "role", "") == "lhs":
                            av = self.graph.vs[ae.target]
                            if _vattr(av, "type", "") in ("field", "property"):
                                lhs_name = _vattr(av, "name", "")
                        elif _vattr(ae, "role", "") == "rhs":
                            rhs_vid = ae.target
                    if lhs_name == prop_name and rhs_vid is not None:
                        if self._rhs_is_whitelist_ternary(rhs_vid):
                            return True
                        return False
                for ce in self._edge_out(w, "ast"):
                    stack.append(ce.target)
                for ce in self._edge_out(w, "own"):
                    stack.append(ce.target)
        return False

    def _rhs_is_whitelist_ternary(self, rhs_vid: int) -> bool:
        """Does this expression constrain its value to a whitelist?

        Accepted shape: an expression containing array_key_exists($p, <const
        array>) or in_array($p, <const array>) — the tested parameter can
        only contribute a whitelisted value (ternary true-branch echoes the
        parameter back, false-branch is a constant).
        """
        calls = []
        stack = [rhs_vid]
        seen = set()
        while stack:
            w = stack.pop()
            if w in seen:
                continue
            seen.add(w)
            wv = self.graph.vs[w]
            if (_vattr(wv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(wv, "type", "") in _CALL_TYPES):
                calls.append(w)
            for ee in self._edge_out(w, "ast"):
                stack.append(ee.target)
        for cv in calls:
            cname = _vattr(self.graph.vs[cv], "name", "")
            if cname == "array_key_exists":
                args = [e.target for e in self.graph.es.select(
                    _source=cv, label="ast")
                    if _vattr(e, "role", "") == "arg"]
                if len(args) >= 2 and self._array_literal_is_const_whitelist(
                        args[1]):
                    return True
                # static prop as key set (self::$end_choices): class-static
                # arrays are fixed at load time, the request cannot alter
                # them — treat as whitelist (osTicket OverviewReport).
                if len(args) >= 2:
                    a1 = self.graph.vs[args[1]]
                    if (_vattr(a1, "type", "") == "static"
                            and "$" in _vattr(a1, "name", "")):
                        return True
            elif cname == "in_array":
                if self._array_literal_is_const_whitelist(cv):
                    return True
                args = [e.target for e in self.graph.es.select(
                    _source=cv, label="ast")
                    if _vattr(e, "role", "") == "arg"]
                if len(args) >= 2:
                    a1 = self.graph.vs[args[1]]
                    if (_vattr(a1, "type", "") == "static"
                            and "$" in _vattr(a1, "name", "")):
                        return True
        return False


    def _new_arg_constrained_by_ctor(self, arg_vid: int) -> bool:
        """arg_vid is an `arg` child of a `new C(...)` operator.  True when
        ctor param i (matching this arg position) is only stored into
        $this-><prop> through a whitelist ternary (Fix 21h-3b)."""
        new_vid = None
        arg_idx = None
        for pe in self._edge_in(arg_vid, "ast"):
            parent = pe.source
            if _vattr(self.graph.vs[parent], "type", "") != "new":
                continue
            new_vid = parent
            arg_idx = _vattr(pe, "arg_index", None)
            break
        if new_vid is None:
            return False
        # locate ctor function node (reuse the stub-fallback lookup pattern)
        class_name = _vattr(self.graph.vs[new_vid], "name", "")
        if not class_name:
            return False
        ctor_fn = None
        want_fullname = f"{class_name.strip(chr(39)).strip(chr(34))}.__construct"
        for fv in self.graph.vs:
            if (_vattr(fv, "label") == NodeLabel.FUNCTION.value
                    and _vattr(fv, "fullname", "") == want_fullname
                    and any(True for _ in self.graph.es.select(
                        _source=fv.index, label="own"))):
                ctor_fn = fv.index
                break
        if ctor_fn is None:
            return False
        # param i of the ctor
        params = []
        for oe in self._edge_out(ctor_fn, "own"):
            pv_ = self.graph.vs[oe.target]
            if _vattr(pv_, "label", "") == NodeLabel.PARAMETER.value:
                params.append(oe.target)
        try:
            arg_idx = int(arg_idx)
        except (TypeError, ValueError):
            return False
        if arg_idx < 0 or arg_idx >= len(params):
            return False
        param_vid = params[arg_idx]
        # does the ctor store THIS param through a whitelist ternary?
        # walk the ctor body: find assigns whose RHS ternary contains a dfg
        # edge from param_vid and passes _rhs_is_whitelist_ternary.
        for oe in self._edge_out(ctor_fn, "own"):
            stack = [oe.target]
            seen = set()
            while stack:
                w = stack.pop()
                if w in seen:
                    continue
                seen.add(w)
                wv = self.graph.vs[w]
                if (_vattr(wv, "label") == NodeLabel.OPERATOR.value
                        and _vattr(wv, "type", "") == "assign"):
                    rhs_vid = None
                    for ae in self._edge_out(w, "ast"):
                        if _vattr(ae, "role", "") == "rhs":
                            rhs_vid = ae.target
                    if rhs_vid is not None:
                        # any dfg edge from the param into the rhs subtree?
                        stack2 = [rhs_vid]
                        seen2 = set()
                        hits_param = False
                        while stack2:
                            w2 = stack2.pop()
                            if w2 in seen2:
                                continue
                            seen2.add(w2)
                            if w2 == param_vid:
                                hits_param = True
                                break
                            for e2 in self.graph.es.select(
                                    _target=w2, label="dfg"):
                                stack2.append(e2.source)
                            for e2 in self.graph.es.select(
                                    _source=w2, label="ast"):
                                stack2.append(e2.target)
                        if hits_param and self._rhs_is_whitelist_ternary(
                                rhs_vid):
                            return True
                for ce in self._edge_out(w, "ast"):
                    stack.append(ce.target)
        return False

    def _fixed_host_url_guard(self, sink_vid: int) -> bool:
        """Fix 23 helper: sink is curl_setopt($ch, CURLOPT_URL, $url) and
        $url's defining assign is a concat whose leftmost ast child is a
        const scalar matching  scheme://host  (host chars inside the same
        literal).  Verified graph shape (probe /tmp/t_curl):
        call curl_setopt --ast/arg--> const 'CURLOPT_URL', var '$url';
        assign('$url') --ast--> binary_op '.' --> [const 'http://...', var].
        """
        sv = self.graph.vs[sink_vid]
        setopt_vid = sink_vid
        if (_vattr(sv, "type", "") != "call"
                or _vattr(sv, "name", "") != "curl_setopt"):
            # scanner may enter pb at a sensitive-call ARGUMENT: the $url of
            # CURLOPT_URL (ast parent is the curl_setopt call) or the $ch
            # handle of curl_exec (the curl_setopt reaches $ch via dfg).
            # Search: ast parent first, then dfg-feeder variables' ast
            # parents, depth 2.
            entry_file = _vattr(sv, "file_path", "") or _vattr(
                sv, "path", "")

            def _owning_setopt(vid):
                for e in self._edge_in(vid, "ast"):
                    pv = self.graph.vs[e.source]
                    if (_vattr(pv, "type", "") == "call"
                            and _vattr(pv, "name", "") == "curl_setopt"):
                        # scope to the entry's file: cross-file same-name
                        # dfg edges (global name matching) otherwise let
                        # the walk land on unrelated curl_setopt calls in
                        # other files whose $url has no pinned host.
                        pf = _vattr(pv, "file_path", "") or _vattr(
                            pv, "path", "")
                        if not entry_file or pf == entry_file:
                            return e.source
                return None
            parent = _owning_setopt(sink_vid)
            if parent is None:
                # walk BOTH dfg directions from the entry: toward taint
                # sources (dfg in-edges) and toward the sink (dfg out-edges,
                # e.g. entry=$query feeding $url feeding curl_setopt).
                seen = {sink_vid}
                frontier = [sink_vid]
                for _depth in range(5):
                    nxt = []
                    for u in frontier:
                        cand = [e.source for e in self.graph.es.select(
                                    _target=u, label="dfg")]
                        cand += [e.target for e in self.graph.es.select(
                                     _source=u, label="dfg")]
                        for src in cand:
                            if src in seen:
                                continue
                            seen.add(src)
                            parent = _owning_setopt(src)
                            if parent is not None:
                                break
                            nxt.append(src)
                        if parent is not None:
                            break
                    if parent is not None:
                        break
                    frontier = nxt
            if parent is None:
                return False
            setopt_vid = parent
        args = [e.target for e in self.graph.es.select(
            _source=setopt_vid, label="ast")
            if _vattr(e, "role", "") == "arg"]
        if len(args) < 3:
            return False
        opt = self.graph.vs[args[1]]
        # phply renders class constants as type 'constant' (not 'const')
        if (_vattr(opt, "type", "") not in ("const", "constant")
                or _vattr(opt, "name", "") != "CURLOPT_URL"):
            return False
        urlv = self.graph.vs[args[2]]
        if _vattr(urlv, "label", "") != NodeLabel.IDENTIFIER.value:
            return False
        url_name = _vattr(urlv, "name", "")
        if not url_name:
            return False
        # find the assign that defines $url (same file as the curl_setopt
        # call, before it — global name matching otherwise picks same-name
        # assigns from unrelated files)
        setopt_file = _vattr(self.graph.vs[setopt_vid], "file_path", "") \
            or _vattr(self.graph.vs[setopt_vid], "path", "")
        setopt_line = int(_vattr(self.graph.vs[setopt_vid], "lineno", 0)
                          or 0)
        for v in self.graph.vs:
            if (_vattr(v, "type", "") == "assign"
                    and _vattr(v, "name", "") == url_name):
                vf = _vattr(v, "file_path", "") or _vattr(v, "path", "")
                vln = int(_vattr(v, "lineno", 0) or 0)
                if setopt_file and vf != setopt_file:
                    continue
                if setopt_line and vln and vln > setopt_line:
                    continue
                kids = [e.target for e in self.graph.es.select(
                    _source=v.index, label="ast")]
                rhs = None
                for k in kids:
                    if _vattr(self.graph.vs[k], "label", "") !=                             NodeLabel.IDENTIFIER.value:
                        rhs = k
                        break
                if rhs is None:
                    continue
                rv = self.graph.vs[rhs]
                if _vattr(rv, "type", "") != "binary_op":
                    continue
                # leftmost ast child of the concat (earliest ast edge =
                # leftmost operand in phply insertion order)
                subs = sorted(((e.index, e.target) for e in
                               self.graph.es.select(
                                   _source=rhs, label="ast")))
                if not subs:
                    continue
                left = self.graph.vs[subs[0][1]]
                if _vattr(left, "type", "") not in ("const", "constant",
                                                    "string"):
                    continue
                # const node names carry their PHP quotes ('...' or "...")
                lit = (_vattr(left, "name", "") or "").strip("'\u0022")
                if re.match(
                        r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s<>()"
                        u"\u005c\u005c]+", lit):
                    return True
        return False

    def _fixed_host_location_guard(self, header_vid: int) -> bool:
        """Fix 23 extension: header('Location: http://host/...') where the
        scheme://host lives inside the same string literal as the
        'Location:' prefix — the redirect target host is pinned by the
        literal, only the query/path can carry taint, so this is not an
        open redirect.  Handles three arg0 shapes: const with full URL,
        concat whose leftmost const child carries 'Location: scheme://host',
        and an identifier whose defining assign's concat does the same."""
        hv = self.graph.vs[header_vid]
        if _vattr(hv, "type", "") != "call" or \
                _vattr(hv, "name", "") != "header":
            return False
        args = [e.target for e in self.graph.es.select(
            _source=header_vid, label="ast")
            if _vattr(e, "role", "") == "arg"]
        if not args:
            return False
        a0 = self.graph.vs[args[0]]

        def _lit_pinned(lit: str) -> bool:
            m = re.match(r"^[\s]*[Ll]ocation[\s]*:[\s]*"
                         r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s<>()"
                         u"\u005c\u005c]+)", lit)
            return bool(m)

        if _vattr(a0, "label", "") == NodeLabel.CONST.value:
            return _lit_pinned(_vattr(a0, "name", "") or "")
        if _vattr(a0, "type", "") == "binary_op":
            subs = sorted(((e.index, e.target) for e in
                           self.graph.es.select(
                               _source=args[0], label="ast")))
            if subs:
                left = self.graph.vs[subs[0][1]]
                if _vattr(left, "label", "") == NodeLabel.CONST.value:
                    return _lit_pinned(_vattr(left, "name", "") or "")
        if _vattr(a0, "label", "") == NodeLabel.IDENTIFIER.value:
            url_name = _vattr(a0, "name", "")
            hfile = _vattr(hv, "file_path", "") or _vattr(hv, "path", "")
            hline = int(_vattr(hv, "lineno", 0) or 0)
            for v in self.graph.vs:
                if (_vattr(v, "type", "") == "assign"
                        and _vattr(v, "name", "") == url_name):
                    vf = _vattr(v, "file_path", "") or _vattr(v, "path", "")
                    vln = int(_vattr(v, "lineno", 0) or 0)
                    if hfile and vf != hfile:
                        continue
                    if hline and vln and vln > hline:
                        continue
                    kids = [e.target for e in self.graph.es.select(
                        _source=v.index, label="ast")]
                    rhs = None
                    for k in kids:
                        if _vattr(self.graph.vs[k], "label", "") != \
                                NodeLabel.IDENTIFIER.value:
                            rhs = k
                            break
                    if rhs is None:
                        continue
                    rv = self.graph.vs[rhs]
                    if _vattr(rv, "type", "") != "binary_op":
                        continue
                    subs = sorted(((e.index, e.target) for e in
                                   self.graph.es.select(
                                       _source=rhs, label="ast")))
                    if not subs:
                        continue
                    left = self.graph.vs[subs[0][1]]
                    if _vattr(left, "label", "") == NodeLabel.CONST.value:
                        if _lit_pinned(_vattr(left, "name", "") or ""):
                            return True
        return False

    def _isset_dim_literal_whitelist(self, call_vid: int,
                                     var_name: str) -> bool:
        """Fix 22a helper: is this isset() call of the form
        isset($some_array[$var]) where $some_array is assigned an array
        literal somewhere in the graph?  Graph shape (verified on
        phplist3 configure.php): isset call --ast/arg--> identifier
        base ('$default_config') --member--> property dim ('$id').
        The base's literal-ness is checked by finding an
        operator/assign named '$base' whose ast rhs is a call to
        'array' (phply renders array literals as array() calls)."""
        args = [e.target for e in self.graph.es.select(
            _source=call_vid, label="ast")
            if _vattr(e, "role", "") == "arg"]
        if not args:
            return False
        base_vid = args[0]
        bv = self.graph.vs[base_vid]
        if _vattr(bv, "label", "") != NodeLabel.IDENTIFIER.value:
            return False
        base_name = _vattr(bv, "name", "")
        if not base_name:
            return False
        # dim must reference var_name (member edge from base)
        dim_ok = False
        for me in self._edge_out(base_vid, "member"):
            dv = self.graph.vs[me.target]
            dname = _vattr(dv, "name", "")
            if dname in (var_name, var_name.lstrip("$"),
                         "$" + var_name.lstrip("$")):
                dim_ok = True
                break
        if not dim_ok:
            return False
        # base must be assigned an array literal somewhere
        for v in self.graph.vs:
            av = v.attributes()
            if (_vattr(v, "type", "") == "assign"
                    and _vattr(v, "name", "") == base_name):
                for ae in self._edge_out(v.index, "ast"):
                    if _vattr(ae, "role", "") != "rhs":
                        continue
                    rv = self.graph.vs[ae.target]
                    if (_vattr(rv, "type", "") == "call"
                            and _vattr(rv, "name", "") == "array"):
                        return True
        return False

    def _negated_whitelist_guard_before(self, sink_vid: int,
                                        var_name: str,
                                        sink_lineno: int | None = None) -> bool:
        """Fix 21a: CouchCMS whitelist pattern.

        In the function owning *sink_vid*, an if-branch BEFORE the sink
        lineno has condition ``!pred($var)`` where pred is either
        ``in_array`` with a constant whitelist (Fix 21-1 keeps the literal
        in the graph) or a user predicate with a 'safe' summary (Fix 20a
        infrastructure), and the guarded body provably terminates.

        Reaching the sink therefore proves pred($var) == TRUE — the
        variable is whitelist-constrained, so taint from ``$var`` is not
        attacker-controlled content at the sink.
        *sink_lineno* overrides the sink position for the branch-order
        test (the post-check probes path nodes created BEFORE the guard —
        e.g. `$in` at L31 guarded at L35, sink at L43 — where the guard
        must be ordered against the real sink, not the probe node).
        """
        sv = self.graph.vs[sink_vid]
        s_file = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        if not s_file:
            return False
        if sink_lineno is not None:
            s_lineno = int(sink_lineno)
        else:
            s_lineno = int(_vattr(sv, "lineno", 0) or 0)

        # the function owning the sink — guards must live in the same one.
        # Walk up via own AND ast edges (identifier/operand nodes have no
        # own parent; Bug A fix — b15/b16 probes).
        owner_fn = None
        cur = sink_vid
        for _ in range(30):
            up = None
            for e in self._edge_in(cur, "own"):
                up = e.source
                break
            if up is None:
                for e in self._edge_in(cur, "ast"):
                    up = e.source
                    break
            if up is None:
                break
            if _vattr(self.graph.vs[up], "label") == NodeLabel.FUNCTION.value:
                owner_fn = up
                break
            if _vattr(self.graph.vs[up], "label") == NodeLabel.FILE.value:
                # Bug E fix: top-level script scope (getsimple api.php) —
                # the file itself is the enclosing "function"; branch
                # lookup below is already file-scoped.
                owner_fn = up
                break
            cur = up
        if owner_fn is None:
            return False

        branch_list = self._nfile_lineno.get(
            (NodeLabel.BRANCH.value, s_file), [])
        for b_lineno, bvid in branch_list:
            if b_lineno >= s_lineno:
                break  # guards must run BEFORE the sink
            bv = self.graph.vs[bvid]
            if _vattr(bv, "type", "") != "if":
                continue
            cond_vid = self._get_condition_root(bvid)
            if cond_vid is None:
                continue
            # Expect unary '!' wrapping a call — OR a disjunction of
            # negated predicates (`!pred($x) or !pred2($x)`, izend
            # fileupload.php:58).  With `or`, reaching the sink proves
            # EVERY operand predicate true (any false operand would have
            # terminated), so each operand must independently qualify.
            cv = self.graph.vs[cond_vid]
            _pred_calls = []
            if (_vattr(cv, "label") == NodeLabel.OPERATOR.value
                    and _vattr(cv, "type", "") == "binary_op"
                    and _vattr(cv, "name", "") in ("or", "||")):
                for _oe in self._edge_out(cond_vid, "ast"):
                    if _vattr(_oe, "role", "") == "operand":
                        _ov = self.graph.vs[_oe.target]
                        if (_vattr(_ov, "label") == NodeLabel.OPERATOR.value
                                and _vattr(_ov, "type", "") == "unary_op"):
                            for _ie in self.graph.es.select(
                                    _source=_oe.target, label="ast"):
                                if _vattr(_ie, "role", "") == "operand":
                                    _pred_calls.append(_ie.target)
                                    break
            if not _pred_calls:
                if (_vattr(cv, "label") != NodeLabel.OPERATOR.value
                        or _vattr(cv, "type", "") != "unary_op"):
                    continue
                for ce in self._edge_out(cond_vid, "ast"):
                    if _vattr(ce, "role", "") == "operand":
                        _pred_calls.append(ce.target)
                        break
            if not _pred_calls:
                continue
            # Fix 27: iterate every negated predicate — with `or`, EACH
            # operand must independently qualify, so ANY failing predicate
            # disqualifies the whole branch.  (This block previously
            # referenced an undefined `call_vid` — NameError on every
            # single-predicate guard, so the whitelist guard never fired.)
            # Fix 42u: existence/type predicates (isset/is_array/is_scalar/
            # is_string/...) referencing var_name are NEUTRAL in an or-chain:
            # they impose no value constraint themselves, but reaching the
            # sink past them (each false operand would have terminated)
            # does not weaken the in_array/whitelist operand's constraint.
            # A branch qualifies when at least one operand is a CONSTRAINT
            # predicate and none is a disqualifying unknown predicate.
            _branch_pred_ok = False
            _has_constraint = False
            for call_vid in _pred_calls:
                _pv = self._pred_qualifies_state(call_vid, var_name, bvid)
                if _pv == "constraint":
                    _has_constraint = True
                elif _pv == "neutral":
                    continue
                else:  # "disqualify"
                    _branch_pred_ok = False
                    break
            else:
                _branch_pred_ok = _has_constraint
            if not _branch_pred_ok:
                continue
            return True
        return False

    _URLENCODE_FUNCS = frozenset({"urlencode", "rawurlencode"})

    def _defining_assign_of(self, var_vid: int) -> int | None:
        """Nearest own-subtree assign writing this variable name BEFORE
        the variable's use line (def-chain head)."""
        sv = self.graph.vs[var_vid]
        v_name = _vattr(sv, "name", "")
        v_file = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        v_line = int(_vattr(sv, "lineno", 0) or 0)
        if not v_name or not v_file:
            return None
        best = None
        best_ln = -1
        for ve in self.graph.vs:
            if (_vattr(ve, "type", "") == "assign"
                    and _vattr(ve, "name", "") == v_name):
                ve_file = _vattr(ve, "file_path", "") or _vattr(ve, "path", "")
                ve_line = int(_vattr(ve, "lineno", 0) or 0)
                if ve_file == v_file and 0 < ve_line < v_line and ve_line > best_ln:
                    best = ve.index
                    best_ln = ve_line
        return best

    def _subtree_has_superglobal(self, vid: int, depth: int = 0) -> bool:
        if depth > 12:
            return False
        v = self.graph.vs[vid]
        nm = _vattr(v, "name", "") or ""
        if nm.startswith("$_"):
            return True
        for e in self._edge_out(vid, "ast"):
            if self._subtree_has_superglobal(e.target, depth + 1):
                return True
        return False

    def _urlencoded_output_guard(self, sink_vid: int, r1) -> str | None:
        """Fix 28: every tainted operand of the echo output is wrapped in
        urlencode — the value charset cannot break out of an HTML
        attribute (no quote/angle/space chars), so this is not XSS."""
        # Fix 43k-3: memoize on (sink_vid, path head) — the guard's result
        # depends only on the graph and those inputs.
        _pkey = tuple((r1.path or [])[:6]) if r1 is not None else ()
        _ck = ("_uog", sink_vid, _pkey)
        if _ck in self._decision_cache:
            return self._decision_cache[_ck]
        _r = self._urlencoded_output_guard_uncached(sink_vid, r1)
        self._decision_cache[_ck] = _r
        return _r

    def _urlencoded_output_guard_uncached(self, sink_vid: int, r1) -> str | None:
        # find the defining assign of the sink variable itself (or of any
        # def-chain variable in the reported path) whose RHS fully
        # encodes the superglobal-derived operands.
        sv = self.graph.vs[sink_vid]
        s_file = _vattr(sv, "file_path", "") or _vattr(sv, "path", "")
        s_line = int(_vattr(sv, "lineno", 0) or 0)
        candidates = [sink_vid]
        for pv in list(r1.path or [])[:6]:
            try:
                candidates.append(pv if isinstance(pv, int) else int(pv))
            except (TypeError, ValueError):
                continue
        seen_vars = set()
        for cv in candidates:
            try:
                cvs = self.graph.vs[cv]
            except Exception:
                continue
            # Fix 28 (revised 2): evaluate ALL same-file definitions of
            # the variable before the use -- the value may come from any
            # branch (osticket $url is defined at both L7 urlencode form
            # and L27 const form), so every definition must be safe.
            v_name = _vattr(cvs, "name", "")
            if not v_name or v_name in seen_vars:
                continue
            seen_vars.add(v_name)
            all_defs_ok = None  # None = no definitions found
            any_encoded = False
            for ve in self.graph.vs:
                if (_vattr(ve, "type", "") != "assign"
                        or _vattr(ve, "name", "") != v_name):
                    continue
                ve_file = _vattr(ve, "file_path", "") or _vattr(ve, "path", "")
                ve_line = int(_vattr(ve, "lineno", 0) or 0)
                if ve_file != s_file or not (0 < ve_line < s_line):
                    continue
                dav = ve
                da = ve.index
                # RHS = ast children that are not the LHS variable
                rhs_vids = [e.target for e in self.graph.es.select(
                    _source=da, label="ast")
                    if _vattr(self.graph.vs[e.target], "name", "")
                    != v_name]
                # Fix 28 (revised): the RHS tree must contain at least one
                # urlencode call AND no bare non-const leaf outside one --
                # the PHP graph keeps member-access BASE nodes (($_REQUEST))
                # out of the ast subtree (21h-3d probe), so "no superglobal
                # in tree" proves nothing; leaf-level accounting is what
                # works on both the encoded and the unencoded shape.
                saw_encoded = any(self._rhs_tree_has_urlencode(rv)
                                  for rv in rhs_vids)
                leaves_ok = all(self._rhs_leaves_all_encoded(rv)
                                for rv in rhs_vids)
                if all_defs_ok is None:
                    all_defs_ok = bool(rhs_vids) and leaves_ok
                else:
                    all_defs_ok = all_defs_ok and (
                        bool(rhs_vids) and leaves_ok)
                any_encoded = any_encoded or saw_encoded
            if not all_defs_ok or not any_encoded:
                continue
            return ("urlencoded output: tainted operand wrapped in "
                    "urlencode before echo (charset cannot escape "
                    "HTML attribute context)")
        return None

    def _rhs_tree_has_urlencode(self, vid: int, depth: int = 0) -> bool:
        if depth > 14:
            return False
        v = self.graph.vs[vid]
        if (_vattr(v, "type", "") in _CALL_TYPES
                and (_vattr(v, "name", "") or "")
                in self._URLENCODE_FUNCS):
            return True
        return any(self._rhs_tree_has_urlencode(e.target, depth + 1)
                   for e in self._edge_out(vid, "ast"))

    def _rhs_leaves_all_encoded(self, vid: int, in_enc: bool = False,
                                depth: int = 0) -> bool:
        """Every non-const ast leaf must sit inside a urlencode call."""
        if depth > 14:
            return False
        v = self.graph.vs[vid]
        if _vattr(v, "label") == NodeLabel.CONST.value:
            return True
        v_type = _vattr(v, "type", "")
        v_name = _vattr(v, "name", "") or ""
        if v_type in _CALL_TYPES and v_name in self._URLENCODE_FUNCS:
            return True
        kids = [e.target for e in self.graph.es.select(
            _source=vid, label="ast")]
        if not kids:
            return in_enc
        # function-name identifiers of plain calls are graph artifacts,
        # not data leaves (probe: urlencode node's ast kids include an
        # identifier named 'urlencode')
        kids = [k for k in kids if not (
            _vattr(self.graph.vs[k], "type", "") == "identifier"
            and _vattr(self.graph.vs[k], "name", "") == v_name
            and v_type in _CALL_TYPES)]
        return all(self._rhs_leaves_all_encoded(k, in_enc, depth + 1)
                   for k in kids)


    def _pred_qualifies(self, call_vid: int, var_name: str,
                        bvid: int) -> bool:
        """Fix 27 helper (extracted from _negated_whitelist_guard_before):
        does ONE negated predicate `!pred(...)` qualify as a value
        constraint on var_name whose guarded branch bvid terminates?"""
        return self._pred_qualifies_state(call_vid, var_name, bvid) == "constraint"

    # Fix 42u: existence/type-check predicates that reference var_name.
    # In a disjunction guard (each false operand terminates), reaching
    # the sink proves every operand TRUE — an existence/type predicate
    # being TRUE constrains shape, not content: NEUTRAL (no value
    # constraint contributed, but no reason to distrust sibling
    # whitelist operands either).
    _NEUTRAL_GUARD_PREDS = frozenset({
        "isset", "empty", "is_null", "array_key_exists", "property_exists",
        "is_array", "is_scalar", "is_string", "is_int", "is_integer",
        "is_numeric", "is_float", "is_double", "is_bool", "is_callable",
        "is_object", "is_iterable", "is_countable", "is_long",
    })

    def _pred_qualifies_state(self, call_vid: int, var_name: str,
                              bvid: int) -> str:
        """Fix 42u tri-state variant of _pred_qualifies:
        'constraint' — the predicate pins var_name's value/content,
        'neutral'    — shape/existence check on var_name (no content claim),
        'disqualify' — unknown predicate; the guard proves nothing safe."""
        _ck = ("_pqs", call_vid, var_name, bvid)
        _hit = self._decision_cache.get(_ck, None)
        if _hit is not None:
            return _hit
        _r = self._pred_qualifies_state_uncached(call_vid, var_name, bvid)
        self._decision_cache[_ck] = _r
        return _r

    def _pred_qualifies_state_uncached(self, call_vid: int, var_name: str,
                                       bvid: int) -> str:
        callee = _vattr(self.graph.vs[call_vid], "name", "")
        # neutral predicates must actually reference var_name to be
        # relevant; a neutral check on an unrelated variable neither
        # constrains nor weakens var_name's guard chain
        _refs_var = False
        _nargs = [e.target for e in self.graph.es.select(
            _source=call_vid, label="ast")
            if _vattr(e, "role", "") == "arg"]
        if _nargs and any(self._subtree_contains_name(a, var_name, depth=0)
                          for a in _nargs):
            _refs_var = True
        if callee in self._NEUTRAL_GUARD_PREDS:
            return "neutral" if _refs_var else "disqualify"
        # NOTE: in_array is listed in _EXISTENCE_CHECK_FUNCS ("membership
        # only — content unchanged"), but HERE membership in a constant
        # whitelist IS the value constraint this guard encodes.  Accept
        # it explicitly BEFORE the existence-check exclusion.
        if callee == "in_array":
            if not self._array_literal_is_const_whitelist(call_vid):
                return "disqualify"
        elif callee in _EXISTENCE_CHECK_FUNCS:
            # isset/empty etc. only prove existence, not value
            # constraint — excluding them here mirrors the 20a
            # predicate-guard exclusion (@4738).
            # Fix 22a: EXCEPT isset($LITERAL_ARRAY[$var]) — when the
            # probed argument is an array-dim whose base variable is
            # assigned an array literal, isset IS a key-whitelist
            # constraint.
            if (callee == "isset"
                    and self._isset_dim_literal_whitelist(
                        call_vid, var_name)
                    and self._branch_body_always_terminates(bvid)):
                return "constraint"
            return "disqualify"
        elif not (callee and self._is_safe_function_call(call_vid)):
            return "disqualify"
        # arg0 must reference var_name
        args = [e.target for e in self.graph.es.select(
            _source=call_vid, label="ast")
            if _vattr(e, "role", "") == "arg"]
        if not args:
            return False
        if not self._subtree_contains_name(args[0], var_name, depth=0):
            # Bug D fix: `$in->method` guards use the PROPERTY name
            # ('method') as arg0, while the path carries '$in'.  Accept
            # when arg0 is a property whose member-parent is var_name.
            prop_ok = False
            a0 = self.graph.vs[args[0]]
            if (_vattr(a0, "type", "") == "property"):
                for me in self._edge_in(args[0], "member"):
                    if _vattr(self.graph.vs[me.source], "name", "") == var_name:
                        prop_ok = True
                        break
            if not prop_ok:
                # Fix 27b: INDIRECT constraint — the predicate binds a
                # derivative of var_name, e.g. phpcms search
                #   $urm_md5 = md5($url); if (!in_array($urm_md5,$wl)) exit;
                # md5 is a one-way function with a unique preimage, so
                # membership of md5($url) in a constant whitelist pins $url
                # to a single value.  Accept when arg0's defining assign
                # wraps a call whose argument subtree contains var_name.
                indir = False
                a0_name = _vattr(a0, "name", "")
                if a0_name:
                    for ve in self.graph.vs:
                        if (_vattr(ve, "type", "") == "assign"
                                and _vattr(ve, "name", "") == a0_name):
                            for ke in self.graph.es.select(
                                    _source=ve.index, label="ast"):
                                if self._subtree_contains_name(
                                        ke.target, var_name, depth=0):
                                    indir = True
                                    break
                        if indir:
                            break
                if not indir:
                    return "disqualify"
            else:
                pass
        # whitelist form needs a constant array; user predicates don't
        if callee == "in_array":
            if not self._array_literal_is_const_whitelist(call_vid):
                return "disqualify"
        # guarded body must provably terminate (else fall-through is
        # NOT proven pred()==true)
        if not self._branch_body_always_terminates(bvid):
            return "disqualify"
        return "constraint"

    def _redirect_base_pinned_by_const(self, op_vid: int) -> bool:
        """Fix 20b: is this binary_op's Location/redirect base pinned to an
        internal path by a constant left-most operand?

        Redirect chains like zblog's ``Redirect('./user.php?id=' . $_GET['id'])``
        → Redirect302 → header only let the attacker control the query
        string — the Location base is a relative site-internal path, so this
        is not an open redirect.  A constant operand pins the base when it
        starts with './', '../', or a single '/' (root-relative, not '//'
        protocol-relative), or looks like an absolute URL whose host part is
        already fixed (contains '://' — host present before any tainted
        part).  Pure concatenations of tainted parts without such a prefix
        are NOT pinned.
        """
        op = self.graph.vs[op_vid]
        if _vattr(op, "type", "") != "binary_op":
            return False
        # left-most operand: walk left children of nested binary_ops
        cur = op_vid
        for _ in range(20):
            left_vid = None
            for e in self._edge_out(cur, "ast"):
                if _vattr(e, "role", "") == "left":
                    left_vid = e.target
                    break
            if left_vid is None:
                return False
            lv = self.graph.vs[left_vid]
            ltype = _vattr(lv, "type", "")
            if ltype == "binary_op":
                cur = left_vid
                continue
            if _vattr(lv, "label", "") == NodeLabel.CONST.value:
                raw = str(_vattr(lv, "name", "") or "").strip("'\"")
                if raw.startswith("./") or raw.startswith("../"):
                    return True
                # root-relative path: '/admin/x' pins the base.  A bare '/'
                # does NOT — '/' . $x with x='/evil.com' yields '//evil.com',
                # a protocol-relative open redirect.
                if len(raw) > 1 and raw.startswith("/") and not raw.startswith("//"):
                    return True
                # absolute URL: only pinned when the host is COMPLETE inside
                # the constant ('http://x.com/p...'); a bare scheme prefix
                # ('http://' . $host) leaves the host attacker-controlled.
                if "://" in raw:
                    rest = raw.split("://", 1)[1]
                    if "/" in rest and rest.split("/", 1)[0]:
                        return True
            return False
        return False

    _REDIRECT_SINK_CALLEES = {
        "redirect", "redirect302", "wp_redirect", "wp_safe_redirect",
        "redirectto", "redirect_to", "location",
    }

    def _start_is_redirect_sink(self, vid: int, max_up: int = 5) -> bool:
        """Fix 20b: is *vid* an argument of a redirect-type sink call?

        True for header('Location: ...'), Redirect302($url), Redirect($x),
        wp_redirect($x), ...  Used to scope the constant-prefix redirect
        analysis so non-redirect sinks (rmdir, system, ...) are untouched.
        """
        cur = vid
        for _ in range(max_up):
            parents = [e.source for e in self._edge_in(cur, "ast")]
            found_call = None
            for p_vid in parents:
                pv = self.graph.vs[p_vid]
                if (_vattr(pv, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(pv, "type", "") in _CALL_TYPES):
                    found_call = p_vid
                    break
            if found_call is None:
                if not parents:
                    return False
                # climb through cast/paren wrappers
                p0 = parents[0]
                if _vattr(self.graph.vs[p0], "label", "") == NodeLabel.OPERATOR.value:
                    cur = p0
                    continue
                return False
            callee = (self._resolve_callee_name(found_call) or "").strip("\\")
            low = callee.lower()
            if low in self._REDIRECT_SINK_CALLEES:
                return True
            if low == "header":
                # header() is a redirect sink only for Location targets:
                # first arg must reference a 'Location:'-style const.
                for ae in self._edge_out(found_call, "ast"):
                    if _vattr(ae, "role", "") != "arg":
                        continue
                    return self._const_in_subtree_starts_with(
                        ae.target, ("location", "content-location", "uri", "refresh"))
            return False
        return False

    def _const_in_subtree_starts_with(self, root_vid: int,
                                      prefixes: tuple[str, ...],
                                      depth: int = 0) -> bool:
        """True if any CONST in the AST subtree starts with one of *prefixes*
        (case-insensitive)."""
        if depth > 6:
            return False
        v = self.graph.vs[root_vid]
        if _vattr(v, "label", "") == NodeLabel.CONST.value:
            nm = str(_vattr(v, "name", "") or "").strip("'\"").lower()
            return any(nm.startswith(p) for p in prefixes)
        for e in self._edge_out(root_vid, "ast"):
            if self._const_in_subtree_starts_with(e.target, prefixes, depth + 1):
                return True
        return False

    def _get_member_chain_parent_taint(self, vid: int) -> str:
        """Walk the incoming member chain from *vid* and return the
        ``taint_type`` of the first ancestor that has one.

        enrich_taint marks the superglobal node (e.g. ``$_GET``) as
        ``safe`` when it is reassigned by a sanitizer, but the property
        child (e.g. ``'package'``) is left untouched.  Callers that detect
        a source *via* a member chain should use this helper to honour the
        parent's ``taint_type`` annotation.
        """
        if self.graph is None:
            return ""
        cur_vid = vid
        for _ in range(10):
            member_in = list(self._edge_in(cur_vid, "member"))
            if not member_in:
                break
            parent_vid = member_in[0].source
            tt = _vattr(self.graph.vs[parent_vid], "taint_type", "")
            if tt:
                return tt
            cur_vid = parent_vid
        return ""

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
            member_in = list(self._edge_in(cur_vid, "member"))
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
                    # Subscript key check (same as below)
                    if self._is_subscript_key_of_non_superglobal(parent_vid):
                        break
                    return parent_name
                break  # no further useful chain to build
            chain = f"{parent_name}.{chain}"
            if self._is_source_variable(chain):
                # Check if the matched superglobal is a subscript key of a
                # non-superglobal (e.g., $export_formats[$_GET['format']]).
                # If so, it selects a predefined value — not a data source.
                if self._is_subscript_key_of_non_superglobal(parent_vid):
                    continue
                return chain
            cur_vid = parent_vid

        return None

    def _format_string_arg0(self, call_vid: int):
        """Return the *constant* format-string value of call arg0, else None."""
        fmt = None
        arg_counter = 0
        for ae in self._edge_out(call_vid, "ast"):
            if _vattr(ae, "role") != "arg":
                continue
            idx = _vattr(ae, "index")
            actual_idx = int(idx) if idx else arg_counter
            arg_counter += 1
            if actual_idx != 0:
                break
            av = self.graph.vs[ae.target]
            label = _vattr(av, "label", "")
            if label == "const":
                fmt = _vattr(av, "name", "") or ""
            elif label == "operator":
                for ce in self._edge_out(ae.target, "ast"):
                    cv = self.graph.vs[ce.target]
                    if _vattr(cv, "label", "") == "const":
                        fmt = _vattr(cv, "name", "") or ""
                        break
            if fmt is None:
                # One DFG hop back (const → $fmt); if that hop lands on an
                # identifier (the assignment LHS $fmt at its definition
                # site), take a second hop to reach the const — handles
                # `$fmt = '%d'; printf($fmt, $x);` where the call arg is a
                # *use site* and the const connects to the *definition*.
                for de in self._edge_in(ae.target, "dfg"):
                    dv = self.graph.vs[de.source]
                    if _vattr(dv, "label", "") == "const":
                        fmt = _vattr(dv, "name", "") or ""
                        break
                    if _vattr(dv, "label", "") == "identifier":
                        for de2 in self._edge_in(dv.index, "dfg"):
                            dv2 = self.graph.vs[de2.source]
                            if _vattr(dv2, "label", "") == "const":
                                fmt = _vattr(dv2, "name", "") or ""
                                break
                        if fmt is not None:
                            break
            break
        if not fmt or len(fmt) > 128 or "%" not in fmt:
            return None
        return fmt.strip().strip("\'")

    def _dyn_call_receiver_classes(self, call_vid: int) -> list[int] | None:
        """Fix 42t: class-node closure (class + crg base chain) for the
        receiver of a dynamic-dispatch method call.

        Resolves ``$obj->{$expr}(...)``'s receiver: find the member-edge
        parent identifier (e.g. ``$mainobj``), then the most recent
        ``$mainobj = new <Class>`` assign BEFORE the call line in the
        same file.  Returns None when the receiver cannot be resolved
        (unknown class, stdClass, param, cross-file) — callers keep the
        un-narrowed full whitelist expansion.
        """
        # 1) receiver identifier vid: member-edge source of the callee
        #    property node, or dfg source of the call
        recv_vids: list[int] = []
        for e in self._edge_in(call_vid, "ast"):
            if _vattr(e, "role", "") == "callee":
                for me in self._edge_in(e.target, "member"):
                    recv_vids.append(me.source)
                break
        if not recv_vids:
            for e in self._edge_in(call_vid, "dfg"):
                sv = self.graph.vs[e.source]
                if (_vattr(sv, "label", "") == NodeLabel.IDENTIFIER.value
                        or _vattr(sv, "type", "") in ("variable", "identifier")):
                    if str(_vattr(sv, "name", "")).startswith("$"):
                        recv_vids.append(e.source)
        if not recv_vids:
            return None
        call_line = int(_vattr(self.graph.vs[call_vid], "lineno", 0) or 0)

        for recv_vid in recv_vids:
            recv_name = _vattr(self.graph.vs[recv_vid], "name", "")
            if not recv_name:
                continue
            recv_file = _vattr(self.graph.vs[recv_vid], "file_path", "") or \
                _vattr(self.graph.vs[recv_vid], "path", "")

            # 2) most recent `recv = new Class` assign before call_line
            best_line, best_new = -1, None
            for av in self._nlbl.get(NodeLabel.OPERATOR.value, []):
                ov = self.graph.vs[av]
                if _vattr(ov, "type", "") != "assign":
                    continue
                if _vattr(ov, "name", "") != recv_name:
                    continue
                if (recv_file and
                        (_vattr(ov, "file_path", "") or _vattr(ov, "path", ""))
                        != recv_file):
                    continue
                aline = int(_vattr(ov, "lineno", 0) or 0)
                if aline >= call_line or aline <= best_line:
                    continue
                for ae in self._edge_out(av, "ast"):
                    if _vattr(ae, "role", "") != "rhs":
                        continue
                    rv = self.graph.vs[ae.target]
                    if _vattr(rv, "type", "") == "new":
                        best_line, best_new = aline, ae.target
                    break
            if best_new is None:
                continue

            # 3) class node by NAME — the new node's use edge points at a
            #    constructor FUNCTION stub, never the class node (phply);
            #    match `new <Class>` against class nodes' names instead.
            cls_name = str(_vattr(self.graph.vs[best_new], "name", "")
                           or "").strip("'\"").lower()
            if not cls_name:
                continue
            cls_vid = None
            for cv in self._nlbl.get(NodeLabel.CLASS.value, []):
                cn = str(_vattr(self.graph.vs[cv], "name", "")
                         or _vattr(self.graph.vs[cv], "fullname", "")
                         or "").strip("'\"").lower()
                if cn == cls_name:
                    cls_vid = cv
                    break
            if cls_vid is None:
                continue
            out, stack, seen = [], [cls_vid], set()
            while stack:
                cv = stack.pop()
                if cv in seen:
                    continue
                seen.add(cv)
                out.append(cv)
                for ce in self._edge_out(cv, "crg"):
                    stack.append(ce.target)
            return out
        return None

    def _preg_replace_whitelist_pattern(self, call_vid: int) -> bool:
        """Fix 42v: does this preg_replace call carry a whitelist
        charset-strip pattern as its FIRST argument?

        Accepted form: ``preg_replace('#[^a-z0-9@ _\\-\\.]#i', '', $x)``
        — pattern begins with a delimiter, then ``[^...]`` (negated
        character class) whose members are literal/escape-only (no
        metacharacter reuse like ``\\w`` which re-imports broad classes),
        and replacement is a constant (usually '').  Every character
        outside the class is deleted, confining the output to the class.
        """
        args = [e.target for e in self.graph.es.select(
            _source=call_vid, label="ast")
            if _vattr(e, "role", "") == "arg"]
        if len(args) < 2:
            return False
        pat = _vattr(self.graph.vs[args[0]], "value", "") or \
            _vattr(self.graph.vs[args[0]], "name", "") or ""
        if not isinstance(pat, str):
            return False
        pat = pat.strip().strip("'\"")
        # Same shape as verified by /tmp/fix42_probe58.py (PAT_RE/BODY_OK)
        m = re.match(r'^([^a-zA-Z0-9\s])\^?\[\^([^\]]*)\]\1[a-zA-Z]*$',
                     pat)
        if not m:
            return False
        body = m.group(2)
        # Only literal chars, escapes of punctuation (\- \. \\ \/), and
        # explicit ranges a-z0-9A-Z — reject \w \s \d . * etc. that keep
        # broad classes alive.
        if not re.fullmatch(
                r'(?:[a-zA-Z0-9@ _\-#&=,;:!?/().\[\]{}~^$+*%|<>]'
                r'|\\[-./\\]|[a-z]-[a-z]|[A-Z]-[A-Z]|[0-9]-[0-9])*',
                body):
            return False
        # replacement (arg1) must be a constant (usually empty)
        rep = _vattr(self.graph.vs[args[1]], "value", "") or ""
        rep_name = _vattr(self.graph.vs[args[1]], "name", "") or ""
        if _vattr(self.graph.vs[args[1]], "type", "") == "const" or rep == "":
            return True
        if rep_name in ("''", '""', ""):
            return True
        return False

    def _is_repair_function(self, name: str) -> bool:
        if not name:
            return False
        clean = name.lstrip("\\")
        # Normalize PHP static-call separator to the dotted form used in
        # graph fullname attributes ('Format.input' on the wire vs
        # 'Format::input' in the knowledge sets) — same normalization
        # _locate_sinks applies.  (Fix 21h)
        clean = clean.replace("::", ".")
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[-1]
        if clean in _REPAIR_FUNCTIONS:
            return True
        # For fluent API chains (e.g. "EntityQuery.use().from().where().queryOne"),
        # check the final method segment.
        dot = clean.rfind(".")
        tail = clean[dot + 1:] if dot >= 0 else clean
        if tail != clean and tail in _REPAIR_FUNCTIONS:
            return True
        # Fix 42v: bare 'preg_replace' is NOT unconditionally safe (an
        # arbitrary pattern can pass anything through), but the whitelist
        # charset-strip form is:
        #   preg_replace('#[^a-z0-9@ _\-\.]#i', "", $x)
        # A leading-^ negated character class with only literal members
        # DELETES every character outside the class — the output is
        # confined to the class.  Callers must verify the pattern via
        # _preg_replace_whitelist_pattern before trusting this name.
        # Also check builtin_knowledge for this language — any function
        # marked safe=True is a repair/sanitizer function.
        bk = self._load_builtin_knowledge()
        if bk:
            entry = bk.get(clean)
            if entry and entry.get("safe"):
                return True
            if tail != clean:
                entry = bk.get(tail)
                if entry and entry.get("safe"):
                    return True
        return False

    def _load_builtin_knowledge(self, language: str = None) -> dict:
        """Load builtin_knowledge for the given language (or self.language).

        Exposed as a public-ish method so scanner.py can query the same
        knowledge base used by _is_repair_function.
        """
        lang = language or self.language
        if lang == self.language and self._builtin_knowledge_cache is not None:
            return self._builtin_knowledge_cache
        try:
            mod_path = f"core.core_engine.{lang}.builtin_knowledge"
            import importlib
            mod = importlib.import_module(mod_path)
            bk = getattr(mod, 'KNOWLEDGE', {})
        except (ImportError, AttributeError):
            bk = {}
        if lang == self.language:
            self._builtin_knowledge_cache = bk
        return bk

    def _is_known_callee(self, name: str) -> bool:
        """Check whether *name* has any entry in builtin_knowledge.

        Unlike _is_repair_function (which only returns True for safe=True),
        this returns True for passthrough entries as well — meaning the
        analyzer has explicit knowledge of how this function handles taint.
        """
        if not name:
            return False
        clean = name.lstrip("\\")
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[-1]
        dot = clean.rfind(".")
        tail = clean[dot + 1:] if dot >= 0 else clean
        bk = self._load_builtin_knowledge()
        if bk:
            if clean in bk or tail in bk:
                return True
        return False

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
        for ae in self._edge_out(call_vid, "ast"):
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
                for me in self._edge_in(current, "member"):
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

    def _find_assign_rhs_call(self, lhs_vid: int) -> int | None:
        """Find the RHS call operator of an assignment whose LHS is *lhs_vid*.

        If ``lhs_vid`` is an identifier that is the LHS of an assignment,
        and the RHS is a function/method call, return the RHS operator vid.
        Otherwise return None.
        """
        # Walk AST parents to find an assign operator
        for parent_vid in self._ef(lhs_vid, "ast"):
            pass  # _ef gives edges FROM vid, but we need edges TO vid
        # Use incoming AST edges
        for parent_vid in self._et(lhs_vid, "ast"):
            pv = self.graph.vs[parent_vid]
            if (_vattr(pv, "label", "") == NodeLabel.OPERATOR.value
                    and _vattr(pv, "type", "") in ("assign", "aug_assign")):
                # Found the assign operator — look for RHS child
                for child_vid in self._ef(parent_vid, "ast"):
                    cv = self.graph.vs[child_vid]
                    if (_vattr(cv, "label", "") == NodeLabel.OPERATOR.value
                            and _vattr(cv, "type", "") in _CALL_TYPES):
                        return child_vid
        return None

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
        for e in self._edge_out(param_vid, "own"):
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
            inc = self._edge_in(cur, "own")
            cur = inc[0].source if inc else None
        return None

    def _get_ast_parent(self, vid: int) -> int | None:
        """从 vid 沿 ast 边反向找直接父节点（ast[source=parent, target=vid]）。"""
        inc = self._edge_in(vid, "ast")
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
            own_inc = self._edge_in(cur, "own")
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
            own_in = self._edge_in(cur, "own")
            if own_in:
                cur = own_in[0].source
            else:
                # Parameter nodes are connected via AST edges, not OWN.
                # Try the AST parent as fallback.
                ast_in = self._edge_in(cur, "ast")
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
            own_inc = self._edge_in(cur, "own")
            if own_inc:
                # Check if any branch has this node as its condition
                # (ast edge with role='condition'). If so, include that
                # branch in the chain — needed for JS/TS where condition
                # nodes may be owned by function rather than branch.
                found_branch = False
                for ae in self._edge_in(cur, "ast"):
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
        for e in self._edge_out(branch_vid, "ast"):
            if _vattr(e, "role", "") == "condition":
                return e.target
        # PHP normalizer emits the if-condition as a plain ast child
        # (usually the binary_op / unary_op expression) without a
        # "condition" role. Fall back to the first ast child that is an
        # operator/expression node rather than a statement.
        _fallback = None
        for e in self._edge_out(branch_vid, "ast"):
            t_type = _vattr(self.graph.vs[e.target], "type", "")
            if t_type in ("binary_op", "unary_op", "expression", "boolean_op"):
                return e.target
            if _fallback is None:
                _fallback = e.target
        return _fallback

    def _subtree_contains_name(self, root_vid: int, var_name: str,
                               depth: int = 0, visited: set | None = None) -> bool:
        """Recursively check if var_name appears anywhere in the AST subtree."""
        if depth > 8 or not var_name:
            return False
        if visited is None:
            visited = set()
        if root_vid in visited:
            return False
        visited.add(root_vid)

        node_name = _vattr(self.graph.vs[root_vid], "name", "")
        if node_name == var_name:
            return True

        # Walk AST children
        for e in self._edge_out(root_vid, "ast"):
            if self._subtree_contains_name(e.target, var_name, depth + 1, visited):
                return True
        # Walk DFG edges (Java normalizer may link via DFG)
        for e in self._edge_out(root_vid, "dfg"):
            if self._subtree_contains_name(e.target, var_name, depth + 1, visited):
                return True
        # Walk member edges (method chaining: matcher(cb) links cb)
        for e in self._edge_out(root_vid, "member"):
            if self._subtree_contains_name(e.target, var_name, depth + 1, visited):
                return True
        return False

    def _check_validation_call_matches(self, call_vid: int, call_name: str, var_name: str) -> bool:
        """Check if a validation call references *var_name*."""
        if call_name == "check_input_parameter":
            _ai = 0
            for ae in self._edge_out(call_vid, "ast"):
                if _vattr(ae, "role") == "arg":
                    _arg_val = _vattr(self.graph.vs[ae.target], "value", "") or _vattr(self.graph.vs[ae.target], "name", "")
                    if _ai == 0 and _arg_val:
                        _vn = var_name.rsplit(".", 1)[-1] if "." in var_name else var_name
                        if str(_arg_val).strip("'\"") == _vn:
                            return True
                    _ai += 1
        else:
            for ae in self._edge_out(call_vid, "ast"):
                if _vattr(ae, "role") == "arg":
                    if self._subtree_contains_name(ae.target, var_name):
                        return True
        return False

    def _check_file_scope_validation(self, v_file: str, v_lineno: int, var_name: str) -> bool:
        """Check standalone validation calls in the same file before v_lineno."""
        if not v_file:
            return False
        import bisect
        op_list = self._nfile_lineno.get((NodeLabel.OPERATOR.value, v_file), [])
        idx = bisect.bisect_left(op_list, (v_lineno, 0))
        for _, ov in op_list[:idx]:
            ov_type = _vattr(self.graph.vs[ov], "type", "")
            ov_name = _vattr(self.graph.vs[ov], "name", "")
            if ov_type not in _CALL_TYPES or ov_name not in _TYPE_VALIDATION_FUNCS:
                continue
            if self._check_validation_call_matches(ov, ov_name, var_name):
                return True
        return False

    def _has_function_level_guard(self, vid: int, var_name: str) -> bool:
        """Check if *any* branch in the same function contains a guard
        function call (from ``_TYPE_VALIDATION_FUNCS``) that references
        ``var_name``.

        This catches the Django "post-guard" pattern::

            url = form.cleaned_data["url"]
            if not url_has_allowed_host_and_scheme(url, ...):
                url = safe_default
            redirect(url)   # outside the if-block, but guarded

        The guard at the if-condition sanitises ``url`` even though the
        sink is not inside the guard's branch.

        Uses ``self._nfile_lineno`` for O(nodes_in_same_file) lookup instead
        of iterating the full node list.
        """
        import bisect

        v_file = _vattr(self.graph.vs[vid], "file_path", "") or _vattr(self.graph.vs[vid], "path", "")
        v_lineno = int(_vattr(self.graph.vs[vid], "lineno", 0) or 0)

        # 1. Find the enclosing function using file-indexed lookup.
        func_vid = None
        if v_file:
            func_list = self._nfile_lineno.get((NodeLabel.FUNCTION.value, v_file), [])
            # All funcs in this file with lineno <= v_lineno; pick the closest
            # Use bisect to find the insertion point for v_lineno
            # func_list is sorted by (lineno, vid)
            idx = bisect.bisect_right(func_list, (v_lineno, float('inf')))
            for i in range(idx - 1, -1, -1):
                fv_lineno, fv = func_list[i]
                if fv_lineno <= v_lineno:
                    func_vid = fv
                    break  # closest (highest lineno ≤ v_lineno)
        branch_vids: list[int] = []
        if func_vid is None:
            # No enclosing function — for global-scope code, still check
            # branches in the same file with lineno <= vid's lineno.
            if v_file:
                branch_list = self._nfile_lineno.get((NodeLabel.BRANCH.value, v_file), [])
                idx = bisect.bisect_right(branch_list, (v_lineno, float('inf')))
                branch_vids = [bv for _, bv in branch_list[:idx]]
            if not branch_vids:
                # Also check for standalone validation calls (not in branches)
                # at file scope, before the source detection point.
                return self._check_file_scope_validation(v_file, v_lineno, var_name)
        else:
            # 2. Collect all branch nodes in the same file after func's lineno.
            fv_lineno = int(_vattr(self.graph.vs[func_vid], "lineno", 0) or 0)
            if v_file:
                branch_list = self._nfile_lineno.get((NodeLabel.BRANCH.value, v_file), [])
                idx_start = bisect.bisect_left(branch_list, (fv_lineno, 0))
                branch_vids = [bv for _, bv in branch_list[idx_start:]]

        # 3. For each branch, check if its condition contains a guard call
        #    whose arguments reference var_name.
        for bvid in branch_vids:
            cond_vid = self._get_condition_root(bvid)
            if cond_vid is None:
                continue
            # Walk the ENTIRE condition subtree.  Guards frequently sit
            # deep inside compound boolean conditions, e.g.
            #   if (!isset($_POST['v']) || empty($_POST['v'])
            #       || !pts_strings::is_version($_POST['v'])) { $proceed = false; }
            # The previous shallow search (condition root + one unary_op
            # level) missed such guards and reported the sink as a FP.
            search_vids: list[int] = []
            stack = [cond_vid]
            while stack:
                sv = stack.pop()
                search_vids.append(sv)
                for ce in self._edge_out(sv, "ast"):
                    stack.append(ce.target)

            for sv in search_vids:
                sv_type = _vattr(self.graph.vs[sv], "type", "")
                sv_name = _vattr(self.graph.vs[sv], "name", "")
                if (sv_type in _CALL_TYPES
                        and sv_name in _TYPE_VALIDATION_FUNCS):
                    # Special case: check_input_parameter takes the key name
                    # as a string literal (arg0), not as a variable.
                    # Match var_name against the string value.
                    if sv_name == "check_input_parameter":
                        _ai = 0
                        for ae in self._edge_out(sv, "ast"):
                            if _vattr(ae, "role") == "arg":
                                _arg_val = _vattr(self.graph.vs[ae.target], "value", "") or _vattr(self.graph.vs[ae.target], "name", "")
                                if _ai == 0 and _arg_val:
                                    _vn = var_name.rsplit(".", 1)[-1] if "." in var_name else var_name
                                    if str(_arg_val).strip("'\"") == _vn:
                                        return True
                                _ai += 1
                        continue
                    # Check if the call references var_name.  Do NOT require
                    # role=="arg" edges: the PHP normalizer emits call
                    # arguments (and static method-name nodes) as plain ast
                    # children with empty roles, which made every guard-arg
                    # match silently fail for PHP.  Walking the whole call
                    # subtree is equivalent for validation calls because
                    # their callee names never equal a data variable name.
                    if self._subtree_contains_name(sv, var_name):
                        return True

        # 4. Fallback: check standalone validation calls (not in branches)
        #    at the same file/scope before the source detection point.
        #    This catches patterns like:
        #      check_input_parameter('dl', $_GET, false, '/^[a-f0-9]{32}$/');
        #      if (!empty($_GET['dl']) && ...) { echo file_get_contents(...); }
        _guard_vid = vid
        if func_vid is not None:
            _guard_vid = func_vid
        _gv_file = _vattr(self.graph.vs[_guard_vid], "file_path", "") or _vattr(self.graph.vs[_guard_vid], "path", "")
        # Use the ORIGINAL vid's lineno (not func_vid's) as the threshold,
        # because the guard must appear BEFORE the source detection point,
        # not before the function definition.
        _gv_lineno = _vattr(self.graph.vs[vid], "lineno", 0)
        # If file_path is empty (e.g. for property/member nodes), try
        # to inherit it from the member-chain parent or AST owner.
        if not _gv_file:
            for me in self.graph.es.select(_target=_guard_vid, label=EdgeLabel.MEMBER.value):
                _pf = _vattr(self.graph.vs[me.source], "file_path", "") or _vattr(self.graph.vs[me.source], "path", "")
                if _pf:
                    _gv_file = _pf
                    if not _gv_lineno:
                        _gv_lineno = _vattr(self.graph.vs[me.source], "lineno", 0)
                    break
        if not _gv_file:
            for oe in self.graph.es.select(_target=_guard_vid, label=EdgeLabel.OWN.value):
                _pf = _vattr(self.graph.vs[oe.source], "file_path", "") or _vattr(self.graph.vs[oe.source], "path", "")
                if _pf:
                    _gv_file = _pf
                    break
        if _gv_file:
            import bisect as _bisect2
            op_list = self._nfile_lineno.get((NodeLabel.OPERATOR.value, _gv_file), [])
            _gv_ln_int = int(_gv_lineno or 0)
            idx = _bisect2.bisect_left(op_list, (_gv_ln_int, 0))
            for _, ov in op_list[:idx]:
                ov_type = _vattr(self.graph.vs[ov], "type", "")
                ov_name = _vattr(self.graph.vs[ov], "name", "")
                if ov_type not in _CALL_TYPES or ov_name not in _TYPE_VALIDATION_FUNCS:
                    continue
                if self._check_validation_call_matches(ov, ov_name, var_name):
                    return True
        return False

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
        # Fix 34f: fast fail -- if the branch condition text is known and
        # does not mention var_name, it cannot constrain it.  CVE-2026-108970:
        # "if ($database->addNewUser(...))" was treated as constraining
        # $subbranch (an argument inside the block), returning
        # uncontrollable and hiding the INSERT injection.  A condition
        # that is a plain call whose result is unrelated to var_name is
        # not a sanitizer for it.
        _bcond = _vattr(self.graph.vs[branch_vid], "condition", "")
        if _bcond and var_name not in _bcond:
            # else/default branches inherit the negated condition; the
            # negation of "A()" still does not mention var_name, so the
            # fast fail holds for them too.
            return False

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
                for e in self._edge_out(cond_vid, "ast"):
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
                        for ce in self._edge_out(left_vid, "ast"):
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
                for e in self._edge_out(cond_vid, "ast"):
                    if not self._check_condition_node(e.target, var_name, depth + 1):
                        return False
                return True

            elif actual_op == "&&":
                # AND: either side constrains → safe
                for e in self._edge_out(cond_vid, "ast"):
                    if self._check_condition_node(e.target, var_name, depth + 1):
                        return True
                return False

            # !=, !==, <, >, <=, >= don't constrain to safe values
            return False

        # FunctionCall / MethodCall: type validator (is_numeric, isdigit, etc.)
        if label == NodeLabel.OPERATOR.value and ntype in _CALL_TYPES:
            if name in _TYPE_VALIDATION_FUNCS:
                # Check if any arg references var_name
                for e in self._edge_out(cond_vid, "ast"):
                    if _vattr(e, "role", "") == "arg":
                        arg_name = _vattr(self.graph.vs[e.target], "name", "")
                        if arg_name == var_name:
                            return True
                # Check method receiver via member chain
                # e.g. page.isdigit() → callee 'isdigit' → member → 'page'
                for ae in self._edge_out(cond_vid, "ast"):
                    if _vattr(ae, "role", "") == "callee":
                        callee_vid = ae.target
                        for me in self._edge_in(callee_vid, "member"):
                            recv_name = _vattr(self.graph.vs[me.source], "name", "")
                            if recv_name == var_name:
                                return True
                # Check method receiver via DFG edge (Python: user_input.isdigit())
                # Python normalizer routes the receiver through a DFG edge into
                # the method_call node instead of a member edge.
                for de in self._edge_in(cond_vid, "dfg"):
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
                for me in self._edge_in(cond_vid, "member"):
                    recv_vid = me.source
                    break
                # Arg is the ast child with role='arg'
                for e in self._edge_out(cond_vid, "ast"):
                    if _vattr(e, "role", "") == "arg":
                        arg_vid = e.target
                        break
                # Fallback: try member or use edge source for receiver
                if recv_vid is None:
                    for me in self._edge_out(cond_vid, "member"):
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

            # Java Pattern.matcher().matches() / Pattern.matches()
            # e.g. validIdentifier.matcher(cb).matches()
            # The method name in graph is 'matcher.matches' or 'matches'.
            # Java method chaining means cb is nested inside matcher() subtree,
            # not a direct child of the matches() condition root.
            callee_name = name.split(".")[-1] if "." in name else name
            if callee_name == "matches":
                # Recursively search the entire condition subtree for var_name
                if self._subtree_contains_name(cond_vid, var_name, depth=0):
                    return True

            # preg_match: anchored regex without dot wildcard → safe
            if name == "preg_match":
                args = []
                for e in self._edge_out(cond_vid, "ast"):
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

            # Fix 20a: user-defined bool predicate functions with a 'safe'
            # function summary (all returns are comparisons / safe builtin
            # wraps, none returns a raw parameter — see _aggregate_flows).
            # e.g. getsimple path_is_safe():
            #   if (path_is_safe($target, GSUPLOADPATH)) { delete_folder($target); }
            # Entering the guarded branch proves the callee's internal
            # checks (realpath prefix compare etc.) passed for var_name.
            # Skipped when the call is negated (!pred($x)) — inside that
            # branch the predicate evaluated FALSE.
            # Existence/emptiness checks (isset/empty/...) must NOT count:
            # their builtin_knowledge entries carry safe=True (return value
            # is safe) but they prove nothing about the *argument's* content
            # — tpure regression: `isset($zbp->Config(...)->PostLOGO)` around
            # a stored-XSS echo wrongly became a "branch constraint".
            _pred_callee = self._resolve_callee_name(cond_vid)
            if (_pred_callee not in _EXISTENCE_CHECK_FUNCS
                    and self._is_safe_function_call(cond_vid)
                    and not self._condition_call_is_negated(cond_vid)):
                for e in self._edge_out(cond_vid, "ast"):
                    if _vattr(e, "role", "") == "arg":
                        if self._subtree_contains_name(e.target, var_name, depth=0):
                            return True

            # re.match / re.fullmatch: anchored regex → safe
            if name in ("match", "fullmatch", "search"):
                args = []
                for e in self._edge_out(cond_vid, "ast"):
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
                for e in self._edge_in(branch_parent, "own"):
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
        for e in self._edge_out(op_vid, "ast"):
            if _vattr(e, "role") == "callee":
                tvid = e.target
                for ae in self._edge_out(tvid, "alias"):
                    resolved_name = _vattr(ae, "resolved_name", "")
                    # Sanity check: resolved_name must look like a valid
                    # function name (no spaces, no SQL keywords, etc.)
                    if resolved_name and " " not in resolved_name:
                        # PHP static_call: prefer the operator's qualified
                        # fullname ('Format.input') when the alias resolved to
                        # the bare method name — class context disambiguates
                        # framework sanitizers such as Format::input from
                        # unrelated same-named methods.  (Fix 21h)
                        if "." not in resolved_name:
                            op_fullname = _vattr(
                                self.graph.vs[op_vid], "fullname", "")
                            if (op_fullname and "." in op_fullname
                                    and op_fullname.endswith(
                                        "." + resolved_name)):
                                return op_fullname
                        return resolved_name
        callee_names: list[tuple[str, int]] = []  # (name, target_vid)
        for e in self._edge_out(op_vid, "ast"):
            if _vattr(e, "role") == "callee":
                t = self.graph.vs[e.target]
                name = _vattr(t, "name") or _vattr(t, "value")
                if name:
                    callee_names.append((name, t.index))
        # Check alias on function node via use edge — if alias builder
        # already resolved the callee (e.g. func_ptr → system), use it
        # directly instead of tracing DFG through member edges.
        # BUT: when a function node has multiple alias edges with *different*
        # resolved_name values (ambiguous — e.g. ``get`` aliased to both
        # ``requests.get`` and ``form.get``), skip alias resolution and fall
        # through to AST callee chain analysis, which is more precise.
        for e in self._edge_out(op_vid, "use"):
            alias_names: set[str] = set()
            for ae in self._edge_out(e.target, "alias"):
                resolved_name = _vattr(ae, "resolved_name", "")
                if resolved_name and " " not in resolved_name:
                    alias_names.add(resolved_name)
            if len(alias_names) == 1:
                _alias_hit = alias_names.pop()
                # Same PHP static_call qualified-name recovery as the
                # ast-callee alias path above.  (Fix 21h)
                if "." not in _alias_hit:
                    op_fullname = _vattr(
                        self.graph.vs[op_vid], "fullname", "")
                    if (op_fullname and "." in op_fullname
                            and op_fullname.endswith("." + _alias_hit)):
                        return op_fullname
                return _alias_hit
            # 0 or >1 aliases: fall through to AST analysis
        # Prefer the last identifier callee (actual method name in chains)
        for idx in range(len(callee_names) - 1, -1, -1):
            name, tvid = callee_names[idx]
            if _vattr(self.graph.vs[tvid], "label") == "identifier":
                vtype = _vattr(self.graph.vs[tvid], "type", "")
                # Property-type identifiers (member access like obj.method)
                # are method names, not variables.
                if vtype == "property":
                    # For qualified calls (a.b.method), try to build the
                    # full qualified name by prepending qualifier names.
                    # This enables _is_repair_function / _is_source_variable
                    # to match on complete references (e.g.
                    # Escape.htmlElementContent) rather than bare short names.
                    if idx > 0:
                        qualifier_name = callee_names[idx - 1][0]
                        return qualifier_name + "." + name
                    # Fallback: check member edges for object qualification
                    for me in self._edge_in(tvid, "member"):
                        obj = self.graph.vs[me.source]
                        obj_name = _vattr(obj, "name", "")
                        if obj_name:
                            return obj_name + "." + name
                    # PHP static_call with class context lost from the callee
                    # chain (phply gives class_ as plain str) — recover it from
                    # the operator fullname so Format::input resolves qualified
                    # instead of the ambiguous bare method name.  (Fix 21h)
                    if "." not in name:
                        op_fullname = _vattr(self.graph.vs[op_vid], "fullname", "")
                        if (op_fullname and "." in op_fullname
                                and op_fullname.endswith("." + name)):
                            return op_fullname
                    return name
                resolved = self._resolve_variable_callee(tvid, name)
                if resolved:
                    return resolved
                return name
                # Check member edges for qualified name (e.g. os.system)
                for me in self._edge_in(tvid, "member"):
                    obj = self.graph.vs[me.source]
                    obj_name = _vattr(obj, "name", "")
                    if obj_name:
                        return obj_name + "." + name
        # No identifier callee found — return the last callee name overall
        if callee_names:
            short = callee_names[-1][0]
            # PHP static_call: prefer the operator's qualified fullname
            # ('Format.input') over the bare method name — class context is
            # required to disambiguate framework sanitizers such as
            # Format::input from unrelated same-named methods.  (Fix 21h)
            if short and "." not in short:
                op_fullname = _vattr(self.graph.vs[op_vid], "fullname", "")
                if (op_fullname and "." in op_fullname
                        and op_fullname.endswith("." + short)):
                    return op_fullname
            return short
        # Fallback: use edge target — check alias first, then variable callee
        for e in self._edge_out(op_vid, "use"):
            # Check alias edges on the function target
            for ae in self._edge_out(e.target, "alias"):
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
        if self._nfile is None:
            self._nfile = {}
            for v in self.graph.vs:
                vl = _vattr(v, 'label', '') or ''
                vn = _vattr(v, 'name', '') or ''
                fp = _vattr(v, 'file_path', '') or _vattr(v, 'path', '') or ''
                if vl and vn:
                    self._nfile.setdefault((vl, vn, fp), []).append(v.index)
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
            inc = self._edge_in(cur, "own")
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
