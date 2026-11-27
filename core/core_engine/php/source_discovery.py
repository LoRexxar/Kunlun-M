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

    # PHP builtin superglobals ($_SESSION / $_SERVER / $_ENV excluded —
    # $_SESSION is server-side session data; $_SERVER has mixed
    # controllability handled per-key by graph_analyzer
    # ._SERVER_UNCONTROLLED_KEYS; $_ENV is OS-level environment variables
    # that are not controllable by HTTP clients.)
    builtin_sources: Set[str] = field(default_factory=lambda: {
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
        '$_FILES',
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

    # Dotted member names recognized as sources by graph_analyzer.
    # Populated from framework config (e.g. "request.input", "request.query").
    source_members: Set[str] = field(default_factory=set)

    # Fix 119d (CVE-2026-44381 perf): is_source_member is a pure function of
    # (chain, scope, source_members, framework_request_objects), all static
    # after add_framework — but enrich calls it per call-node (millions of
    # times on a 1M-node corpus; 91% of py-spy samples on MISP corpus2).
    # Memoize on (chain, scope); the cache is cleared at the end of
    # add_framework (the only mutator).
    _ism_cache: Dict[tuple, bool] = field(default_factory=dict)

    # Fix 119g (CVE-2026-44381): property-form source members that are only
    # attacker data when the READ happens in a specific class context.
    # {member_chain: frozenset(scope_tags)}, populated from the framework
    # config key 'member_scope'.  See _resolve_member_scope.
    _member_scope: Dict[str, frozenset] = field(default_factory=dict)

    # Fix 146c (CVE-2026-100365): ORM mutator method names (SugarCRM-style
    # `$bean->retrieve($id)`).  Populated from the framework config key
    # 'orm_mutator_methods'.  Unlike orm_fetch (return-value form), a
    # mutator writes the DB row INTO the receiver object's properties —
    # subsequent `$bean->prop` reads are second-order sources.  Consumed
    # by graph_analyzer's member-chain walk, NOT by is_source_member.
    orm_mutator_methods: Set[str] = field(default_factory=set)

    # Fix 149b (CVE-2026-63214): RPC entry-method classes (lowercase,
    # PREFIX-matched).  Legacy REST/SOAP stacks (SugarCRM lineage) build
    # one service object and dispatch every call through
    # `$this->implementation->{$method}(...array_values($json_payload))`
    # (service/core/REST/SugarRestJSON.php @ SuiteCRM 7.15.1:100) — a
    # tainted-method-name dynamic dispatch the CG can never resolve
    # (receiver built via `new $implementationClass()` from a string).
    # Semantics: every PUBLIC method of a registered class (and its
    # subclasses, via prefix) is an RPC endpoint whose parameters carry
    # network input — entry-param sources, mirroring Java Fix 135a
    # callback-interface params.  Consumed by graph_analyzer's
    # entry-parameter guard, NOT by is_source_member.
    rpc_entry_classes: Set[str] = field(default_factory=set)

    def is_rpc_entry_class(self, class_name: str) -> bool:
        """Fix 149b: does this (bare) class name belong to a registered
        RPC entry-method family?  Prefix match so versioned subclasses
        (SugarWebServiceImplv4_1 under sugarwebserviceimpl) inherit the
        endpoint semantics.  Defensive no-op for non-PHP registries
        missing the field (cross-language interface rule)."""
        pool = getattr(self, 'rpc_entry_classes', None)
        if not pool or not class_name:
            return False
        cn = class_name.lstrip('\\').lower()
        return any(cn == p or cn.startswith(p) for p in pool)

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
        # Fix 114a: consult the *merged* runtime sets (framework_request_objects /
        # request_methods) rather than the raw config, so context-gated additions
        # like orm_fetch_objects + orm_fetch_methods take effect here too.
        if obj_name not in self.framework_request_objects:
            return False
        # Check if the method is a source method
        return method_name in self.request_methods

    def is_framework_global_function(self, func_name: str) -> bool:
        """Check if a function name is a framework global source function."""
        return func_name in self.framework_global_functions

    # Fix 119g (CVE-2026-44381): class-scope resolution for gated property
    # sources.  CakePHP registers Controller property sources ($this->request,
    # $this->passedArgs, $this->params) — but the same chain names live in
    # OTHER classes with different semantics: Shell::$params is CLI argv
    # (Console tooling, outside the web threat model), and Cache/Log/
    # Configure internals hold no request data.  Matching receiver-blind
    # produced e.g. ServerShell system($this->params[...]) command-injection
    # FPs on the MISP corpus (task 6510: 1011/1002/1017 rows across
    # ServerShell / FileEngine / ConsoleOutput / ExtractTask / UpgradeShell).
    # The scope of a member READ is decided by the reading file's path:
    #   'controller'  — any 'Controller' path segment (app/Controller,
    #                   lib/Cake/Controller, app/Controller/Component)
    #   'view_helper' — a 'View' segment plus a 'Helper*' segment (CakePHP
    #                   helpers legitimately hold $this->request)
    @staticmethod
    def _resolve_member_scope(file_path: str) -> str:
        if not file_path:
            return ''
        segs = {s.lower() for s in file_path.replace('\\', '/').split('/')}
        if 'controller' in segs:
            return 'controller'
        if 'view' in segs and any(s.startswith('helper') for s in segs):
            return 'view_helper'
        return ''

    def is_source_member(self, chain: str, file_path: str = "") -> bool:
        """Check if a dotted name chain matches a known source member.

        Memoized (Fix 119d): the hot path in enrich_taint.  Fix 119g: the
        verdict is scoped — when the framework registers gated property
        members (see _member_scope), the caller passes the file path of the
        member READ and the verdict only holds in allowed class contexts.
        Callers without file context pass nothing; gated members then MISS
        (conservative: a '$this.params' chain with no proven Controller
        context is treated as Shell/config semantics, not attacker data).
        """
        scope = self._resolve_member_scope(file_path) if self._member_scope else ''
        key = (chain, scope)
        cached = self._ism_cache.get(key)
        if cached is not None:
            return cached
        result = self._is_source_member_uncached(chain, scope)
        self._ism_cache[key] = result
        return result

    def _is_source_member_uncached(self, chain: str, scope: str) -> bool:
        """Check if a dotted name chain matches a known source member.

        Matches three forms:
        - exact (e.g. "request.input")
        - suffix (e.g. "request.input" matches when chain is a longer
          dotted path ending with the registered member whose prefix is
          a request object name)
        - prefix (Fix 119b, CVE-2026-44381): chain STARTS WITH a
          registered source object + '.' — a member/dim read under a
          source object is attacker data.  Required for framework
          property sources like CakePHP "$this->request": the member
          chain of $this->request['named']['sort'] only ever appears as
          the full prefix chain "$this.request.named.sort", never as the
          bare object name.

        Fix 119g: a member registered in _member_scope only matches when
        `scope` (the reading context) is in its allowed set.  The three
        arms each keep scanning past a gated-denied member so set
        iteration order never decides the verdict.
        """
        def _gate_ok(sm: str) -> bool:
            allowed = self._member_scope.get(sm)
            return allowed is None or scope in allowed

        if chain in self.source_members:
            return _gate_ok(chain)
        # Suffix match: chain="foo.request.input" should match
        # source_member "request.input" when "foo" is a request object name.
        for sm in self.source_members:
            if chain.endswith('.' + sm):
                # Check if the prefix is a known request object name
                prefix = chain[:-(len(sm) + 1)]
                if prefix in self.framework_request_objects and _gate_ok(sm):
                    return True
        # Prefix match (Fix 119b): chain="request.query.x" /
        # "$this.request.named.sort" under a registered source object.
        for sm in self.source_members:
            if chain.startswith(sm + '.') and _gate_ok(sm):
                return True
        return False

    def add_framework(self, framework: str):
        """Initialize framework-specific source patterns."""
        self.framework = framework
        config = FRAMEWORK_CONFIGS[framework]
        self._fw_config = config  # 保留完整配置供 knowledge_bridge 使用

        self.framework_request_objects = set(config['request_object_names'])
        self.request_methods = set(config['request_methods'])

        # Fix 114a: OpenEMR Phreezer ORM fetch — `$this->Phreezer->Get(...)`
        # return values are second-order sources.  Routed through the same
        # request-object machinery (context-gated: method counts only when
        # the receiver is a registered ORM fetch object).
        _orm_objs = set(config.get('orm_fetch_objects', set()))
        _orm_methods = set(config.get('orm_fetch_methods', set()))
        if _orm_objs and _orm_methods:
            self.framework_request_objects |= _orm_objs
            self.request_methods |= _orm_methods

        # ⚠️ request_methods 不注册为 framework_methods（即不作为全局 source producer）。
        # 这些方法（如 get, query, all）只有在 request 对象上调用时才是 source，
        # 全局注册会导致所有名为 get() 的方法被误标。保留在 request_methods 中
        # 供 is_framework_request_method() 上下文检查使用。
        # （值已在上文初始化并合并 orm_fetch_methods，勿重置。）

        # Register dotted member names for graph_analyzer's _is_source_variable
        # and _is_source_via_member_chain.  e.g. "request.input", "$request.get".
        for obj in self.framework_request_objects:
            clean = obj.lstrip('$')
            for method in self.request_methods:
                self.source_members.add(f'{clean}.{method}')
                if obj != clean:
                    self.source_members.add(f'{obj}.{method}')

        # Fix 119a (CVE-2026-44381): framework property-form sources that are
        # not method cross-products (e.g. CakePHP Controller $this->request /
        # $this->passedArgs).  Consumed by is_source_member with prefix
        # semantics (Fix 119b): every dim/member read UNDER a registered
        # source object ("$this.request.named.sort" under "$this.request")
        # is attacker data.
        for sm in config.get('extra_source_members', set()):
            self.source_members.add(sm)

        # Fix 119g (CVE-2026-44381): class-scope gates for property-form
        # members (see _resolve_member_scope / is_source_member).
        self._member_scope = {
            sm: frozenset(scopes)
            for sm, scopes in config.get('member_scope', {}).items()
        }

        # Fix 146c (CVE-2026-100365): ORM mutator receiver methods —
        # `$bean->retrieve($id)` loads the DB row into the receiver's
        # properties; member reads on that receiver become second-order
        # sources (graph_analyzer member-chain walk).
        self.orm_mutator_methods = set(config.get('orm_mutator_methods', set()))

        # Fix 149b (CVE-2026-63214): RPC entry-method classes — public
        # methods of these classes receive network input via the legacy
        # REST/SOAP dispatch (graph_analyzer entry-param guard).
        self.rpc_entry_classes = set(config.get('rpc_entry_classes', set()))

        # Fix 67: symfony 1.x form proxy — the form object is bound to
        # request params ($form->bind($request->getParameter(...))), so
        # field reads are user-input-backed: $form['field'] (base[] form)
        # and $form['field']->getValue() / $form->getValue() (dotted form).
        if config.get('form_bind_propagates_taint'):
            for obj in ('$form', 'form', '$this->form', 'this.form'):
                clean = obj.lstrip('$')
                self.source_members.add(f'{clean}.getValue')
                self.source_members.add(f'{clean}[]')
                if obj != clean:
                    self.source_members.add(f'{obj}.getValue')
                    self.source_members.add(f'{obj}[]')

        for func in config.get('global_source_functions', set()):
            self.framework_global_functions[func] = SourceInfo(
                type='framework',
                name=func,
                framework=framework,
            )

        # Fix 119d: add_framework is the only mutator of source_members /
        # framework_request_objects — drop any memoized verdicts from a
        # previous framework configuration.
        self._ism_cache.clear()

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
    'wordpress': {
        # WP REST callbacks: function(WP_REST_Request $request) — the
        # request object exposes attacker-controlled data.
        # Fix 69: WP_Query objects too — plugin code feeds $_REQUEST into
        # new WP_Query($params) and reads it back in a posts_where filter
        # callback via $wp_query->get('...'); the query vars are attacker
        # data (CVE-2026-114189 Anywhere Elementor 'search_post_title').
        'request_object_names': {'request', '$request', 'wp_query', '$wp_query'},
        'request_methods': {
            'get_param', 'get_params', 'get_body', 'get_json_params',
            'get_header', 'get_file_params', 'get_query_params',
            'get_route_params', 'get_attributes',
            # wp-kit / common plugin Request wrappers: attributes are
            # seeded from $_GET/$_POST/JSON body — validate()/all()/get()
            # return attacker-controlled data.
            'validate', 'all', 'get', 'input', 'json', 'only', 'except',
        },
        'global_source_functions': set(),
    },
    'slim': {
        # Fix 59: Slim Framework — route closures receive ($request, $response, $args)
        # via DI; PSR-7 ServerRequestInterface methods return attacker data.
        'request_object_names': {'request', '$request'},
        'request_methods': {
            'getQueryParams', 'getParsedBody', 'getAttribute', 'getAttributes',
            'getCookieParams', 'getServerParams', 'getUploadedFiles',
            'getBody', 'getHeader', 'getHeaderLine', 'getHeaders',
        },
        'global_source_functions': set(),
    },
    'openemr': {
        # Fix 86: OpenEMR (CVE-2026-126489, GHSA-8j6v-q545-q9q7) —
        # second-order SQLi.  Admin-editable layout tables (layout_options,
        # written by interface/super/edit_layout.php) are read back through
        # the library/sql.inc.php DB wrappers and spliced into SQL column
        # positions (ippf_issues.inc.php issue_ippf_con_save).  The DB-read
        # wrappers' return values are therefore second-order sources.
        'request_object_names': {'request', '$request'},
        # Fix 115a (CVE-2026-126478): the Zend/Laminas module controllers
        # (interface/modules/zend_modules/*) read user input through
        # `$request = $this->getRequest(); $request->getPost('name', ...)`
        # (AbstractActionController).  Laminas Request methods are gated on
        # the receiver being a request object; Symfony-style method names
        # (get/request/query chains) are NOT added, so FHIR's
        # Symfony Request usage is unaffected.
        'request_methods': {
            'getPost', 'getQuery', 'getFiles', 'getHeaders',
            'getServer', 'getEnv', 'getContent',
        },
        # Verified against library/sql.inc.php @ v8_4_1: row-returning
        # read wrappers are sqlFetchArray / sqlQuery / sqlGetAssoc.
        'global_source_functions': {
            'sqlFetchArray', 'sqlQuery', 'sqlGetAssoc',
            # Fix 144a (CVE-2026-124463): the QueryUtils OO read family
            # (src/Common/Database/QueryUtils.php @ v8_2_0) carries the same
            # second-order semantics — every wrapper returns DB-stored data.
            # fetchArrayFromResultSet() ends in `$resultSet->FetchRow()`, so
            # no path from the sql.inc.php globals reaches it; it needs its
            # own registration.  Qualified key matches the graph enrich pass
            # (full_lookup = normalizer fullname "QueryUtils.<method>" for
            # static calls); bare key matches the AST parser path
            # (get_simple_name) and self::-form call nodes.  fetchRecords /
            # fetchRecordsNoLog return row arrays; fetchTableColumn /
            # fetchTableColumnAssoc / fetchSingleValue return column values.
            'QueryUtils.fetchArrayFromResultSet', 'fetchArrayFromResultSet',
            'QueryUtils.fetchRecords', 'fetchRecords',
            'QueryUtils.fetchRecordsNoLog', 'fetchRecordsNoLog',
            'QueryUtils.fetchTableColumn', 'fetchTableColumn',
            'QueryUtils.fetchTableColumnAssoc', 'fetchTableColumnAssoc',
            'QueryUtils.fetchSingleValue', 'fetchSingleValue',
            # Fix 161a (CVE-2026-124479): the REST document download chain
            # (src/Services/DocumentService.php getFile @ v8_2_0) reads the
            # stored document back via
            # `$obj = new \C_Document(); $document = $obj->retrieve_action(
            # $pid, $did, true, true, true);` (onReturnRetrieveKey grants
            # the raw-bytes return).  Stored document bytes are user-
            # uploadable content (DocumentService::insertAtPath ->
            # file_get_contents(tmp_name) -> createDocument), so the return
            # value is a second-order source.  Same dual-key pattern as
            # QueryUtils/getPreference: qualified key for the graph enrich
            # full_lookup (C_Document receiver type resolves from the new
            # op), bare key for the AST parser path (get_simple_name).
            # retrieve_action is defined only on C_Document in the OpenEMR
            # corpus and always returns stored document content, so the
            # bare key is framework-scoped-safe (cf. openemr sqlQuery).
            'C_Document.retrieve_action', 'retrieve_action',
        },
        # Fix 114a (CVE-2026-126451): the patient-portal Phreezer ORM is the
        # other second-order channel.  Portal patients persist arbitrary
        # JSON into OnsiteDocument columns via Create()/Update()
        # (portal/patient/libs/Controller/OnsiteDocumentController.php);
        # `$this->Phreezer->Get('OnsiteDocument', $pk)` reads the row back
        # and every property of the returned object is DB-stored
        # patient-controlled data (TemplateData -> DocumentTemplateRender
        # iframe src).  'Get' is context-gated on the Phreezer object name
        # only — never registered as a bare global source.
        'orm_fetch_objects': {
            'Phreezer', '$this->Phreezer', 'phreezer', '$phreezer',
        },
        'orm_fetch_methods': {'Get'},
        # Fix 108 (CVE-2026-126482): official output-escaping helpers
        # (library/htmlspecialchars.inc.php — all htmlspecialchars /
        # json_encode wrappers).  Framework-scoped repair set consumed by
        # knowledge_bridge step 6b; per-svid veto (Fix 48i) still applies
        # at analysis time, so e.g. js_escape only kills XSS-family svids.
        # Deliberately excludes xl() (raw translation, no escaping) and
        # renderer helpers (generate_display_field et al.).
        'repair_functions': {
            'text', 'attr', 'attr_js', 'js_escape', 'json_sanitize',
            'xlt', 'xla', 'xlj',
        },
    },
    'suitecrm': {
        # Fix 146b (CVE-2026-100365): SuiteCRM 7.x (SugarCRM lineage) —
        # second-order SQLi via AOR report engine.  Stored report field
        # labels (aor_fields.label, admin/user-editable via the report
        # editor) are loaded back with `$field = BeanFactory::newBean(
        # 'AOR_Fields'); $field->retrieve($field_id);` and the property
        # reads (`$field->label`) splice into ORDER BY without an
        # identifier whitelist (AOR_Report.php:501 pre-7.15.2; upstream
        # fix adds preg_replace('/[^A-Za-z0-9_]/')).
        #
        # Mutator form source: SugarBean::retrieve() (data/SugarBean.php
        # @ 7.15.1:4579) returns $this AFTER populateFromRow($row) has
        # copied the DB row into the receiver's properties — so the
        # RECEIVER, not the (usually discarded) return value, carries the
        # second-order data.  Registered via orm_mutator_methods and
        # consumed by graph_analyzer's member-chain walk (Fix 146c).
        # retrieve_by_string_fields (SugarBean.php:5817) is the same
        # populateFromRow mutator keyed on arbitrary column matches.
        #
        # SuiteCRM reads user input through bare $_REQUEST/$_POST
        # superglobals (already native sources); framework-specific source
        # semantics are the ORM mutator and the getPreference store read
        # (Fix 155a global_source_functions below).
        'request_object_names': set(),
        'request_methods': set(),
        # Fix 155a (CVE-2026-61649): the user-preference read accessor is a
        # second-order source.  SuiteCRM persists dashlet options (incl.
        # RSSDashlet's rss url, MySugar.php:152/168 @ 7.15.1) into the
        # user_preferences table via $current_user->setPreference(...) →
        # UserPreference::savePreferencesToDB (serialize+base64 →
        # SugarBean->save).  Every read side —
        # $current_user->getPreference('dashlets', 'Home') (MySugar.php:146,
        # Dashlet.php:440/454) and UserPreference::getPreference (raw
        # $db->query + fetchByAssoc + unserialize back into $_SESSION) —
        # returns that stored, user-editable data.  $_SESSION reads are
        # deliberately excluded from superglobal sources, and the read
        # path never passes through a registered orm_mutator, so without
        # this registration the whole dashlet-options store channel is
        # invisible (RSSDashlet getRSSOutput → validate_external_host →
        # file_get_contents SSRF, CVE-2026-61649 stripos-bypass guard).
        # Corpus-wide (7.15.1, 4307 files) getPreference is defined exactly
        # in User and UserPreference and always means this accessor, so the
        # bare key is safe here (framework-scoped, cf. openemr sqlQuery).
        'global_source_functions': {
            'getPreference',
            'User.getPreference', 'UserPreference.getPreference',
        },
        'orm_mutator_methods': {'retrieve', 'retrieve_by_string_fields'},
        # Fix 150 (CVE-2026-69134): graph-enrichment mirror of the tamper
        # FILTER_FUNCTIONS quote/quoteIdentifier encoders (Fix 146a) —
        # marks $x->db->quote(...) call nodes taint_type=safe so
        # function_summary treats quote-wrapped return paths as sanitized
        # (same two-line pattern as openemr's Fix 108 repair set; the
        # analyzer-side qualified-name lookup is covered by the Fix 150
        # registry short-tail fallback in _is_repair_function).
        # Fix 150b: + quoted — DBManager::quoted() (value wrapped in
        # quotes + escaped, used by retrieve() WHERE :4593) is a genuine
        # SQL-string encoder; SugarBean.php:4599 limitQuery row was FP.
        'repair_functions': {'quote', 'quoteIdentifier', 'quoted'},
        # Fix 149b (CVE-2026-63214): legacy REST/SOAP RPC entry classes.
        # service/core/webservice.php instantiates SugarWebServiceImplv4_1
        # (via registerImplClass) and SugarRestJSON::serve dispatches
        # `$this->implementation->{$_REQUEST['method']}(...$data)` with the
        # JSON-decoded $_REQUEST['rest_data'] payload — every public method
        # of the SugarWebServiceImpl family (core + v2..v4_1 subclasses,
        # prefix-matched) is a network-facing endpoint.
        'rpc_entry_classes': {'sugarwebserviceimpl'},
    },
    'cakephp': {
        # Fix 119a (CVE-2026-44381): CakePHP 2.x (MISP et al.) —
        # CakeRequest instance receivers: $request->query('x') /
        # $request->data('x') / $request->param('x') / input().
        'request_object_names': {'request', '$request'},
        # CakeRequest::query($name)/data($name)/param($name)/input() all
        # return attacker-controlled request payloads (lib/Cake/Network/
        # CakeRequest.php @ 2.x).  Property forms ($request->query['x'])
        # are covered via the cross-product source_members + Fix 119b
        # prefix semantics.
        'request_methods': {'query', 'data', 'param', 'input'},
        'global_source_functions': set(),
        # Controller property-form sources (CakePHP 2.x Controller):
        #   $this->request    — the CakeRequest object itself; ArrayAccess
        #                       reads ($this->request['named']['sort']) and
        #                       every property under it are user data
        #   $this->passedArgs — URL named + pass params (MISP index sort)
        #   $this->params     — request params merge (deprecated alias)
        # 'Model::$data' (current record) is deliberately NOT registered:
        # same chain name, different semantics (DB record vs request body)
        # — registering it would taint every beforeSave body.
        'extra_source_members': {
            '$this.request', 'this.request',
            '$this.passedArgs', 'this.passedArgs',
            '$this.params', 'this.params',
        },
        # Fix 119g (CVE-2026-44381): the property chains above are
        # Controller(+/Helper) state.  The same chain names exist in other
        # classes with different semantics — Shell::$params is CLI argv,
        # Cache/Log/Configure internals hold no request data — so they are
        # gated by the reading file's class scope (SourceRegistry.
        # _resolve_member_scope).  MISP task 6510 evidence: ServerShell
        # system($this->params[...]) command-injection FP et al.
        'member_scope': {
            '$this.request': ('controller', 'view_helper'),
            'this.request': ('controller', 'view_helper'),
            '$this.passedArgs': ('controller',),
            'this.passedArgs': ('controller',),
            '$this.params': ('controller',),
            'this.params': ('controller',),
        },
    },
    'symfony': {
        'request_object_names': {'request', '$request'},
        'request_methods': {
            'get', 'query', 'request', 'getContent', 'getPayload',
            'toArray', 'getBasePath', 'getBaseUrl', 'getRequestUri',
            'getParameter', 'getParameterHolder', 'getFiles',
        },
        # Fix 67: symfony 1.x form proxy — bind(tainted, ...) taints the
        # form object; $form['field'] / ->getValue() reads become sources.
        'form_bind_propagates_taint': True,
        # 这些通过链式调用（query→get）使用，需要特殊处理
        'parameter_bag_methods': {'get', 'all', 'has', 'set', 'remove'},
        'global_source_functions': set(),
        # 方法返回值经过安全转换（hash/枚举/常量），不应传播污点
        'safe_return_methods': {
            'getCacheKey', 'getScheme', 'getHost', 'getPort',
            'getHttpHost', 'getBaseUrl', 'getBasePath', 'getPathInfo',
            'getSchemeAndHttpHost',
        },
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

            # Fix 86: OpenEMR — project-type composer.json (name: openemr/openemr).
            # MUST run before the dependency loop: OpenEMR itself depends on
            # symfony/* components, which would otherwise claim it as symfony.
            if data.get('name') == 'openemr/openemr':
                return 'openemr'

            # Fix 146b (CVE-2026-100365): SuiteCRM — project-type composer.json
            # (name: suitecrm/suitecrm).  Same ordering rationale as OpenEMR:
            # must precede the dependency loop (symfony/* tooling deps).
            if data.get('name') == 'suitecrm/suitecrm':
                return 'suitecrm'

            # Fix 119a (CVE-2026-44381): CakePHP — before symfony/*: cake
            # apps commonly pull symfony/console etc. as build tooling.
            if any(dep == 'cakephp/cakephp' or dep.startswith('cakephp/')
                   for dep in deps):
                return 'cakephp'

            for dep in deps:
                if dep == 'slim/slim' or dep.startswith('slim/'):
                    return 'slim'
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

    # Fix 119a (CVE-2026-44381): CakePHP 2.x — composer.json can live at
    # app/ level (cake2 app skeleton; MISP) with the framework vendored
    # as a submodule instead of a composer dependency.
    _cake_composer = os.path.join(project_dir, 'app', 'composer.json')
    if os.path.isfile(_cake_composer):
        try:
            with open(_cake_composer, 'r', encoding='utf-8') as f:
                _cake_data = json.load(f)
            _cake_deps = {}
            _cake_deps.update(_cake_data.get('require', {}))
            _cake_deps.update(_cake_data.get('require-dev', {}))
            if any(dep == 'cakephp/cakephp' or dep.startswith('cakephp/')
                   for dep in _cake_deps):
                return 'cakephp'
        except (json.JSONDecodeError, OSError):
            pass
    # Fix 119a: directory fingerprints — classic app skeleton (lib/Cake),
    # MISP-style vendored submodule (app/Lib/cakephp), or a bare cake2
    # app tree (app/Controller + app/Model; thinkphp/laravel/ci use
    # different casing so no clash on case-sensitive filesystems).
    if (os.path.isdir(os.path.join(project_dir, 'lib', 'Cake'))
            or os.path.isdir(os.path.join(project_dir, 'app', 'Lib', 'cakephp'))
            or (os.path.isdir(os.path.join(project_dir, 'app', 'Controller'))
                and os.path.isdir(os.path.join(project_dir, 'app', 'Model')))):
        return 'cakephp'

    # Fallback: directory structure
    # Fix 86: OpenEMR — vendored app tree (library/sql.inc.php DB layer +
    # interface/ controllers + sites/ instances) marks the app even when
    # composer.json is stripped from a partial scan target.
    if (os.path.isfile(os.path.join(project_dir, 'library', 'sql.inc.php'))
            and os.path.isdir(os.path.join(project_dir, 'interface'))):
        return 'openemr'
    # Fix 146b (CVE-2026-100365): SuiteCRM — suitecrm_version.php is a
    # SuiteCRM-only fingerprint (SugarCRM apps carry sugar_version.php).
    if (os.path.isfile(os.path.join(project_dir, 'suitecrm_version.php'))
            and os.path.isdir(os.path.join(project_dir, 'modules'))):
        return 'suitecrm'
    # Fix 67: symfony 1.x (1.4-era) — vendored framework tree inside the
    # project (qdPM: core/lib/symfony; classic apps: lib/symfony)
    for _sf in (('core', 'lib', 'vendor', 'symfony'), ('core', 'lib', 'symfony'),
                ('lib', 'symfony'), ('lib', 'vendor', 'symfony')):
        if os.path.isdir(os.path.join(project_dir, *_sf)):
            return 'symfony'
    if os.path.isdir(os.path.join(project_dir, 'app', 'Http', 'Controllers')):
        return 'laravel'
    if os.path.isdir(os.path.join(project_dir, 'app', 'controller')):
        return 'thinkphp'
    if os.path.isdir(os.path.join(project_dir, 'application', 'controllers')):
        return 'codeigniter'

    # Fix 52r: WordPress plugin detection — hooks entry files
    # (add_action / register_rest_route / register_activation_hook)
    # anywhere in the tree mark a WordPress plugin; framework sources
    # then annotate REST/ajax callback parameters.
    for _root, _dirs, _fs in os.walk(project_dir):
        if 'vendor' in _root:
            continue
        for _f in _fs:
            if not _f.endswith('.php'):
                continue
            try:
                with open(os.path.join(_root, _f), 'r', encoding='utf-8', errors='ignore') as _fh:
                    _head = _fh.read(200000)
                if ('add_action(' in _head or 'register_rest_route(' in _head
                        or 'register_activation_hook(' in _head
                        # Fix 69: add_filter registers filter callbacks the same
                        # way add_action registers action callbacks (WP unifies
                        # them); posts_where/preview filters carry request data.
                        or 'add_filter(' in _head):
                    return 'wordpress'
            except OSError:
                continue
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
