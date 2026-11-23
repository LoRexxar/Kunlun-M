"""UseEdgeBuilder — derives call operator → function use edges from AST.

Runs after DFG builder (needs dfg edges for receiver type resolution).
Before CG builder (cg builder depends on use edges).

This builder replaces the per-normalizer use edge generation that
previously ran during AST mapping (phase 1).  Moving to phase 2
enables:

- Receiver type resolution using java_type / dtype attributes set
  during normalization (field/variable declarations).
- DFG backward tracing for receiver types (assigned from method
  calls or other variables).
- Correct ``fullname`` on external function nodes (e.g.
  ``Unmarshaller.unmarshal`` instead of ``this.um.unmarshal``).
- Future extensibility (return type inference, cross-file resolution).
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig

from core.graph.edge_builders.base import BaseEdgeBuilder
from core.graph.node_edge_schema import (
    EdgeLabel,
    FunctionType,
    NodeLabel,
    OperatorType,
    CgCallType,
)
from utils.igraph_compat import _vattr

logger = logging.getLogger(__name__)

_CALL_TYPES = {
    OperatorType.CALL.value,
    OperatorType.STATIC_CALL.value,
    OperatorType.METHOD_CALL.value,
    OperatorType.NEW.value,
}


class UseEdgeBuilder(BaseEdgeBuilder):
    """Derive call→function use edges with receiver type resolution.

    For each call/static_call/method_call operator node:
      1. Extract callee method name from ast[callee] edges.
      2. Determine receiver type (java_type/dtype) for method calls:
         a. Check identifier nodes along callee/member chain.
         b. Trace DFG backward (up to 5 hops) for assignment sources.
      3. Build qualified fullname = ``Type.method`` when type found.
      4. Find or create target function node and add use edge.
    """

    def build(self, graph: "ig.Graph", language: str = "", **kwargs) -> int:
        if graph.vcount() == 0:
            return 0

        # ── 预构建边索引：O(E) 一次遍历，替代后续所有 es.select() ──
        self._ast_src_from: dict[int, list[tuple[int, str]]] = defaultdict(list)
        self._ast_to: dict[int, list[tuple[int, str]]] = defaultdict(list)
        self._member_to: dict[int, list[int]] = defaultdict(list)
        self._own_to: dict[int, list[int]] = defaultdict(list)
        self._dfg_to: dict[int, list[int]] = defaultdict(list)
        self._incoming_to: dict[int, list[int]] = defaultdict(list)
        # use 边索引（已存在的 use 边，用于去重）
        self._use_pairs: set[tuple[int, int]] = set()
        # Fix 97: python 同名有体函数索引（懒构建，duck-typing 虚分发）
        self._py_dispatch_idx: dict[str, list[int]] | None = None
        # Fix 137g: java 接口虚分发 — implements 关系（cr g 边 class→external class）
        # 与 接口方法判定缓存（target_vid → 接口名或 ''）
        self._iface_implementors: dict[str, set[str]] = defaultdict(set)
        self._iface_of_target: dict[int, str] = {}
        # Fix 143a (CVE-2026-129448): java class-hierarchy indexes —
        # extends-only child→parent map (super-call walks), and the set of
        # corpus class-declaration names (virtual-dispatch fan gating).
        self._cls_extends: dict[str, str] = {}
        self._cls_decl_names: set[str] = set()
        self._subtype_closure_cache: dict[str, tuple[str, ...]] = {}

        # ── 预缓存节点属性 — 避免 15s+ 的 _vattr/graph.vs 开销 ──
        n = graph.vcount()
        self._vlabel: list[str] = [""] * n
        self._vname: list[str] = [""] * n
        self._vtype: list[str] = [""] * n
        self._vpath: list[str] = [""] * n
        self._vlineno: list[int] = [0] * n
        self._vfile_path: list[str] = [""] * n
        self._vis_external: list[bool] = [False] * n
        self._vfullname: list[str] = [""] * n
        self._vjava_type: list[str] = [""] * n
        self._vdtype: list[str] = [""] * n
        self._vreturn_type: list[str] = [""] * n
        self._vvalue: list[str] = [""] * n
        self._vraw_type: list[str] = [""] * n
        for v in graph.vs:
            i = v.index
            self._vlabel[i] = _vattr(v, "label", "")
            self._vname[i] = _vattr(v, "name", "")
            self._vtype[i] = _vattr(v, "type", "")
            self._vpath[i] = _vattr(v, "path", "")
            self._vlineno[i] = _vattr(v, "lineno", 0) or 0
            self._vfile_path[i] = _vattr(v, "file_path", "") or ""
            self._vis_external[i] = _vattr(v, "is_external", False)
            self._vfullname[i] = _vattr(v, "fullname", "") or ""
            self._vjava_type[i] = _vattr(v, "java_type", "") or ""
            self._vdtype[i] = _vattr(v, "dtype", "") or ""
            self._vreturn_type[i] = _vattr(v, "return_type", "") or ""
            self._vvalue[i] = _vattr(v, "value", "") or ""
            self._vraw_type[i] = _vattr(v, "raw_type", "") or ""

        for e in graph.es:
            elabel = _vattr(e, "label", "")
            if elabel == "ast":
                role = _vattr(e, "role", "")
                self._ast_src_from[e.source].append((e.target, role))
                self._ast_to[e.target].append((e.source, role))
            elif elabel == "member":
                self._member_to[e.target].append(e.source)
            elif elabel == "crg":
                # Fix 137g: class→external-class 引用边在 java 里承载
                # implements/extends 关系；只收 class→(external class)，
                # 外部节点名=接口/父类简名。
                if (self._vlabel[e.source] == "class"
                        and self._vlabel[e.target] == "class"
                        and self._vis_external[e.target]
                        and self._vfullname[e.source]):
                    self._iface_implementors[self._vname[e.target]].add(
                        self._vfullname[e.source])
                    # Fix 143a (CVE-2026-129448): extends-only map for
                    # super-call resolution (implements edges must NOT be
                    # walked by super.X()).  crg edges carry the direction
                    # in attrs.type (extends/implements).
                    if _vattr(e, "type", "") == "extends":
                        self._cls_extends[self._vname[e.source]] = \
                            self._vname[e.target]
            elif elabel == "own":
                self._own_to[e.target].append(e.source)
            elif elabel == "dfg":
                self._dfg_to[e.target].append(e.source)
            elif elabel == "use":
                self._use_pairs.add((e.source, e.target))
            self._incoming_to[e.target].append(e.source)

        self._ast_src_from = dict(self._ast_src_from)
        self._ast_to = dict(self._ast_to)
        self._member_to = dict(self._member_to)
        self._own_to = dict(self._own_to)
        self._dfg_to = dict(self._dfg_to)
        self._incoming_to = dict(self._incoming_to)

        # ── 函数节点索引：替代 vs.select(label="function") 的 O(V) 遍历 ──
        self._func_fullname_idx: dict[str, int] = {}
        self._func_name_file_idx: dict[str, dict[str, int]] = defaultdict(dict)
        self._func_name_ext_idx: dict[str, list[int]] = defaultdict(list)

        for v in graph.vs:
            i = v.index
            if self._vlabel[i] != NodeLabel.FUNCTION.value:
                continue
            fn = self._vfullname[i]
            if fn:
                self._func_fullname_idx[fn] = i
            name = self._vname[i]
            if not name:
                continue
            fp = self._vfile_path[i]
            is_ext = self._vis_external[i]
            if fp and not is_ext:
                self._func_name_file_idx[name][fp] = i
            if is_ext:
                self._func_name_ext_idx[name].append(i)
        self._func_name_ext_idx = dict(self._func_name_ext_idx)

        # Fix 143c (CVE-2026-129448): corpus class-declaration names
        # (classes actually declared in the corpus — virtual-dispatch fan
        # only fires for receivers whose declared type is one of these).
        for v in graph.vs:
            i = v.index
            if self._vlabel[i] == "class" and self._vraw_type[i]:
                nm = self._vname[i]
                if nm:
                    self._cls_decl_names.add(nm)

        # ── enclosing function 缓存 ──
        self._enclosing_fn_cache: dict[int, int | None] = {}
        self._enclosing_fn_lineno_cache: dict[int, tuple[int, int] | None] = {}

        # ── 预计算所有节点的 enclosing function，避免 _resolve_receiver_type 中重复 fallback 遍历 ──
        for vid in range(n):
            self._enclosing_function(graph, vid)
        for vid in range(n):
            self._enclosing_function_lineno(graph, vid)

        # ── 收集 callee_targets set ──
        callee_targets: set[int] = set()
        for src_vid, targets in self._ast_src_from.items():
            for tgt, role in targets:
                if role == "callee":
                    callee_targets.add(tgt)

        # Identify callee_targets that have their own args
        callee_with_args: set[int] = set()
        for ct_vid in callee_targets:
            ast_edges = self._ast_src_from.get(ct_vid, [])
            if any(role == "arg" for _, role in ast_edges):
                callee_with_args.add(ct_vid)

        # Build name → [vid] index for identifier/parameter lookup
        name_index: dict[str, list[int]] = {}
        for v in graph.vs:
            i = v.index
            if self._vlabel[i] in (NodeLabel.IDENTIFIER.value, NodeLabel.PARAMETER.value):
                name = self._vname[i]
                if name:
                    name_index.setdefault(name, []).append(i)

        # ── 遍历 operator 节点，生成 use 边 ──
        count = 0
        use_edges: list[tuple[int, int]] = []
        use_attrs: list[dict] = []

        for v in graph.vs:
            vid = v.index
            if self._vlabel[vid] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[vid] not in _CALL_TYPES:
                continue
            if vid in callee_targets and vid not in callee_with_args:
                continue

            lineno = self._vlineno[vid]
            op_name = self._vname[vid]
            op_type = self._vtype[vid]

            # Determine call_type
            if op_type == OperatorType.STATIC_CALL.value:
                cg_call_type = CgCallType.STATIC.value
            elif op_type == OperatorType.METHOD_CALL.value:
                cg_call_type = CgCallType.METHOD.value
            else:
                cg_call_type = CgCallType.DIRECT.value

            # Extract callee method name and call_type override from qualifier
            callee_name = self._extract_callee_name(graph, vid, op_name)
            if not callee_name:
                continue

            # Resolve receiver type for method/static calls
            resolved_type = None
            if op_type in (OperatorType.METHOD_CALL.value,
                           OperatorType.STATIC_CALL.value):
                resolved_type = self._resolve_receiver_type(
                    graph, vid, callee_name, name_index)

            # ── Fix 143a (CVE-2026-129448): super-call resolution ──
            # `super.execute(...)`, `super.characters(...)`,
            # `Qualifier.super.member(...)`: the callee identifier emitted
            # by the normalizer is literally "super", so every super call
            # previously bound to an empty external stub and the whole
            # superclass callgraph leg was invisible (xmlrpc chain:
            # XmlRpcServletServer.execute → super.execute →
            # XmlRpcStreamServer.execute carried the request stream).
            # Resolve to the enclosing class's EXTENDS chain (implements
            # edges are never walked by super.X()).
            _super_method = ""
            if callee_name == "super" and op_name and "." in op_name:
                _super_method = op_name.rsplit(".", 1)[1]
            if _super_method and language == "java":
                _enc = self._enclosing_class_name_ast(graph, vid)
                if _enc:
                    for _anc in self._java_superclass_chain(_enc):
                        _sv = self._func_fullname_idx.get(
                            f"{_anc}.{_super_method}")
                        if _sv is not None and self._vfile_path[_sv]:
                            if (vid, _sv) not in self._use_pairs:
                                self._use_pairs.add((vid, _sv))
                                use_edges.append((vid, _sv))
                                use_attrs.append({
                                    "label": "use",
                                    "call_type": cg_call_type,
                                    "lineno": lineno,
                                })
                                count += 1
                            break

            # ── Fix 143b (CVE-2026-129448): implicit-this inherited call ──
            # A bare method call `setResult(...)` / `.writeBuffer(...)`
            # inside class C executes C's own method or one inherited from
            # the superclass chain.  The generic path bound these to
            # same-file or external stubs (ByteArrayParser.endElement's
            # setResult never reached TypeParserImpl.setResult; Base64
            # Decoder.write's writeBuffer hit Encoder.writeBuffer — a
            # sibling nested class — via the same-file name fallback).
            # Try the own-class + extends chain BEFORE generic resolution.
            _implicit_this = (
                language == "java"
                and callee_name != "super"
                and op_name
                and not op_name.startswith("this.")
                and ("." not in op_name or op_name.startswith("."))
            )
            if _implicit_this:
                _enc = self._enclosing_class_name_ast(graph, vid)
                if _enc:
                    _iv = self._java_lookup_method(graph, _enc, callee_name)
                    if _iv is not None:
                        if (vid, _iv) not in self._use_pairs:
                            self._use_pairs.add((vid, _iv))
                            use_edges.append((vid, _iv))
                            use_attrs.append({
                                "label": "use",
                                "call_type": cg_call_type,
                                "lineno": lineno,
                            })
                            count += 1
                        # Fix 143k (CVE-2026-129448): the own-chain hit is
                        # an abstract/interface method (no body) — the
                        # runtime dispatch target is an override in the
                        # enclosing class's subtype closure (xmlrpc:
                        # Decoder.write's writeBuffer → Base64$76 override).
                        if not self._fn_has_body(graph, _iv):
                            _tcls = self._class_of_function(graph, _iv)
                            if _tcls:
                                for _child in self._java_subtype_closure(_tcls):
                                    _fv = self._func_fullname_idx.get(
                                        f"{_child}.{callee_name}")
                                    if (_fv is not None
                                            and self._vfile_path[_fv]
                                            and _fv != _iv
                                            and (vid, _fv) not in self._use_pairs):
                                        self._use_pairs.add((vid, _fv))
                                        use_edges.append((vid, _fv))
                                        use_attrs.append({
                                            "label": "use",
                                            "call_type": cg_call_type,
                                            "lineno": lineno,
                                        })
                                        count += 1
                        continue

            # Fix 97 (CVE-2026-29080): python duck-typed multi-target
            # dispatch.  An opaque-receiver method call
            # (`selected_plugin_to_use.list_dids(...)`,
            # `metadata_plugin.manages_key(...)`) can dispatch to ANY
            # same-named method at runtime — rucio builds its plugin
            # registry via importlib+getattr, so no static receiver type
            # exists.  The old path resolved the callee through the name
            # index and bound ONE arbitrary same-name function: a
            # deterministic mis-bind that both missed the real targets
            # and stole the call edge (dispatcher call at
            # did_meta_plugins/__init__.py:249 bound to gateway
            # did.py:36 list_dids instead of the four plugin list_dids).
            # Bind to ALL non-external same-named python functions
            # instead (standard virtual-dispatch over-approximation for
            # duck typing).  Guards: python only; >1 candidates (a lone
            # candidate is already found by the normal single-bind
            # path); <=8 candidates (utility-name storms like `get`/
            # `run` across a big corpus keep the old behavior).
            if (language == "python"
                    and op_type == OperatorType.METHOD_CALL.value
                    and resolved_type is None):
                _cands = self._py_dispatch_candidates(graph, callee_name)
                if _cands:
                    for _tgt in _cands:
                        if (vid, _tgt) not in self._use_pairs:
                            self._use_pairs.add((vid, _tgt))
                            use_edges.append((vid, _tgt))
                            use_attrs.append({
                                "label": "use",
                                "call_type": cg_call_type,
                                "lineno": lineno,
                            })
                            count += 1
                    continue

            # Build fullname
            if resolved_type:
                fullname = f"{resolved_type}.{callee_name}"
                # Fix 143i (CVE-2026-129448): java nested-class receivers
                # resolve under the SIMPLE nested name — corpus methods of
                # `Base64.Decoder` are indexed as `Decoder.write`, so the
                # qualified form only ever matched (or created) an external
                # stub and the call edge left the corpus.
                if (language == "java" and "." in resolved_type
                        and self._func_fullname_idx.get(fullname) is None):
                    _simple = f"{resolved_type.rsplit('.', 1)[-1]}.{callee_name}"
                    if self._func_fullname_idx.get(_simple) is not None:
                        fullname = _simple
            elif op_type == OperatorType.NEW.value:
                fullname = callee_name
            else:
                # Fix 106 (CVE-2026-126482): PHP static calls carry a
                # qualified fullname from the normalizer (e.g.
                # 'SLEOB.slInvoiceNumber') even when receiver-type
                # resolution fails (no dtype on the class-ref identifier).
                # Prefer it over the bare callee name — the bare name
                # matched a synthetic external stub instead of the real
                # method, cutting the callgraph at every Class::method()
                # in name-imported (use ...;) code.
                cand = op_name or ""
                if op_type == OperatorType.STATIC_CALL.value:
                    op_fn = self._vfullname[vid]
                    if op_fn and "." in op_fn:
                        cand = op_fn
                fullname = cand or callee_name

            func_name = callee_name

            # Find existing function node or create external one
            caller_file = self._vfile_path[vid]
            # Fix 137f (CVE-2026-83542 OFBiz): for receiver-RELATIVE call
            # names ("this.x", "$this->x", "self::x", "cls.x") resolve the
            # enclosing class's own method first — see the guard inside
            # _find_or_create_function.
            enc_cls = None
            if op_type == OperatorType.METHOD_CALL.value:
                enc_cls = self._enclosing_class_name(graph, vid)
            target_vid = self._find_or_create_function(
                graph, func_name, fullname, lineno,
                caller_file=caller_file, enclosing_class=enc_cls or ""
            )

            if target_vid is not None:
                if (vid, target_vid) not in self._use_pairs:
                    self._use_pairs.add((vid, target_vid))
                    use_edges.append((vid, target_vid))
                    use_attrs.append({
                        "label": "use",
                        "call_type": cg_call_type,
                        "lineno": lineno,
                    })
                    count += 1

                # Fix 137g (CVE-2026-83542 OFBiz): java 接口虚分发。
                # 当调用绑定的 target 是 corpus 内声明的接口方法
                # （enclosing class raw_type=InterfaceDeclaration，无体），
                # 运行时实际执行的是某个实现类的同签名方法——把 use 边
                # 同时建到所有 implements 该接口的类（crg implements 索引）
                # JDK 接口（Serializable/Map…）在 corpus 无
                # InterfaceDeclaration 节点，天然不触发，无边爆炸。
                # java 里小写接收者的实例调用常被归为 static_call
                # （resolver.resolveLocation），两种类型都放行——真正的
                # 闸门是 target 的 InterfaceDeclaration 判定。
                if op_type in (OperatorType.METHOD_CALL.value,
                               OperatorType.STATIC_CALL.value):
                    for impl_vid in self._java_iface_dispatch_targets(
                            graph, target_vid, func_name):
                        if (vid, impl_vid) not in self._use_pairs:
                            self._use_pairs.add((vid, impl_vid))
                            use_edges.append((vid, impl_vid))
                            use_attrs.append({
                                "label": "use",
                                "call_type": cg_call_type,
                                "lineno": lineno,
                            })
                            count += 1

                    # ── Fix 143c (CVE-2026-129448): subtype-closure
                    # virtual dispatch ──
                    # Two shapes the 137g direct-implementor fan misses:
                    # (a) receiver's DECLARED type is a corpus class or
                    #     interface but the bound target sits elsewhere
                    #     (same-file mis-bind / base-class method): the
                    #     runtime callee is any same-name method in the
                    #     receiver type's SUBTYPE CLOSURE — xmlrpc
                    #     `typeParser.getResult` (TypeParser interface,
                    #     real target SerializableParser.getResult two
                    #     subclass hops down).
                    # (b) the bound target has NO body (interface method
                    #     or abstract): overrides in the enclosing class's
                    #     subtype closure are the real dispatch targets —
                    #     xmlrpc Base64 Decoder.writeBuffer (abstract) →
                    #     the anonymous override in ByteArrayParser.
                    # Both fans only bind corpus (file-backed) nodes and
                    # cap the closure at 16 classes.
                    _fan_targets: set[int] = set()
                    if language == "java":
                        if resolved_type:
                            _rt = resolved_type.rsplit(".", 1)[-1]
                            if (_rt in self._cls_decl_names
                                    or _rt in self._iface_implementors):
                                for _child in self._java_subtype_closure(
                                        resolved_type):
                                    _fv = self._func_fullname_idx.get(
                                        f"{_child}.{callee_name}")
                                    if (_fv is not None
                                            and self._vfile_path[_fv]
                                            and _fv != target_vid):
                                        _fan_targets.add(_fv)
                        if (target_vid is not None
                                and self._vfile_path[target_vid]
                                and not self._fn_has_body(
                                    graph, target_vid)):
                            _tcls = self._class_of_function(graph, target_vid)
                            if _tcls:
                                for _child in self._java_subtype_closure(
                                        _tcls):
                                    _fv = self._func_fullname_idx.get(
                                        f"{_child}.{callee_name}")
                                    if (_fv is not None
                                            and self._vfile_path[_fv]
                                            and _fv != target_vid):
                                        _fan_targets.add(_fv)
                    for _fv in _fan_targets:
                        if (vid, _fv) not in self._use_pairs:
                            self._use_pairs.add((vid, _fv))
                            use_edges.append((vid, _fv))
                            use_attrs.append({
                                "label": "use",
                                "call_type": cg_call_type,
                                "lineno": lineno,
                            })
                            count += 1

        # ── 批量写入 use 边 ──
        if use_edges:
            graph.add_edges(use_edges)
            n_existing = graph.ecount() - len(use_edges)
            for i, attrs in enumerate(use_attrs):
                eid = n_existing + i
                for k, val in attrs.items():
                    graph.es[eid][k] = val

        # ── Fix 143d (CVE-2026-129448): SAX parse → ContentHandler
        # dispatch (xmlrpc-style framework callback bridging) ──
        count += self._sax_dispatch_edges(graph)

        # ── Fix 106 (CVE-2026-126482): string-const callback dispatch ──
        # PHP dynamic call `$cb($out)` where the callee variable is a
        # formal parameter bound at the (sole/all) call site(s) of the
        # enclosing function to a string constant naming a defined
        # function (parseERA($tmp, 'era_payments_callback')).  Rebuild
        # the use edge from the caller's const arg so the callgraph
        # reaches the callback body.
        count += self._resolve_string_callbacks(graph)

        return count

    def _resolve_string_callbacks(self, graph: "ig.Graph") -> int:
        """Bind variable-callee calls to functions named by const args.

        For each `call` operator whose callee is a variable that is a
        formal param of the enclosing function, collect the const-string
        values that can reach that param position through caller chains
        (direct const arg, param-to-param pass-through, one-hop const
        assignment via dfg), and add a use edge to each defined function
        named by those constants.  Only binds to real (file-backed,
        non-external) function nodes; caps distinct targets at 8.
        """
        # use-edge reverse index: function vid → caller op vids
        callers_of: dict[int, list[int]] = defaultdict(list)
        for (src, tgt) in self._use_pairs:
            if self._vlabel[tgt] == NodeLabel.FUNCTION.value:
                callers_of[tgt].append(src)

        added = 0
        new_edges: list[tuple[int, int]] = []
        new_attrs: list[dict] = []
        for v in graph.vs:
            vid = v.index
            if self._vlabel[vid] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[vid] != OperatorType.CALL.value:
                continue
            callee_name = self._extract_callee_name(
                graph, vid, self._vname[vid])
            if not callee_name or not callee_name.startswith("$"):
                continue
            enc = self._enclosing_function(graph, vid)
            if enc is None:
                continue
            param_idx = self._param_position(graph, enc, callee_name)
            if param_idx is None:
                continue

            values = self._collect_const_values(
                graph, enc, param_idx, callers_of)
            if not values:
                import os
                if os.environ.get("KM_DBG_CB"):
                    print(f"[cb-dbg] op {vid} enc={enc} pidx={param_idx}: "
                          f"no values (callers={callers_of.get(enc, [])})")
                continue

            targets: dict[str, int] = {}
            for fname in values:
                if len(targets) >= 8:
                    break
                cand = self._func_name_file_idx.get(fname, {}).get(
                    self._vfile_path[vid])
                if cand is None:
                    fids = list(
                        self._func_name_file_idx.get(fname, {}).values())
                    if len(fids) == 1:
                        cand = fids[0]
                if cand is not None:
                    targets.setdefault(fname, cand)

            for _fname, tgt_vid in targets.items():
                if (vid, tgt_vid) in self._use_pairs:
                    continue
                self._use_pairs.add((vid, tgt_vid))
                new_edges.append((vid, tgt_vid))
                new_attrs.append({
                    "label": "use",
                    "call_type": CgCallType.DIRECT.value,
                    "lineno": self._vlineno[vid],
                })
                added += 1

        if new_edges:
            graph.add_edges(new_edges)
            n_existing = graph.ecount() - len(new_edges)
            for i, attrs in enumerate(new_attrs):
                eid = n_existing + i
                for k, val in attrs.items():
                    graph.es[eid][k] = val
        return added

    def _param_position(self, graph: "ig.Graph", fn_vid: int,
                        var_name: str) -> int | None:
        """Positional index of the formal param named var_name (params
        carry no `index` attr — mirror the analyzer's positional
        convention from own-edge order).  NB: ``_own_to`` is a
        child→parent index; children must come from own OUT-edges."""
        pos = 0
        for eid in graph.incident(fn_vid, mode="out"):
            e = graph.es[eid]
            if _vattr(e, "label", "") != "own":
                continue
            tgt = e.target
            if self._vlabel[tgt] == NodeLabel.PARAMETER.value:
                if self._vname[tgt] == var_name:
                    return pos
                pos += 1
        return None

    def _arg_at(self, graph: "ig.Graph", call_vid: int,
                position: int) -> int | None:
        """vid of the arg at `position` (positional, like the analyzer)."""
        arg_counter = 0
        for eid in graph.incident(call_vid, mode="out"):
            e = graph.es[eid]
            if _vattr(e, "label", "") != "ast":
                continue
            if _vattr(e, "role", "") != "arg":
                continue
            if arg_counter == position:
                return e.target
            arg_counter += 1
        return None

    def _collect_const_values(self, graph: "ig.Graph", fn_vid: int,
                              param_idx: int,
                              callers_of: dict[int, list[int]],
                              depth: int = 0,
                              seen: set[int] | None = None) -> set[str]:
        """Const-string values that can reach (fn_vid, param_idx).

        Bounded backward walk over caller chains:
        * direct const-string actual arg,
        * actual arg that is the caller function's own formal param
          (pass-through: parseERA2100($out, $cb) ← parseERA(..., $cb)),
        * one-hop dfg const assignment into the actual arg identifier.
        """
        values: set[str] = set()
        if depth > 4:
            return values
        if seen is None:
            seen = set()
        if fn_vid in seen:
            return values
        seen.add(fn_vid)

        for caller_op in callers_of.get(fn_vid, ()):
            if self._vlabel[caller_op] != NodeLabel.OPERATOR.value:
                continue
            arg_vid = self._arg_at(graph, caller_op, param_idx)
            if arg_vid is None:
                continue
            fname = self._const_string_value(arg_vid)
            if fname:
                values.add(fname)
                continue
            # pass-through: arg is the caller's own formal param
            caller_fn = self._enclosing_function(graph, caller_op)
            if caller_fn is not None:
                arg_name = self._vname[arg_vid]
                if arg_name:
                    pidx = self._param_position(graph, caller_fn, arg_name)
                    if pidx is not None:
                        values |= self._collect_const_values(
                            graph, caller_fn, pidx, callers_of,
                            depth + 1, seen)
            # one-hop const assignment: $x = 'name'; f($x)
            for src_vid in self._dfg_to.get(arg_vid, ()):
                fname = self._const_string_value(src_vid)
                if fname:
                    values.add(fname)
        return values

    def _const_string_value(self, vid: int) -> str | None:
        """Sanitized function-name string if vid is a string const."""
        if self._vlabel[vid] != NodeLabel.CONST.value:
            return None
        raw = self._vvalue[vid] or self._vname[vid]
        if not raw:
            return None
        fname = str(raw).strip("'\" ")
        if not fname or not fname.replace("_", "a").isalnum():
            return None
        return fname

    # -- helpers -----------------------------------------------------------

    def _extract_callee_name(self, graph: "ig.Graph", op_vid: int,
                             op_name: str) -> str:
        """Extract callee method name from ast[callee] edges."""
        callee_names: list[tuple[str, int]] = []
        for tgt, role in self._ast_src_from.get(op_vid, []):
            if role == "callee":
                t = graph.vs[tgt]
                name = self._vname[tgt] or self._vvalue[tgt]
                if name:
                    callee_names.append((name, t.index))

        for name, tvid in reversed(callee_names):
            if self._vlabel[tvid] == NodeLabel.IDENTIFIER.value:
                return name
        if callee_names:
            return callee_names[-1][0]
        if op_name:
            parts = op_name.replace("::", ".").rsplit(".", 1)
            if len(parts) == 2 and parts[1]:
                return parts[1]
            # Fix 31e: bare function call ("gets", "dir" -- no qualifier).
            # The previous fallback returned "" here, so bare calls never
            # got a use edge to their function stub and builtin-knowledge
            # annotations (source/safe) on that stub were unreachable from
            # the call site.
            return parts[0]
        return ""

    def _resolve_receiver_type(self, graph: "ig.Graph", op_vid: int,
                               callee_name: str,
                               name_index: dict[str, list[int]]) -> str | None:
        """Resolve the declared type of the method call's receiver."""
        receiver_names = self._get_receiver_ident_names(graph, op_vid)
        if not receiver_names:
            op_name = self._vname[op_vid]
            if op_name and "." in op_name:
                parts = op_name.replace("::", ".").rsplit(".", 1)
                prefix = parts[0].rsplit(".", 1)[-1]
                if prefix and prefix not in ("this", "self", "super", "cls"):
                    receiver_names = [prefix]
        if not receiver_names:
            return None

        call_file = self._vfile_path[op_vid]
        op_scope = self._enclosing_function_lineno(graph, op_vid)

        for qualifier_name in receiver_names:
            candidates = name_index.get(qualifier_name, [])
            same_scope: list[int] = []
            same_file: list[int] = []
            other_file: list[int] = []
            # 限制候选数量，避免同文件同名变量过多导致性能问题
            for vid in candidates[:50]:
                cand_scope = self._enclosing_function_lineno(graph, vid)
                if op_scope and cand_scope and op_scope[0] == cand_scope[0]:
                    same_scope.append(vid)
                else:
                    vfile = self._vfile_path[vid]
                    if vfile == call_file:
                        same_file.append(vid)
                    else:
                        other_file.append(vid)
            sorted_candidates = same_scope + same_file + other_file

            for vid in sorted_candidates:
                dtype = self._vjava_type[vid] or self._vdtype[vid]
                if dtype and dtype != "var":
                    return dtype

                # Trace DFG backward to find definition site
                visited: set[int] = set()
                current = vid
                for _ in range(5):
                    if current in visited:
                        break
                    visited.add(current)
                    for src_vid in self._get_dfg_sources(graph, current):
                        dtype = self._vjava_type[src_vid] or self._vdtype[src_vid]
                        if dtype:
                            return dtype
                        # PHP/JS "new ClassName" operator: name IS the type
                        if self._vtype[src_vid] == OperatorType.NEW.value:
                            new_name = self._vname[src_vid]
                            if new_name and new_name[0:1].isupper():
                                return new_name
                        if self._vlabel[src_vid] == NodeLabel.IDENTIFIER.value:
                            current = src_vid
                            break
                    else:
                        break

        return self._resolve_chain_receiver_type(graph, op_vid)

    def _resolve_chain_receiver_type(self, graph: "ig.Graph",
                                     op_vid: int) -> str | None:
        """Resolve receiver type from a chained call's return type."""
        for tgt, role in self._ast_src_from.get(op_vid, []):
            if role != "callee":
                continue
            target_label = self._vlabel[tgt]
            if target_label != NodeLabel.OPERATOR.value:
                continue
            inner_type = self._vtype[tgt]
            if inner_type not in _CALL_TYPES:
                continue

            inner_op_name = self._vname[tgt]
            inner_callee = self._extract_callee_name(
                graph, tgt, inner_op_name
            )
            if not inner_callee:
                continue

            if inner_type == OperatorType.STATIC_CALL.value and \
                    "." in inner_op_name:
                qualifier = inner_op_name.split(".")[0]
                inner_fullname = f"{qualifier}.{inner_callee}"
            else:
                inner_fullname = inner_callee

            if inner_type == OperatorType.NEW.value:
                # Chained "new X(...).method()": the receiver type IS the
                # constructed class. _extract_callee_name returns the bare
                # class identifier here ("X"), never the "new X" op name, so
                # the legacy startswith("new") hint below could never fire
                # and these receivers resolved to None (external stub).
                if inner_callee and inner_callee[0:1].isupper():
                    return inner_callee

            vid = self._func_fullname_idx.get(inner_fullname)
            if vid is not None:
                rt = self._vreturn_type[vid]
                if rt and rt != "void":
                    return rt
                # Fix 115b (CVE-2026-126478): getter with no declared return
                # type — body is `return $this->prop;` (Zend/Laminas module
                # controllers: getSyndromicsurveillanceTable()).  Resolve the
                # property's class from its assignment sources (constructor
                # DI param type hint / `new X`), so the chained call
                # `$this->getter()->method()` binds to the real method def
                # instead of an external stub (no cg edge → in-body sinks
                # invisible).
                rt = self._infer_getter_return_type(graph, vid)
                if rt:
                    return rt

            if inner_callee.startswith("new") and len(inner_callee) > 3:
                hint = inner_callee[3:]
                if hint[0:1].isupper():
                    return hint

            return None

        return None

    def _infer_getter_return_type(self, graph: "ig.Graph",
                                  func_vid: int) -> str | None:
        """Fix 115b (CVE-2026-126478): infer a getter's return type from its
        body when no declared return type exists.

        Recognized shape (the Zend/Laminas module-controller idiom):
            public function getXyzTable() { return $this->xyzTable; }
        Walk the function's own subtree for `return` statements whose value
        is a ``$this->prop`` member read, then resolve the property's class
        via :meth:`_infer_property_class_type`.  Only single-hop property
        returns are recognized — anything more complex stays unresolved.
        """
        # own-subtree walk (Fix 34b doctrine: full subtree, not just children)
        stack = [func_vid]
        seen: set[int] = set()
        return_stmts: list[int] = []
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self._own_to.get(cur, ()))
            if cur != func_vid and self._vlabel[cur] == NodeLabel.RETURN.value:
                return_stmts.append(cur)
        if not return_stmts:
            return None
        for rop in return_stmts:
            for tgt, role in self._ast_src_from.get(rop, []):
                if role != "value":
                    continue
                if self._vlabel[tgt] != NodeLabel.IDENTIFIER.value:
                    continue
                # must be a property read on $this (member edge from this)
                member_srcs = self._member_to.get(tgt) or []
                if not member_srcs:
                    continue
                if not any(self._vname[ms] in ("this", "$this", "self")
                           for ms in member_srcs):
                    continue
                prop_name = self._vname[tgt]
                if not prop_name:
                    continue
                pt = self._infer_property_class_type(graph, func_vid, prop_name)
                if pt:
                    return pt
        return None

    def _infer_property_class_type(self, graph: "ig.Graph",
                                   func_vid: int,
                                   prop_name: str) -> str | None:
        """Fix 115b: resolve the class of a ``$this-><prop_name>`` property.

        Finds property-write identifier nodes named ``prop_name`` (member of
        ``$this``) in the getter's own file and walks their DFG sources (≤3
        hops) for a typed constructor/DI parameter or a ``new X`` operator:

            function __construct(Cls $table) {  # FQCN type hint, e.g. Ns\\Cls
                $this->xyzTable = $table;   // ← type hint is the class
            }

        File-scoped approximation of class scope (PSR-1: one class per PHP
        file); the ``$this`` receiver requirement keeps unrelated same-name
        locals out.
        """
        ffile = self._vfile_path[func_vid]
        if not ffile or not prop_name:
            return None

        def _cls_from_hint(hint: str) -> str | None:
            if not hint:
                return None
            base = hint.replace("::", "\\").rsplit("\\", 1)[-1]
            if base and base[0:1].isupper():
                return base
            return None

        for v in graph.vs:
            i = v.index
            if self._vlabel[i] != NodeLabel.IDENTIFIER.value:
                continue
            if self._vname[i] != prop_name:
                continue
            if self._vfile_path[i] != ffile:
                continue
            member_srcs = self._member_to.get(i) or []
            if not any(self._vname[ms] in ("this", "$this", "self")
                       for ms in member_srcs):
                continue
            # walk DFG sources up to 3 hops looking for a typed param or new
            frontier = [i]
            visited: set[int] = set()
            for _ in range(3):
                nxt: list[int] = []
                for u in frontier:
                    for s in self._dfg_to.get(u, ()):
                        if s in visited:
                            continue
                        visited.add(s)
                        if self._vlabel[s] == NodeLabel.PARAMETER.value:
                            cls = _cls_from_hint(
                                _vattr(graph.vs[s], "type_hint", "") or "")
                            if cls:
                                return cls
                        if self._vlabel[s] == NodeLabel.OPERATOR.value and \
                                self._vtype[s] == OperatorType.NEW.value:
                            cls = _cls_from_hint(self._vname[s])
                            if cls:
                                return cls
                        nxt.append(s)
                frontier = nxt
        return None

    def _get_receiver_ident_names(self, graph: "ig.Graph",
                                  call_vid: int) -> list[str]:
        """Extract receiver identifier names from callee chain."""
        callee_vids: list[int] = []
        for tgt, role in self._ast_src_from.get(call_vid, []):
            if role == "callee":
                callee_vids.append(tgt)

        names: list[str] = []

        for cv in callee_vids:
            cv_label = self._vlabel[cv]
            cv_name = self._vname[cv]

            if cv_label == NodeLabel.IDENTIFIER.value:
                for source in self._member_to.get(cv, []):
                    src_label = self._vlabel[source]
                    if src_label == NodeLabel.IDENTIFIER.value:
                        src_name = self._vname[source]
                        if src_name and src_name not in ("this", "self"):
                            names.append(src_name)
                    elif src_label == NodeLabel.OPERATOR.value:
                        names.extend(self._get_receiver_ident_names(graph, source))
                continue

            if cv_label == NodeLabel.OPERATOR.value:
                current = cv
                visited: set[int] = set()
                while current not in visited:
                    visited.add(current)
                    found = False
                    for source in self._member_to.get(current, []):
                        src_label = self._vlabel[source]
                        if src_label == NodeLabel.IDENTIFIER.value:
                            src_name = self._vname[source]
                            src_type = self._vtype[source]
                            if src_name and src_name not in ("this", "self"):
                                if src_type != "this":
                                    names.append(src_name)
                            found = True
                            break
                        elif src_label == NodeLabel.OPERATOR.value:
                            current = source
                            found = True
                            break
                    if not found:
                        break

        return names

    def _get_dfg_sources(self, graph: "ig.Graph", vid: int) -> list[int]:
        """Get upstream DFG source vertex IDs."""
        return list(self._dfg_to.get(vid, []))

    def _py_dispatch_candidates(self, graph: "ig.Graph", name: str) -> list[int]:
        """Fix 97 (CVE-2026-29080): all python METHODS with this exact name
        — the virtual-dispatch target set for an opaque-RECEIVER method
        call.  An instance receiver (`selected_plugin_to_use.list_dids()`)
        can only dispatch to methods (own-parent = class node), never to
        module-level functions, so module functions are excluded — that
        also keeps the candidate set small when a name is shared by both
        forms (rucio has 4 plugin methods + 5 module-level list_dids;
        the module functions would blow the storm cap).  Returns []
        unless there are 2..8 candidates: a single candidate is left to
        the normal single-bind path, and a storm (>8 same-named methods)
        also keeps old behavior to bound edge growth on huge corpora.
        """
        if not name:
            return []
        if self._py_dispatch_idx is None:
            idx: dict[str, list[int]] = {}
            # own-edge index: parent → children (class → its methods)
            own_to: dict[int, list[int]] = defaultdict(list)
            for e in graph.es:
                if _vattr(e, "label", "") == "own":
                    own_to[e.source].append(e.target)
            for i in range(graph.vcount()):
                if self._vlabel[i] != NodeLabel.CLASS.value:
                    continue
                for ch in own_to.get(i, ()):
                    if self._vlabel[ch] != NodeLabel.FUNCTION.value:
                        continue
                    if self._vis_external[ch]:
                        continue
                    if not str(self._vfile_path[ch]).endswith(".py"):
                        continue
                    nm = self._vname[ch]
                    if nm:
                        idx.setdefault(nm, []).append(ch)
            self._py_dispatch_idx = idx
        cands = self._py_dispatch_idx.get(name, [])
        if 1 < len(cands) <= 8:
            return cands
        return []

    def _find_or_create_function(self, graph: "ig.Graph",
                                func_name: str, fullname: str,
                                lineno: int = 0,
                                caller_file: str = "",
                                enclosing_class: str = "") -> int | None:
        """Find an existing function node or create an external one.

        Uses pre-built indexes instead of O(V) vs.select() scans.
        """
        # Fix 137f (CVE-2026-83542 OFBiz): receiver-RELATIVE call fullnames
        # ("this.getLocation", "$this.method", "self::x", "cls.x") must
        # resolve to the ENCLOSING CLASS's own method (java inner classes:
        # real fullname 'DecoratorScreen.getLocation'), then any same-file
        # definition — BEFORE the exact-fullname step.  Without this, an
        # unrelated file's earlier this.X call creates a synthetic external
        # hub whose fullname is ALSO "this.X", and the exact match silently
        # hijacks every later this.X call even in files that DO define X
        # (callee bare-name cross-file hijack — on the OFBiz corpus all 14
        # ModelScreenWidget getLocation call sites bound to a hub polluted
        # by SimpleServiceEngine/GroovyEngine, killing the return-value
        # propagation and with it the whole screen-render taint chain).
        # "super"/"parent" are excluded: they legitimately target a
        # superclass that may live in another file.
        if "." in fullname:
            _rt, _rm = fullname.rsplit(".", 1)
            if _rt.lstrip("$") in ("this", "self", "cls"):
                if enclosing_class:
                    _vid = self._func_fullname_idx.get(
                        f"{enclosing_class}.{_rm}")
                    if _vid is not None:
                        return _vid
                if caller_file:
                    _vid = self._func_name_file_idx.get(_rm, {}).get(caller_file)
                    if _vid is not None:
                        return _vid

        # 1. Exact fullname match
        vid = self._func_fullname_idx.get(fullname)
        if vid is not None:
            return vid

        # Fix 106 (CVE-2026-126482): a qualified fullname may carry a
        # namespace the method node doesn't ('OpenEMR\Billing\SLEOB.x'
        # vs 'SLEOB.x') — retry with the namespace-stripped type part.
        if "." in fullname:
            _t, _m = fullname.rsplit(".", 1)
            _short = f"{_t.rsplit(chr(92), 1)[-1]}.{_m}"
            if _short != fullname:
                vid = self._func_fullname_idx.get(_short)
                if vid is not None:
                    return vid

        # 2. Same-file name match (non-external declarations)
        if caller_file:
            vid = self._func_name_file_idx.get(func_name, {}).get(caller_file)
            if vid is not None:
                return vid

        # 3. Name match on external nodes (with type compatibility check)
        for vid in self._func_name_ext_idx.get(func_name, []):
            existing_fn = self._vfullname[vid]
            existing_type = existing_fn.rsplit(".", 1)[0] if "." in existing_fn else ""
            new_type = fullname.rsplit(".", 1)[0] if "." in fullname else ""
            if not existing_type or not new_type or existing_type == new_type:
                return vid

        # 4. Create new external function node
        new_v = graph.add_vertex(
            label=NodeLabel.FUNCTION.value,
            name=func_name,
            lineno=0,
            language="",
            fullname=fullname,
            type=FunctionType.FUNCTION.value,
            is_external=True,
        )
        new_vid = new_v.index
        # 扩展属性缓存以覆盖新节点
        for arr, default in [
            ("_vlabel", NodeLabel.FUNCTION.value),
            ("_vname", func_name),
            ("_vtype", FunctionType.FUNCTION.value),
            ("_vpath", ""),
            ("_vlineno", 0),
            ("_vfile_path", ""),
            ("_vis_external", True),
            ("_vfullname", fullname),
            ("_vjava_type", ""),
            ("_vdtype", ""),
            ("_vreturn_type", ""),
            ("_vvalue", ""),
        ]:
            lst = getattr(self, arr)
            while len(lst) <= new_vid:
                lst.append(default if isinstance(default, str) or isinstance(default, bool) or isinstance(default, int) else "")
            lst[new_vid] = default
        # 更新索引，使后续查找能命中
        self._func_fullname_idx[fullname] = new_vid
        self._func_name_ext_idx.setdefault(func_name, []).append(new_vid)
        return new_vid

    def _enclosing_function(self, graph: "ig.Graph", vid: int) -> int | None:
        """Find the ancestor function node of *vid* via ``own`` edges."""
        cached = self._enclosing_fn_cache.get(vid)
        if cached is not None or vid in self._enclosing_fn_cache:
            return cached

        visited: set[int] = set()
        current = vid
        for _ in range(10):
            if current in visited:
                break
            visited.add(current)
            for parent_vid in self._own_to.get(current, []):
                parent_label = self._vlabel[parent_vid]
                if parent_label == NodeLabel.FUNCTION.value:
                    self._enclosing_fn_cache[vid] = parent_vid
                    return parent_vid
                current = parent_vid
                break
            else:
                break

        self._enclosing_fn_cache[vid] = None
        return None

    def _enclosing_class_name(self, graph: "ig.Graph", vid: int) -> str:
        """Fix 137f: name of the class enclosing *vid* (inner-class aware).

        Walks own-parents from the enclosing FUNCTION up to the nearest
        'class' node (java inner classes: DecoratorScreen nested inside
        ModelScreenWidget resolves to 'DecoratorScreen').  Cached per
        enclosing function; '' when no class scope is found (top-level
        function / php procedural file).
        """
        fn_vid = self._enclosing_function(graph, vid)
        if fn_vid is None:
            return ""
        cached = getattr(self, "_enclosing_cls_cache", None)
        if cached is None:
            cached = self._enclosing_cls_cache = {}
        if fn_vid in cached:
            return cached[fn_vid]

        result = ""
        visited: set[int] = set()
        current = fn_vid
        for _ in range(10):
            if current in visited:
                break
            visited.add(current)
            if self._vlabel[current] == "class":
                result = self._vname[current] or ""
                break
            parents = self._own_to.get(current, [])
            if not parents:
                break
            current = parents[0]

        cached[fn_vid] = result
        return result

    # ── Fix 143 (CVE-2026-129448): java class-hierarchy helpers ──

    def _enclosing_function_ast(self, graph: "ig.Graph", vid: int) -> int | None:
        """Fix 143j: enclosing function via own edges, falling back to
        ast parents.

        ``_enclosing_function`` walks ``own`` edges only, but ops under
        branch containers can sit on a branch node whose own chain ends
        (``<else>`` hangs off the if-condition identifier via an ast
        iffalse edge) — ``super.characters``/``xr.parse``-style ops then
        resolved to NO enclosing function and every enclosing-scope
        feature (super dispatch, SAX registration) silently died.  Mixed
        bounded walk: prefer own parent, else first ast parent; stop at
        any function node.
        """
        fn = self._enclosing_function(graph, vid)
        if fn is not None:
            return fn
        cached = getattr(self, "_enclosing_fn_ast_cache", None)
        if cached is None:
            cached = self._enclosing_fn_ast_cache = {}
        if vid in cached:
            return cached[vid]
        visited: set[int] = {vid}
        current = vid
        for _ in range(15):
            own = self._own_to.get(current, [])
            if own:
                nxt = own[0]
                if self._vlabel[nxt] == NodeLabel.FUNCTION.value:
                    cached[vid] = nxt
                    return nxt
                if nxt not in visited:
                    visited.add(nxt)
                    current = nxt
                    continue
            astp = self._ast_to.get(current, [])
            found = None
            for p, _role in astp:
                if self._vlabel[p] == NodeLabel.FUNCTION.value:
                    found = p
                    break
            if found is not None:
                cached[vid] = found
                return found
            if astp and astp[0][0] not in visited:
                visited.add(astp[0][0])
                current = astp[0][0]
                continue
            break
        cached[vid] = None
        return None

    def _enclosing_class_name_ast(self, graph: "ig.Graph", vid: int) -> str:
        """Fix 143j: ``_enclosing_class_name`` on the ast-fallback walk."""
        fn_vid = self._enclosing_function_ast(graph, vid)
        if fn_vid is None:
            return ""
        cached = getattr(self, "_enclosing_cls_cache", None)
        if cached is None:
            cached = self._enclosing_cls_cache = {}
        if fn_vid in cached:
            return cached[fn_vid]
        current = fn_vid
        visited: set[int] = set()
        for _ in range(10):
            if current in visited:
                break
            visited.add(current)
            if self._vlabel[current] == NodeLabel.CLASS.value:
                cached[fn_vid] = self._vname[current] or ""
                return cached[fn_vid]
            own = self._own_to.get(current, [])
            if not own:
                break
            current = own[0]
        cached[fn_vid] = ""
        return ""

    def _java_superclass_chain(self, cls: str) -> list[str]:
        """Extends-only ancestor chain of a corpus class (bounded 6)."""
        out: list[str] = []
        seen = {cls}
        cur = cls
        for _ in range(6):
            parent = self._cls_extends.get(cur)
            if not parent or parent in seen:
                break
            seen.add(parent)
            out.append(parent)
            cur = parent
        return out

    def _java_lookup_method(self, graph: "ig.Graph", cls: str,
                            name: str) -> int | None:
        """Own-class + extends-chain method lookup (file-backed only).

        Handles dotted declared types (``Base64.Decoder`` → try
        ``Base64.Decoder.name`` then ``Decoder.name``), then walks the
        superclass chain — implicit-this calls in a subclass execute
        inherited methods (ByteArrayParser.endElement's setResult lives
        in TypeParserImpl).
        """
        if not cls or not name:
            return None
        cands = [cls]
        if "." in cls:
            cands.append(cls.rsplit(".", 1)[-1])
        for c in cands:
            for k in [c] + self._java_superclass_chain(c):
                fv = self._func_fullname_idx.get(f"{k}.{name}")
                if fv is not None and self._vfile_path[fv]:
                    return fv
        return None

    def _java_subtype_closure(self, cls: str) -> tuple[str, ...]:
        """Transitive subtype closure (extends+implements), cap 16, cached.

        Keys are simple class names (crg stub names); dotted inputs are
        reduced to their last segment.
        """
        root = cls.rsplit(".", 1)[-1] if "." in cls else cls
        cached = self._subtype_closure_cache.get(root)
        if cached is not None:
            return cached
        seen: set[str] = {root}
        out: list[str] = []
        frontier = [root]
        while frontier and len(out) < 16:
            cur = frontier.pop()
            for child in self._iface_implementors.get(cur, ()):
                if child not in seen:
                    seen.add(child)
                    out.append(child)
                    frontier.append(child)
        result = tuple(out)
        self._subtype_closure_cache[root] = result
        return result

    def _fn_has_body(self, graph: "ig.Graph", fn_vid: int) -> bool:
        """True when the function node owns non-parameter children.

        Fix 143k-b: body detection must look at OUTGOING own edges
        (statements/branches the function owns); the previous version
        inspected incoming own parents (the enclosing class), which made
        every corpus method look like it had a body and silently disabled
        the abstract-method override fan.
        """
        for eid in graph.incident(fn_vid, mode="out"):
            e = graph.es[eid]
            if e["label"] != EdgeLabel.OWN.value:
                continue
            if self._vlabel[e.target] != NodeLabel.PARAMETER.value:
                return True
        return False

    def _class_of_function(self, graph: "ig.Graph", fn_vid: int) -> str:
        """Fix 143k-c: name of the class DECLARING *fn_vid*.

        ``_enclosing_class_name`` resolves the enclosing function of an
        OP first — handed a function vid it walks fn→class→file, finds no
        function, and returns '' (the shape-b fan never fired).  Walk
        own-parents from the function directly to the nearest class node.
        """
        current = fn_vid
        visited: set[int] = set()
        for _ in range(6):
            if current in visited:
                break
            visited.add(current)
            if self._vlabel[current] == NodeLabel.CLASS.value:
                return self._vname[current] or ""
            own = self._own_to.get(current, [])
            if not own:
                break
            current = own[0]
        return ""

    def _sax_dispatch_edges(self, graph: "ig.Graph") -> int:
        """Fix 143d (CVE-2026-129448): SAX parse → ContentHandler dispatch.

        ``xr.setContentHandler(handler); xr.parse(new InputSource(stream))``
        — the XMLReader framework invokes the registered handler's
        startElement/characters/endElement callbacks with the parsed
        document's content.  There is no syntactic call edge, so the
        whole SAX-parsing leg of the xmlrpc deserialization chain was
        invisible.  Binding: same receiver name + same enclosing function
        for setContentHandler/parse; handler class resolved from the
        setter's arg0 identifier (declared java_type, else its dfg NEW
        definition).  Callbacks bound as use edges from the parse op, so
        dfg phase 2's arg→param binding carries the parse-arg taint
        (attacker InputSource) into the callback parameters.
        The SAXParser.parse(InputStream, DefaultHandler) shape (handler
        as arg 1) is bound the same way.
        """
        if not self._cls_decl_names:
            return 0
        added = 0
        # setter registry: (enclosing_fn, receiver) → handler class name
        handlers: dict[tuple[int, str], str] = {}
        parse_ops: list[tuple[int, str, int]] = []  # (op_vid, recv, fn_vid)
        for v in graph.vs:
            vid = v.index
            if self._vlabel[vid] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[vid] not in _CALL_TYPES:
                continue
            nm = self._vname[vid] or ""
            dot = nm.find(".")
            recv = nm[:dot] if dot > 0 else ""
            meth = nm[dot + 1:] if dot >= 0 else nm
            fn_vid = self._enclosing_function_ast(graph, vid)
            if meth == "setContentHandler" and recv and fn_vid is not None:
                hcls = self._sax_handler_class(graph, vid)
                if hcls:
                    handlers[(fn_vid, recv)] = hcls
            elif meth == "parse" and recv and fn_vid is not None:
                parse_ops.append((vid, recv, fn_vid))

        sax_callbacks = ("startElement", "characters", "endElement")
        for vid, recv, fn_vid in parse_ops:
            hcls = handlers.get((fn_vid, recv))
            if hcls is None:
                # SAXParser.parse(stream, handler) shape
                hcls = self._sax_parse_arg_handler(graph, vid)
            if not hcls:
                continue
            for cb in sax_callbacks:
                fv = self._func_fullname_idx.get(f"{hcls}.{cb}")
                if fv is None or not self._vfile_path[fv]:
                    continue
                if (vid, fv) not in self._use_pairs:
                    self._use_pairs.add((vid, fv))
                    self._add_use_edge_late(graph, vid, fv)
                    added += 1
        return added

    def _add_use_edge_late(self, graph: "ig.Graph", src: int,
                           tgt: int) -> None:
        """Append a use edge directly (post-batch phase)."""
        graph.add_edge(src, tgt)
        e = graph.es[graph.ecount() - 1]
        e["label"] = "use"
        e["call_type"] = "method"
        e["lineno"] = self._vlineno[src] or 0

    def _sax_handler_class(self, graph: "ig.Graph", op_vid: int) -> str:
        """Handler class name from a setContentHandler call's arg0."""
        arg0 = None
        for tgt, role in self._ast_src_from.get(op_vid, ()):
            if role == "arg":
                arg0 = tgt
                break
        if arg0 is None:
            return ""
        jt = self._vjava_type[arg0] or self._vdtype[arg0]
        if jt:
            return jt.rsplit(".", 1)[-1] if "." in jt else jt
        # Fix 143h (CVE-2026-129448): bounded dfg BACK-WALK to the `new X`
        # definition.  The one-hop lookup only reached the declaring
        # identifier (`parser` use → `parser` decl) and stopped — the NEW
        # op sits two+ hops upstream, so every locally-constructed handler
        # resolved to "".
        seen = {arg0}
        frontier = [arg0]
        for _ in range(6):
            nxt: list[int] = []
            for u in frontier:
                for src in self._dfg_to.get(u, ()):
                    if src in seen:
                        continue
                    seen.add(src)
                    nm = self._vname[src] or ""
                    if (self._vlabel[src] == NodeLabel.OPERATOR.value
                            and nm.startswith("new ") and len(nm) > 4):
                        return nm[4:].rsplit(".", 1)[-1]
                    nxt.append(src)
            if not nxt:
                break
            frontier = nxt
        return ""

    def _sax_parse_arg_handler(self, graph: "ig.Graph", op_vid: int) -> str:
        """Handler class from SAXParser.parse(stream, handler) arg1."""
        args = []
        for e in graph.incident(op_vid, mode="out"):
            if self._elabel_is_ast(e, "arg"):
                idx = e["arg_index"] if "arg_index" in e.attributes() else -1
                args.append((idx, e.target))
        args.sort()
        for idx, tgt in args:
            if idx != 1:
                continue
            jt = self._vjava_type[tgt] or self._vdtype[tgt]
            if jt:
                return jt.rsplit(".", 1)[-1] if "." in jt else jt
        return ""

    def _elabel_is_ast(self, e, role: str) -> bool:
        try:
            return e["label"] == "ast" and e["role"] == role
        except Exception:
            return False

    def _java_iface_dispatch_targets(self, graph: "ig.Graph",
                                     target_vid: int,
                                     callee_name: str) -> list[int]:
        """Fix 137g: 接口方法 target → 实现类同名方法 vids。

        target 的 enclosing class 是 corpus 内 InterfaceDeclaration 时，
        通过 crg implements 索引把所有实现类的同名方法作为分发目标
        （java-only：以 target 节点文件后缀 .java 判定；上限 16 个
        实现类防边爆炸）。非接口方法/无实现/超限一律返回 []。
        """
        if target_vid is None or not callee_name:
            return []
        cached = self._iface_of_target.get(target_vid)
        if cached is not None:
            impls = cached
        else:
            impls = ""
            fp = self._vfile_path[target_vid]
            if fp.endswith(".java"):
                cls_vid = self._enclosing_class_vid(graph, target_vid)
                if cls_vid is not None and self._vraw_type[cls_vid] == \
                        "InterfaceDeclaration":
                    impls = self._vname[cls_vid] or ""
            self._iface_of_target[target_vid] = impls
        if not impls:
            return []
        out: list[int] = []
        for impl_cls in list(self._iface_implementors.get(impls, ()))[:16]:
            iv = self._func_fullname_idx.get(f"{impl_cls}.{callee_name}")
            if iv is not None and iv != target_vid:
                out.append(iv)
        return out

    def _enclosing_class_vid(self, graph: "ig.Graph", vid: int) -> int | None:
        """Fix 137g: *vid* 的 enclosing class 节点（own 父链上溯）。

        先到 enclosing function（*vid* 本身是函数节点时直接从它起
        步——_enclosing_function 对函数节点会返回 None），再逐级 own-父
        上溯到最近的 class 节点。与 _enclosing_class_name 同型，但返回
        节点 vid 供 raw_type 检查。
        """
        if self._vlabel[vid] == NodeLabel.FUNCTION.value:
            start = vid
        else:
            start = self._enclosing_function(graph, vid)
        if start is None:
            return None
        cache = getattr(self, "_enclosing_cls_vid_cache", None)
        if cache is None:
            cache = self._enclosing_cls_vid_cache = {}
        if start in cache:
            return cache[start]
        result = None
        visited: set[int] = set()
        current = start
        for _ in range(10):
            if current in visited:
                break
            visited.add(current)
            if self._vlabel[current] == "class":
                result = current
                break
            parents = self._own_to.get(current, [])
            if not parents:
                break
            current = parents[0]
        cache[start] = result
        return result

    def _enclosing_function_lineno(self, graph: "ig.Graph", vid: int) -> tuple[int, int] | None:
        """Find the enclosing function's lineno range for *vid*.

        Uses cache to avoid repeated upward traversal.
        """
        cached = self._enclosing_fn_lineno_cache.get(vid)
        if cached is not None or vid in self._enclosing_fn_lineno_cache:
            return cached

        fn_vid = self._enclosing_function(graph, vid)
        if fn_vid is None:
            # Fallback: walk all incoming edges (not just own) to find function.
            # Identifiers may only have ast edges to intermediate operator nodes.
            visited: set[int] = set()
            current = vid
            for _ in range(15):
                if current in visited:
                    break
                visited.add(current)
                found = False
                # First pass: check all incoming for a direct function parent
                for source in self._incoming_to.get(current, []):
                    if self._vlabel[source] == NodeLabel.FUNCTION.value:
                        fn_vid = source
                        found = True
                        break
                if found:
                    break
                # Move up one level: prefer own edge, then ast edge
                moved = False
                for parent_vid in self._own_to.get(current, []):
                    current = parent_vid
                    moved = True
                    break
                if not moved:
                    # Walk ast edges in reverse
                    ast_sources = self._ast_to.get(current, [])
                    if ast_sources:
                        current = ast_sources[0][0]  # take first ast parent
                        moved = True
                if not moved:
                    break

        if fn_vid is None:
            self._enclosing_fn_lineno_cache[vid] = None
            return None
        start = self._vlineno[fn_vid]
        result = (start, start + 200)
        self._enclosing_fn_lineno_cache[vid] = result
        return result
