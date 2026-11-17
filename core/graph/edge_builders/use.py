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

        for e in graph.es:
            elabel = _vattr(e, "label", "")
            if elabel == "ast":
                role = _vattr(e, "role", "")
                self._ast_src_from[e.source].append((e.target, role))
                self._ast_to[e.target].append((e.source, role))
            elif elabel == "member":
                self._member_to[e.target].append(e.source)
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
                    graph, vid, callee_name, name_index
                )

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
            target_vid = self._find_or_create_function(
                graph, func_name, fullname, lineno,
                caller_file=caller_file
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

        # ── 批量写入 use 边 ──
        if use_edges:
            graph.add_edges(use_edges)
            n_existing = graph.ecount() - len(use_edges)
            for i, attrs in enumerate(use_attrs):
                eid = n_existing + i
                for k, val in attrs.items():
                    graph.es[eid][k] = val

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
                                caller_file: str = "") -> int | None:
        """Find an existing function node or create an external one.

        Uses pre-built indexes instead of O(V) vs.select() scans.
        """
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
