"""Graph-based function summary — 图引擎上的函数摘要生成器。

替代旧引擎的 14 语言 summary_generator.py，直接在已构建的 AST 图上工作。
从 function 的 return 节点沿 DFG 反向 BFS 到 parameter，
生成摘要并直接标注为图节点属性。

摘要结果写入 function 节点：
    func_summary_type: "passthrough" | "source" | "safe" | "literal" | "unknown"
    func_summary_pt: [0, 2, ...]  — 返回值依赖的形参索引

同步到 taint 属性（供 graph_analyzer Rule 4c 消费）：
    taint_type = func_summary_type
    taint_passthrough = func_summary_pt

算法：
    1. 遍历所有 function 节点
    2. 找 return → ast[value] → 返回值表达式
    3. 从返回值沿 DFG 反向 BFS（约束在 own 子树内）
    4. 碰到 parameter → 记录 own 边 index
    5. 碰到 taint_type=source/safe/passthrough → 标记
    6. 碰到 call → use → function → 递归查目标摘要
    7. 汇总 return flows → 确定 summary_type
    8. 两遍迭代处理解决递归调用依赖
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig

__all__ = ["build_function_summaries"]

logger = logging.getLogger("KunlunLog")

# BFS 递归深度上限
_MAX_TRACE_DEPTH = 15

# Fix 53-perf: per-graph __construct node index (52z-3 scan cache)
_CTOR_NODES_CACHE: dict[int, list[int]] = {}
# Fix 63b (perf): memoize the per-(ctor, property) assign lookup. The 53-perf
# fix cached the __construct node LIST, but every property hit still BFS-walked
# every ctor's subtree — on osticket that BFS body was ~88% of self time in
# the summaries phase (py-spy). The lookup result (assign vid or None) depends
# only on the immutable graph + eidx, so it is safely memoizable per graph.
_CTOR_ASSIGN_CACHE: dict[tuple[int, int, str], int | None] = {}
_CTOR_MISS = object()  # sentinel: distinguish "cached None" from "not cached"

# Fix 145b (CVE-2026-124468): per-graph index of file-backed PHP
# constructors, keyed by class name (both the fullname's class part and
# its namespace-stripped short form).  Lets the `new X(args)` return
# tracer distinguish "corpus class whose state includes the ctor args"
# from framework externals (which keep the blanket constructor-safe).
_PHP_CTOR_IDX_CACHE: dict[int, dict[str, int]] = {}

# Fix 145d (CVE-2026-124468): per-graph index of php setter methods —
# prop name -> [(setter function vid, param name the prop is assigned
# from)].  Built in one pass: a "setter" is a php function whose body has
# a direct `$this-><prop> = <own param>` assign (the classic fluent value
# object: setFragment/setField).  Lets the 52z-3 property tracer resolve
# properties written INDIRECTLY in constructors ($this->setField($field))
# — the assign lives in the setter body, invisible to the ctor-only scan.
# _PHP_SETTER_PARAM_CACHE carries setter_vid -> {param name -> position}.
# _CTOR_SETTER_CALL_CACHE memoizes (graph, ctor, method name) -> call-op
# vids inside that ctor (None = no such call).
_PHP_SETTER_IDX_CACHE: dict[int, dict[str, list[tuple[int, str, str]]]] = {}
_PHP_SETTER_PARAM_CACHE: dict[int, dict[int, dict[str, int]]] = {}
_CTOR_SETTER_CALL_CACHE: dict[tuple[int, int, str], list[int] | None] = {}
_PHP_FN_CLASS_CACHE: dict[int, dict[int, str]] = {}


def _php_fn_class_map(graph, eidx) -> dict[int, str]:
    """Fix 145f: fvid -> enclosing class name via own-parent walk.

    145d's setter index is keyed by bare property name graph-wide; on
    multi-class corpora (osticket class.forms.php + class.dynamic_forms
    .php) same-named props (`ht`, `choices`) conflate ACROSS classes and
    flip unrelated getters safe->unknown (anchor task 130 +15 FP, e.g.
    $_POST@staff/dashboard.inc.php:2 reaching client/faq.inc.php:19
    through `_choices`/`ht` name collisions).  Every 145d hop (reader,
    setter writer, ctor) must now resolve to the SAME class."""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr
    _gk = id(graph)
    m = _PHP_FN_CLASS_CACHE.get(_gk)
    if m is not None:
        return m
    parent: dict[int, int] = {}
    for _pv, _lst in eidx["own_ch"].items():
        for _cv, _ in _lst:
            parent.setdefault(_cv, _pv)
    m = {}
    for v in graph.vs:
        if _vattr(v, "label", "") != NodeLabel.FUNCTION.value:
            continue
        cur = v.index
        seen: set[int] = set()
        cls = ""
        while cur not in seen:
            seen.add(cur)
            cv = graph.vs[cur]
            if _vattr(cv, "type", "") == "class":
                cls = _vattr(cv, "name", "") or ""
                break
            nxt = parent.get(cur, -1)
            if nxt < 0:
                break
            cur = nxt
        if cls:
            m[v.index] = cls
    _PHP_FN_CLASS_CACHE[_gk] = m
    return m


def _php_prop_setter_idx(graph, eidx) -> dict[str, list[tuple[int, str, str]]]:
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr
    _gk = id(graph)
    idx = _PHP_SETTER_IDX_CACHE.get(_gk)
    if idx is not None:
        return idx
    idx = {}
    params: dict[int, dict[str, int]] = {}
    for fv in graph.vs:
        if (_vattr(fv, "label", "") != NodeLabel.FUNCTION.value
                or _vattr(fv, "language", "") != "php"
                or not _vattr(fv, "file_path", "")):
            continue
        fvid = fv.index
        pidx: dict[str, int] = {}
        for _cp, _ci in eidx["own_ch"].get(fvid, []):
            if _vattr(graph.vs[_cp], "label", "") == NodeLabel.PARAMETER.value:
                _cn = str(_vattr(graph.vs[_cp], "name", ""))
                if _cn:
                    pidx[_cn] = int(_ci) if _ci not in (None, "") else 0
        if not pidx:
            continue
        _stack = [fvid]
        _seen = set()
        _hits: list[tuple[str, str]] = []
        while _stack:
            _x = _stack.pop()
            if _x in _seen:
                continue
            _seen.add(_x)
            _xv = graph.vs[_x]
            _xl = _vattr(_xv, "label", "")
            if _xl == NodeLabel.FUNCTION.value and _x != fvid:
                continue  # don't cross into nested/sibling functions
            if (_xl == NodeLabel.OPERATOR.value
                    and _vattr(_xv, "type", "") in ("assign", "aug_assign")):
                _lhs_name = None
                _rhs_names: list[str] = []
                for _t, _r, _ in eidx["ast_ch"].get(_x, []):
                    if _r in ("lhs", "left"):
                        _lhs_name = str(_vattr(graph.vs[_t], "name", "")).strip(chr(39) + chr(34))
                    elif _r in ("rhs", "right"):
                        _rhs_names.append(str(_vattr(graph.vs[_t], "name", "")))
                if _lhs_name:
                    for _rn in _rhs_names:
                        if _rn in pidx:
                            _hits.append((_lhs_name, _rn))
                            break
            for _t, _r, _ in eidx["ast_ch"].get(_x, []):
                if _t not in _seen:
                    _stack.append(_t)
            for _t2 in eidx["out"].get("own", {}).get(_x, []):
                if _t2 not in _seen:
                    _stack.append(_t2)
        if _hits:
            params[fvid] = pidx
            _cls145f = _php_fn_class_map(graph, eidx).get(fvid, "")
            for _pn, _paramn in _hits:
                lst = idx.setdefault(_pn, [])
                if (fvid, _paramn, _cls145f) not in lst:
                    lst.append((fvid, _paramn, _cls145f))
    _PHP_SETTER_IDX_CACHE[_gk] = idx
    _PHP_SETTER_PARAM_CACHE[_gk] = params
    return idx


def _php_corpus_ctor_idx(graph) -> dict[str, int]:
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr
    _gk = id(graph)
    idx = _PHP_CTOR_IDX_CACHE.get(_gk)
    if idx is None:
        idx = {}
        for fv in graph.vs:
            if (_vattr(fv, "label", "") != NodeLabel.FUNCTION.value
                    or str(_vattr(fv, "name", "")) != "__construct"
                    or _vattr(fv, "language", "") != "php"
                    or not _vattr(fv, "file_path", "")):
                continue
            fn = str(_vattr(fv, "fullname", "") or "")
            cls = fn.rsplit(".", 1)[0] if "." in fn else ""
            if not cls:
                continue
            idx.setdefault(cls, fv.index)
            _short = cls.rsplit(chr(92), 1)[-1]
            if _short != cls:
                idx.setdefault(_short, fv.index)
        _PHP_CTOR_IDX_CACHE[_gk] = idx
    return idx

# 迭代轮数上限（解决 A→B→A 递归调用）
_MAX_ITERATIONS = 5

# call operator 类型集合
_CALL_TYPES = frozenset({"call", "method_call", "static_call"})


def _build_edge_index(graph: "ig.Graph"):
    """一次性遍历所有边，构建 O(1) 索引替代 es.select。

    Returns:
        out: dict[str, dict[int, list[int]]]  — label → {src_vid: [tgt_vid, ...]}
        inn: dict[str, dict[int, list[int]]]  — label → {tgt_vid: [src_vid, ...]}
        ast_children: dict[int, list[tuple[int, str, str]]]  — src_vid → [(tgt_vid, role, arg_index), ...]
        own_children: dict[int, list[tuple[int, str]]]  — src_vid → [(tgt_vid, index), ...]
    """
    from utils.igraph_compat import _vattr
    out: dict[str, dict[int, list[int]]] = {}
    inn: dict[str, dict[int, list[int]]] = {}
    ast_children: dict[int, list[tuple[int, str, str]]] = {}
    own_children: dict[int, list[tuple[int, str]]] = {}
    for e in graph.es:
        el = _vattr(e, "label") or ""
        s, t = e.source, e.target
        out.setdefault(el, {}).setdefault(s, []).append(t)
        inn.setdefault(el, {}).setdefault(t, []).append(s)
        if el == "ast":
            role = _vattr(e, "role") or ""
            arg_idx = _vattr(e, "arg_index") or _vattr(e, "index") or ""
            ast_children.setdefault(s, []).append((t, role, arg_idx))
        if el == "own":
            idx = _vattr(e, "index") or ""
            own_children.setdefault(s, []).append((t, idx))
    return {
        "out": out,
        "in": inn,
        "ast_ch": ast_children,
        "own_ch": own_children,
    }


def _collect_ast_descendants(graph: ig.Graph, start_vid: int, result: set[int],
                               return_vids: list[int] | None = None, eidx: dict | None = None):
    """递归收集 start_vid 通过 ast/own 边可达的所有后代节点（BFS）。

    同时追踪 ast 边和 own 边（own 边仅在 branch/control 节点下展开）。
    因为 PHP 等语言的 if/else body 通过 branch → own → return 连接，
    而非 ast 边。限制 own 边展开避免跨越到其他 function 节点。

    Args:
        return_vids: 如果提供，在展开过程中收集到的 return 节点也会追加到此列表。
    """
    from collections import deque
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    if eidx is None:  # defensive: callers always pass the shared index
        eidx = _build_edge_index(graph)

    # 允许展开 own 子节点的节点类型（branch/control/函数体）
    _OWN_EXPAND_LABELS = {NodeLabel.BRANCH.value, "control", NodeLabel.FUNCTION.value}

    queue = deque([start_vid])
    result.add(start_vid)
    if return_vids is not None and _vattr(graph.vs[start_vid], "label", "") == NodeLabel.RETURN.value:
        return_vids.append(start_vid)
    while queue:
        vid = queue.popleft()
        src_label = _vattr(graph.vs[vid], "label", "")
        for tgt_vid in eidx["out"].get("ast", {}).get(vid, []):
            if tgt_vid not in result:
                result.add(tgt_vid)
                queue.append(tgt_vid)
        # Fix 98a: method-call receivers connect to the callee property via a
        # *member* edge (receiver → property), not as an ast child of the
        # call operator — the normalizer attaches them to the property node.
        # Walking ast edges alone therefore misses the receiver identifier
        # (`for k, v in g.items()` — `g` was invisible to own_vids), so
        # _trace_return_value's second pass skipped it as a foreign vid and
        # container-building functions were mis-summarised (CVE-2026-29080
        # FilterEngine).  Follow the reverse member edge from every collected
        # property/callee node to pull the receiver into the function's own
        # set; member edges never cross statement boundaries.
        # Fix 98a-gate: python-only — receivers reached via member edges also
        # exist in PHP method bodies, and admitting them flipped hundreds of
        # PHP method summaries (sanitizers tracing to unknown), collapsing
        # the scanner safe-cut (osticket +260 XSS FPs).  The receiver-into-
        # own_vids semantics is only needed for the python FilterEngine
        # self-field/container chains.
        _py98a = _vattr(graph.vs[vid], "language", "") == "python"
        if _py98a:
            for src_vid in eidx["in"].get("member", {}).get(vid, []):
                if src_vid not in result:
                    result.add(src_vid)
                    queue.append(src_vid)
        if src_label in _OWN_EXPAND_LABELS:
            # branch/control 节点的 own 子节点也展开
            for tgt_vid in eidx["out"].get("own", {}).get(vid, []):
                if tgt_vid not in result:
                    result.add(tgt_vid)
                    queue.append(tgt_vid)
                    if return_vids is not None and _vattr(graph.vs[tgt_vid], "label", "") == NodeLabel.RETURN.value:
                        return_vids.append(tgt_vid)


def _hub_serves_java(graph, vid: int) -> bool:
    """Fix 136 (CVE-2026-45049): external placeholder hubs are synthesized
    language-less by the edge builders (unlike normalizer-created nodes,
    which carry the source language).  The hub's language is the language
    of its call sites: any use/cg in-edge from a java node makes this a
    java hub.  Checked only for the Fix 102a/136 safe-veto path, so the
    cost is bounded to placeholder hubs whose name coincides with a real
    'safe' def — first-hit return keeps it O(1) on java corpora."""
    from utils.igraph_compat import _vattr
    try:
        for eid in graph.incident(vid, mode="in"):
            e = graph.es[eid]
            if e["label"] not in ("use", "cg"):
                continue
            if _vattr(graph.vs[e.source], "language", "") == "java":
                return True
    except Exception:
        pass
    return False


def _propagate_same_name_summaries(graph: "ig.Graph") -> None:
    """Propagate func_summary_type from definition nodes to same-name
    reference nodes created by the normalizer when building 'use' edges."""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    func_by_name: dict[str, list[tuple[int, str, str, bool]]] = {}
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.FUNCTION.value:
            continue
        fname = _vattr(v, "name", "")
        if fname:
            fst = _vattr(v, "func_summary_type", "")
            func_by_name.setdefault(fname, []).append(
                (v.index, fst, str(_vattr(v, "fullname", "") or ""),
                 bool(_vattr(v, "is_external", False))))

    def _cls158a(fn_full: str) -> str:
        # Fix 158a: class part of a qualified fullname ('Criteria.GetOrder'
        # -> 'Criteria', 'NS\\Cls::run' -> 'NS\\Cls').  '' = global fn.
        for _sep in ("::", "."):
            if _sep in fn_full:
                return fn_full.rsplit(_sep, 1)[0]
        return ""

    for fname, entries in func_by_name.items():
        best = ""
        for _, fst, _, _ in entries:
            if fst in ("safe", "source", "source:user"):
                best = fst
                break
            if fst == "passthrough" and not best:
                best = fst
        if best:
            # Fix 158a (CVE-2026-124444): 'safe' needs class identity for
            # REAL method/ctor defs.  PHP kept 102b's calibrated external-
            # hub semantics, but real-def fanout is pure bare-name
            # coincidence: ONE natively-safe __construct (a ctor with an
            # explicit return) stamped all 284 ctors in the OpenEMR sparse
            # tree, DataSet.__construct included, and the scanner's
            # safe-cut then deleted the arg DFG edges of
            # ``new DataSet($sql, ...)`` (Phreezer:470) — the Phreeze
            # ORDER BY GT chain was severed in every full-tree scan while
            # a 14-file mini (no same-name safe def -> no stamping)
            # detected it natively.  Same disease as Fix 102a (python) /
            # Fix 136 (java), closed on the PHP real-def side: a real def
            # whose fullname carries a class part only receives 'safe'
            # from a same-class def.  Globals (no class part) and external
            # placeholder hubs keep the calibrated 102b propagation
            # semantics; source/passthrough keep propagating on name (they
            # favour detection).
            _safe_classes158a = None
            if best == "safe":
                _safe_classes158a = {
                    _cls158a(fn_full)
                    for _, fst, fn_full, _ in entries
                    if fst == "safe"
                }
            for vid, fst, fn_full, ext in entries:
                if fst != best:
                    # (Fix 102a/102b/136 guards follow — unchanged.)
                    # Fix 102a (CVE-2026-29080 gates): never propagate 'safe'
                    # onto EXTERNAL placeholder nodes.  Same-name propagation
                    # is a name coincidence, and a placeholder is a bare-name
                    # hub fanning out to every same-named call in the corpus
                    # (osticket: the 'lookup' hub serves 557 call sites).  A
                    # 'safe' stamped that way (a) enrols the placeholder in
                    # the scanner's safe-cleanup, cutting DFG arg edges into
                    # every hub call at graph level, and (b) feeds analyzer
                    # Rule 4b's veto — `Ticket::lookup($child[0])` was killed
                    # by ajax.orgs.php's unrelated zero-arg lookup() whose
                    # safe summary Fix 98a started producing (ticket-relations
                    # .inc.php:27/30 regression).  safe is a VETO and needs
                    # identity proof; source/passthrough propagate on (they
                    # favour detection — same asymmetry as Fix 93/99/101).
                    # Fix 102b (CVE-2026-29080 gates): python-only.  Ungated,
                    # un-stamping the PHP hubs took ~20k legitimate safe-cut
                    # targets away from the scanner's safe-call cut (osticket
                    # "Removed N DFG edges": 27361 → 7014) — every sanitizer
                    # sharing a bare name with any real def stopped cutting
                    # and the corpus exploded +250 XSS rows.  The hub-hijack
                    # this guards against is the python duck-typing dispatch
                    # shape; PHP placeholders keep the calibrated HEAD
                    # propagation semantics.
                    # Fix 136 (CVE-2026-45049): the same hub-hijack on the
                    # JAVA side.  OpenAM corpus: 121 all-literal user
                    # toString() defs stamp 'safe' onto 87 language-less
                    # 'toString' placeholder hubs; one hub (StringBuilder
                    # .toString, 35 call sites) vetoed CDCServlet's tainted
                    # redirectURL.toString() args at L644/L677 — the CDSSO
                    # open-redirect GT rows silently vanished in every
                    # full-corpus scan while a 2-file mini (no same-name
                    # safe def → no stamping) detected them natively.
                    # Corpus-wide: 803 java placeholder hubs stamped safe by
                    # name coincidence, fanning out to 6385 call sites
                    # (String.equals 2034, Iterator.next 650, Set.isEmpty
                    # 185...).  Java stubs are synthesized language-less
                    # (edge builders, not normalizers), so hub language is
                    # inferred from its call sites (use/cg in-edge sources).
                    # PHP keeps the calibrated 102b semantics.
                    _ext102 = _vattr(graph.vs[vid], "is_external", False)
                    if best == "safe" and _ext102:
                        _lang102 = _vattr(graph.vs[vid], "language", "")
                        if _lang102 == "python":
                            continue
                        if (_lang102 == "java"
                                or (not _lang102
                                    and _hub_serves_java(graph, vid))):
                            continue
                    # Fix 158a stamp gate: real def with a class part gets
                    # 'safe' only from same-class defs (see block comment
                    # above).  External hubs (ext) and globals (empty class
                    # part) keep the calibrated propagation.
                    if (best == "safe" and not ext
                            and _safe_classes158a is not None):
                        _tgt_cls158a = _cls158a(fn_full)
                        if (_tgt_cls158a
                                and _tgt_cls158a not in _safe_classes158a):
                            continue
                    graph.vs[vid]["func_summary_type"] = best


_PROP_INDEX_CACHE: list = [None, None]  # [weakref(graph), {name: [vid, ...]}]


def _property_name_index(graph) -> dict:
    """Fix 87 (perf): name→vids bucket index over property nodes.

    Fix 72c-2's same-name property union originally scanned ALL graph
    vertices on every call — O(N²) on large corpora (OpenEMR 1.6M nodes
    spent 4.5h+ inside build_function_summaries with 100% of samples in
    that loop).  Build the index once per graph and reuse it.
    """
    ref, idx = _PROP_INDEX_CACHE
    if ref is not None and ref() is graph:
        return idx
    import weakref
    from utils.igraph_compat import _vattr
    new_idx: dict = {}
    for v in graph.vs:
        if _vattr(v, "type", "") == "property":
            new_idx.setdefault(_vattr(v, "name", ""), []).append(v.index)
    _PROP_INDEX_CACHE[:] = [weakref.ref(graph), new_idx]
    return new_idx


def build_function_summaries(
    graph: ig.Graph,
    languages: list[str] | None = None,
) -> dict[str, int]:
    """在图上构建函数摘要，标注 function 节点属性。

    Args:
        graph: 已构建 DFG 边的 igraph AST 图
        languages: 语言过滤列表（可选），None 表示全部

    Returns:
        统计信息 dict: {"annotated": N, "passthrough": N, "source": N, "safe": N, "literal": N, "unknown": N}
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    lang_set: set[str] | None = set(languages) if languages else None

    stats = {"annotated": 0, "passthrough": 0, "source": 0, "safe": 0, "literal": 0, "unknown": 0}

    # 一次性构建 O(1) 边索引，替代所有 es.select 调用
    eidx = _build_edge_index(graph)

    # ── 收集所有 function 节点及其结构 ──
    func_data: dict[int, dict] = {}  # func_vid → {own_vids, param_idx, return_vids, lang}
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.FUNCTION.value:
            continue
        if lang_set is not None and _vattr(v, "language", "") not in lang_set:
            continue
        vid = v.index
        own_vids: set[int] = set()
        param_idx: dict[int, int] = {}  # param_vid → param index
        return_vids: list[int] = []
        for child_vid, edge_idx in eidx["own_ch"].get(vid, []):
            child_label = _vattr(graph.vs[child_vid], "label", "")
            if child_label == NodeLabel.PARAMETER.value:
                if edge_idx is not None and edge_idx != "":
                    param_idx[child_vid] = int(edge_idx)
                # parameter 不展开 ast 子树（无意义）
                own_vids.add(child_vid)
            elif child_label == NodeLabel.RETURN.value:
                return_vids.append(child_vid)
                own_vids.add(child_vid)
                # Fix 98a-2: top-level RETURN children of a function body were
                # added to own_vids without expanding their ast subtree, so
                # the returned *value* identifier (`return rows` — the `rows`
                # node under the return) stayed foreign to the function.
                # Fix 98a-gate: python-only (see 98a above) — expanding PHP
                # return subtrees flipped PHP summaries corpus-wide.
                if _vattr(graph.vs[child_vid], "language", "") == "python":
                    _collect_ast_descendants(graph, child_vid, own_vids, return_vids, eidx=eidx)
            else:
                # 其他 own 子节点：递归展开 ast 子树（同时收集嵌套 return）
                _collect_ast_descendants(graph, child_vid, own_vids, return_vids, eidx=eidx)
        func_data[vid] = {
            "own_vids": own_vids,
            "param_idx": param_idx,
            "return_vids": return_vids,
        }

    if not func_data:
        return stats

    # ── 迭代处理（解决递归调用依赖） ──
    processed: set[int] = set()

    for iteration in range(_MAX_ITERATIONS):
        new_this_round = 0
        for vid, fd in func_data.items():
            if vid in processed:
                continue
            if not fd["return_vids"]:
                # 无 return 的函数（void/无显式返回）— 不需要摘要
                processed.add(vid)
                continue

            # Fix 145f: carry the summarized function's vid on eidx so the
            # 145d setter tracer can scope hops to the reader's class.
            eidx["__reader_fvid145f__"] = vid
            return_flows = _collect_return_flows(
                graph, fd["return_vids"], fd["own_vids"], fd["param_idx"], eidx
            )
            if not return_flows:
                processed.add(vid)
                continue

            # 汇总
            summary_type, dep_params = _aggregate_flows(return_flows)

            if os.environ.get("KM_DBG_FS"):
                _fs_nm = _vattr(graph.vs[vid], "name", "")
                _fs_fp_full = _vattr(graph.vs[vid], "file_path", "") or ""
                _fs_spec = os.environ["KM_DBG_FS"]
                _fs_hit = False
                for _tok in _fs_spec.split(","):
                    if ":" in _tok:
                        if _tok.rstrip(":") in _fs_fp_full:
                            _fs_hit = True
                    elif _fs_nm == _tok:
                        _fs_hit = True
                if _fs_hit:
                    _fs_fp = _fs_fp_full.split("/")[-1]
                    print(f"[FS] {_fs_fp}:{_vattr(graph.vs[vid], 'lineno', '')} "
                          f"{_fs_nm!r} -> {summary_type} dep={sorted(dep_params)}")
                    for _fl in return_flows:
                        print(f"    flow origin={_fl.get('origin')!r} "
                              f"type={_fl.get('origin_type')!r} "
                              f"dep={_fl.get('dep_params')} "
                              f"unres={_fl.get('has_unresolved_call')}")

            # 如果有未解析的 call（目标函数尚未有摘要），且不是最后一轮，延迟处理
            has_unresolved = any(
                f.get("has_unresolved_call")
                and f.get("origin_type") in ("unknown", "param")
                for f in return_flows
            )
            if has_unresolved and summary_type in ("unknown", "passthrough") and iteration < _MAX_ITERATIONS - 1:
                continue

            # ── 写入摘要属性 ──
            graph.vs[vid]["func_summary_type"] = summary_type
            if dep_params:
                graph.vs[vid]["func_summary_pt"] = sorted(dep_params)

            # 同步到 taint 属性（仅当 enrich_taint 未标注时）
            existing_taint = _vattr(graph.vs[vid], "taint_type", "")
            if not existing_taint and summary_type in ("passthrough", "source", "safe"):
                # Use "source:user" for source to distinguish from framework/builtin
                # sources, allowing inline return analysis in graph_analyzer.
                sync_type = "source:user" if summary_type == "source" else summary_type
                graph.vs[vid]["taint_type"] = sync_type
                if summary_type == "passthrough" and dep_params:
                    sorted_deps = sorted(dep_params)
                    graph.vs[vid]["taint_passthrough"] = sorted_deps
                    _mark_passthrough_params(graph, vid, sorted_deps, eidx)

            processed.add(vid)
            new_this_round += 1
            stats[summary_type] = stats.get(summary_type, 0) + 1

        stats["annotated"] += new_this_round
        if new_this_round == 0:
            break  # 无进展，停止迭代

        # Propagate summaries to same-name reference nodes after each round.
        # This ensures that when function A (round 1) calls function B (round 2)
        # via a reference node, the reference already has B's summary.
        _propagate_same_name_summaries(graph)

    # 将剩余未处理的标记为 processed（避免后续重复计算）
    for vid in func_data:
        if vid not in processed:
            processed.add(vid)

    # Final propagation to same-name reference nodes
    _propagate_same_name_summaries(graph)

    logger.debug(
        "build_function_summaries: processed %d/%d functions, stats=%s",
        len(processed), len(func_data), stats,
    )

    return stats


# ---------------------------------------------------------------------------
# Internal: return flow 收集与聚合
# ---------------------------------------------------------------------------


def _collect_return_flows(
    graph: ig.Graph,
    return_vids: list[int],
    own_vids: set[int],
    param_idx: dict[int, int],
    eidx: dict,
) -> list[dict]:
    """从所有 return 节点收集 return flows。"""
    from utils.igraph_compat import _vattr

    flows = []
    for ret_vid in return_vids:
        for tgt, role, _ in eidx["ast_ch"].get(ret_vid, []):
            if role == "value":
                flow = _trace_return_value(graph, tgt, own_vids, param_idx, set(), eidx)
                if flow:
                    flows.append(flow)
    return flows


def _aggregate_flows(flows: list[dict]) -> tuple[str, set[int]]:
    """汇总 return flows，返回 (summary_type, dep_params_set)。

    规则：
    - 有任何 source → "source"
    - 有 dep_params，且没有 safe flow → "passthrough"
    - 有 dep_params + safe flow 混合 → "safe"（函数内部做了 sanitization，
      param return 通常是特殊条件的 fallback，如 is_array 分支）
    - 全部 literal/safe → "safe"
    - 否则 → "unknown"
    """
    has_source = False
    has_safe = False
    all_dep_params: set[int] = set()
    all_safe_or_literal = True

    for flow in flows:
        ot = flow.get("origin_type", "")
        if ot == "source":
            has_source = True
            all_safe_or_literal = False
        elif ot == "param":
            all_dep_params.update(flow.get("dep_params", []))
            all_safe_or_literal = False
        elif ot == "literal":
            pass  # safe_or_literal stays True
        elif ot == "safe":
            has_safe = True
            pass  # safe_or_literal stays True
        else:  # unknown
            all_safe_or_literal = False

    if has_source:
        return "source", all_dep_params
    if all_dep_params:
        # Mixed safe + param: function has a conditional sanitization path
        # AND a raw parameter passthrough path. Be conservative: mark as
        # "passthrough" so the taint analysis can still trace the parameter.
        # Previously this returned "safe", which suppressed TPs when a
        # function conditionally sanitized but also returned raw input.
        return "passthrough", all_dep_params
    if flows and all_safe_or_literal:
        return "safe", all_dep_params
    return "unknown", all_dep_params


# ---------------------------------------------------------------------------
# Internal: DFG 反向追踪
# ---------------------------------------------------------------------------


def _trace_return_value(
    graph: ig.Graph,
    start_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    eidx: dict,
    depth: int = 0,
) -> dict:
    """从返回值表达式 vid 沿 DFG 反向追踪到参数/字面量/source。

    Returns dict: {origin, origin_type, dep_params, has_unresolved_call}
    """
    from core.graph.node_edge_schema import NodeLabel, AstRole
    from utils.igraph_compat import _vattr

    if start_vid in visited or depth > _MAX_TRACE_DEPTH:
        # Fix 17b: a visited-set hit is a CYCLE (we are already tracing this
        # node higher in the stack), and a depth overflow is a trace bound —
        # neither is a call to an unknown function, so neither may set
        # has_unresolved_call.  That flag drives the defer logic in
        # build_function_summaries; a cyclic flow with has_unresolved=True
        # deferred its function every iteration (the cycle can never
        # resolve), starving the function of a summary entirely.
        return {"origin": "", "origin_type": "unknown", "dep_params": [], "has_unresolved_call": False}
    visited = visited | {start_vid}

    v = graph.vs[start_vid]
    vlabel = _vattr(v, "label", "")
    vtype = _vattr(v, "type", "")
    vname = _vattr(v, "name", "")
    if os.environ.get("KM_DBG_TRACE"):
        _trfp = _vattr(v, "file_path", "") or ""
        if os.environ["KM_DBG_TRACE"] in _trfp:
            print(f"[TR] d{depth} {'  ' * depth}{vlabel}/{vtype} "
                  f"{vname!r} taint={_vattr(v, 'taint_type', '')!r} "
                  f"pt={_vattr(v, 'taint_passthrough', '')!r} vid={start_vid}")

    # ── 1. 直接命中 parameter ──
    if start_vid in param_idx:
        # 检查 parameter 是否已被 enrich_taint 标注为 source（如 @RequestParam）
        self_taint = _vattr(v, "taint_type", "")
        if self_taint == "source":
            return {
                "origin": vname,
                "origin_type": "source",
                "dep_params": [],
                "has_unresolved_call": False,
            }
        # 引用参数（&$param）的值由调用者提供，不应作为 passthrough 依赖。
        # 如果函数 return 仅依赖引用参数，调用者的变量已经通过 SAME DFG
        # 连接到 sink，不需要绕经函数内部产生虚假跨参数 taint 传播。
        if _vattr(v, "is_reference", ""):
            return {"origin": vname, "origin_type": "unknown", "dep_params": [], "has_unresolved_call": False}
        return {
            "origin": vname,
            "origin_type": "param",
            "dep_params": [param_idx[start_vid]],
            "has_unresolved_call": False,
        }

    # ── 1b. Fix 44a: same-name parameter use-site (Java/JS SSA vids) ──
    #    Normalizers create distinct vids per use-site; a use of parameter
    #    ``sql`` at L281 has a different vid than the formal parameter node.
    #    Java DFG def-use ordering then routes it through the *last* writer
    #    (e.g. an if-branch assignment) instead of the parameter — the
    #    CVE-2026-38158 parseSql case: ``String sqlForUse=sql`` resolved to
    #    ``new Context`` (safe) and the param dependency was lost, marking
    #    parseSql as a sanitizer.  A bare identifier whose name equals a
    #    parameter name is that parameter's use: resolve to param directly.
    if (vlabel == NodeLabel.IDENTIFIER.value and vtype in ("variable", "identifier")
            and isinstance(vname, str) and vname
            and start_vid not in param_idx):
        for pvid, pidx in param_idx.items():
            pname = _vattr(graph.vs[pvid], "name", "")
            if pname == vname:
                p_taint = _vattr(graph.vs[pvid], "taint_type", "")
                if p_taint == "source":
                    return {"origin": vname, "origin_type": "source",
                            "dep_params": [], "has_unresolved_call": False}
                return {"origin": vname, "origin_type": "param",
                        "dep_params": [pidx], "has_unresolved_call": False}

    # ── 2. 字面量 ──
    if vlabel == NodeLabel.CONST.value:
        # Fix 117g (CVE-2026-110279): container literals / comprehensions
        # (Fix 117b/117c) — and the joinedstr (f-string) precedent —
        # normalize to a CONST node that CARRIES dfg in-edges from its
        # dynamic element expressions (`{k.lower(): v for k, v in
        # request_headers.items()}`, ``f"{param}"``).  Concluding 'literal'
        # here buried the element-origin dependency: get_passthrough_headers
        # summarized as passthrough(pt=[1]) — the tainted param-0 flow
        # through the comprehension vanished — and its caller invoke_tool
        # collapsed to 'safe', so the scanner's safe-cut deleted the
        # arg→call DFG edge and the whole chain died one hop before the
        # sink.  A CONST with dynamic (non-const) dfg sources is a
        # CONTAINER: trace its sources and aggregate.  Pure-literal
        # containers have no dynamic in-edges (117b only links non-Constant
        # elements) and stay literal.
        # Fix 142k (CVE-2026-104126): the 117g filter dropped CONST sources
        # wholesale — but a NESTED container literal (dict-in-dict:
        # ``host.update({'jms_asset': {'address': asset.address, …}})``)
        # is itself a const whose OWN dfg in-edges carry the dynamic member
        # reads.  Skipping it certified the whole outer literal as
        # pure-literal, so asset_to_host summarized 'safe' (the JMSInventory
        # generate→f.write chain died on the full corpus: ladG 173 files
        # detects, ladH 1317 files misses — the corpus only had to grow
        # enough same-name ``update`` defs for the 142i every-candidate
        # safe veto to fire on ``host.update``).  Recurse: a const source
        # with dynamic (non-const) dfg ancestry is a container, not a
        # literal.  Python-scoped (137f doctrine — no php behavior change
        # without anchor evidence).
        def _has_dynamic_142k(_cvid, _d=0):
            if _d > 6:
                return False
            for _s2 in (eidx["in"].get("dfg", {}).get(_cvid) or []):
                if _vattr(graph.vs[_s2], "label", "") != NodeLabel.CONST.value:
                    return True
                if _has_dynamic_142k(_s2, _d + 1):
                    return True
            return False

        _is_py_142k = _vattr(v, "language", "") == "python"
        _dyn_in = [s for s in (eidx["in"].get("dfg", {}).get(start_vid) or [])
                   if _vattr(graph.vs[s], "label", "") != NodeLabel.CONST.value
                   or (_is_py_142k and _has_dynamic_142k(s))]
        if _dyn_in:
            _flows, _unres = [], False
            for _s in _dyn_in:
                if _s in visited:
                    continue
                _sub = _trace_return_value(graph, _s, own_vids, param_idx,
                                           visited, eidx, depth + 1)
                if _sub:
                    _flows.append(_sub)
                    _unres = _unres or bool(_sub.get("has_unresolved_call"))
            if _flows:
                _agg_type, _agg_params = _aggregate_flows(_flows)
                if _agg_type == "source":
                    return {"origin": vname, "origin_type": "source",
                            "dep_params": [], "has_unresolved_call": _unres}
                if _agg_type == "passthrough":  # param deps present
                    return {"origin": vname, "origin_type": "param",
                            "dep_params": list(_agg_params),
                            "has_unresolved_call": _unres}
                # safe / literal / unknown — propagate with unresolved flag
                # so 'unknown' containers defer instead of certifying safe.
                return {"origin": vname, "origin_type": _agg_type,
                        "dep_params": list(_agg_params),
                        "has_unresolved_call": _unres}
        return {"origin": vname, "origin_type": "literal", "dep_params": [], "has_unresolved_call": False}

    # ── 2.5. 节点自身已有 taint_type 注解（由 enrich_taint 或 _enrich_source_variables 标注） ──
    #     适用于 identifier/function/statement 等非 operator 节点。
    #     例如: return \$_GET (identifier 被标注为 source)
    #     operator 节点在 step 3 中单独处理（因为 call 还需要追踪 use→function）。
    self_taint = _vattr(v, "taint_type", "")
    if self_taint == "source":
        return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
    if self_taint == "safe":
        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
    if self_taint == "passthrough":
        pt = _vattr(v, "taint_passthrough", [])
        if pt:
            return _trace_passthrough_call(graph, start_vid, pt, own_vids, param_idx, visited, eidx, depth)

    # ── 2.6. $this / self（链式调用返回自身实例） ──
    #     PHP/Java 中 `return $this` / `return self` 是链式调用模式，
    #     返回的是当前对象实例，不是外部输入，视为 safe。
    if vlabel == NodeLabel.IDENTIFIER.value:
        iname = _vattr(v, "name", "")
        if isinstance(iname, str) and iname in ("$this", "self"):
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        # phply 格式: Variable('$this')
        if isinstance(iname, str) and ("$this" in iname or iname.strip("'\"") == "$this"):
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 2.7. 静态属性/常量（identifier type='static'） ──
    #     self::$instance（name 含 Variable，可能从外部赋值）不安全；
    #     ORM::LIMIT_STYLE_TOP_N（name 不含 Variable，静态常量）safe。
    #     self::$_config[$key]（name 含 Variable('$key')，$key 是参数）→ passthrough。
    if vlabel == NodeLabel.IDENTIFIER.value and vtype == "static":
        if "Variable(" not in vname:
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        # 提取 name 中的所有 Variable('$xxx') 名，尝试与参数关联
        import re as _re
        var_names = _re.findall(r"Variable\('\$(\w+)'\)", vname)
        if var_names:
            matched_params = []
            for vn in var_names:
                for pvid, pidx in param_idx.items():
                    pname = _vattr(graph.vs[pvid], "name", "")
                    # 参数名可能是 $xxx 或 Variable('$xxx')
                    if pname.endswith("$" + vn) or ("Variable('$" + vn + "'") in pname:
                        matched_params.append(pidx)
                        break
            if matched_params:
                unique = list(dict.fromkeys(matched_params))
                return {"origin": vname, "origin_type": "param",
                        "dep_params": unique, "has_unresolved_call": False}

    # ── 3. Operator（call, method_call, static_call 等） ──
    if vlabel == NodeLabel.OPERATOR.value:
        # 3a. 已有 taint_type 注解（builtin 函数，由 enrich_taint 标注）
        taint = _vattr(v, "taint_type", "")
        if taint == "source":
            return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
        if taint == "safe":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        if taint == "passthrough":
            pt = _vattr(v, "taint_passthrough", [])
            _pt_res = _trace_passthrough_call(graph, start_vid, pt, own_vids, param_idx, visited, eidx, depth)
            # Fix 117m (CVE-2026-110279): receiver passthrough.  The python
            # builtin knowledge models container-view methods as
            # ``__method__.items => {"passthrough": ["this"]}`` — enrich_taint
            # resolves the "this" index into ``taint_receiver_pt=True`` with
            # an EMPTY taint_passthrough (node 41 ``request_headers.items()``
            # mini task 6447: taint_passthrough=[], taint_receiver_pt=True).
            # The analyzer consumes the flag (graph_analyzer Rule 4 via
            # _trace_call_receiver), but this summary tracer never did —
            # _trace_passthrough_call found no ast args and returned
            # 'unknown', so get_passthrough_headers lost the param-0 leg
            # (pt=[1] instead of [0,1]) and invoke_tool collapsed to 'safe'
            # (the safe-cut then deleted the arg→call DFG edge).  Consume the
            # flag for python method calls — the receiver reaches the op via
            # dfg, never as an ast arg (same shape Fix 117h-2 traced).
            if (_vattr(v, "taint_receiver_pt", False)
                    and _vattr(v, "language", "") == "python"
                    and vtype == "method_call"):
                _recv = _trace_method_receivers(
                    graph, start_vid, own_vids, param_idx, visited, eidx, depth)
                if _recv and _recv.get("origin_type") in ("source", "param"):
                    if (_pt_res and _pt_res.get("origin_type") == "source"
                            and _recv.get("origin_type") != "source"):
                        return _pt_res  # an explicit-arg source still wins
                    if (_pt_res and _pt_res.get("origin_type") == "param"
                            and _recv.get("origin_type") == "param"):
                        _merged = dict(_recv)
                        _merged["dep_params"] = sorted(set(
                            list(_recv.get("dep_params", []))
                            + list(_pt_res.get("dep_params", []))))
                        _merged["has_unresolved_call"] = bool(
                            _recv.get("has_unresolved_call")) or bool(
                            _pt_res.get("has_unresolved_call"))
                        return _merged
                    return _recv
            return _pt_res

        # Fix 72d: subscript reads are CONTAINER accesses, not function
        # calls.  `self.cfg['k']` normalizes to a 'call' operator whose name
        # embeds the bracket ('...config[...]'), and 3b's fallback then
        # concluded 'safe' from the literal KEY — hiding the container's
        # config-file origin entirely (CVE-2026-109830).  For bracket-named
        # calls, trace the CONTAINER child (the ast object operand) instead.
        _nm = vname or ''
        if vtype == 'call' and ('[' in _nm or _nm.endswith('[]')):
            _container_result = None
            for _cv, _role, _ in eidx['ast_ch'].get(start_vid, []):
                if _role in ('object', 'callee', 'arg0', 'arg', 'value'):
                    _sub = _trace_return_value(graph, _cv, own_vids, param_idx, visited, eidx, depth + 1)
                    if _sub and _sub.get('origin_type') in ('source', 'param'):
                        return _sub
                    if _sub and _sub.get('origin_type') == 'unknown':
                        _container_result = _sub
                    # Fix 72e: an EMPTY-flow 'safe' on the container means the
                    # trace hit a DFG break (per-occurrence property nodes are
                    # not linked) — not a proven-sanitized value.  A property
                    # container with no own flows must not certify the whole
                    # subscript read as safe.
                    if (_sub and _sub.get('origin_type') == 'safe'
                            and not eidx['in'].get('dfg', {}).get(_cv)):
                        _container_result = _sub
            # Fix 72d-2: container-origin unknown must NOT fall into 3b's
            # call-summary path — the literal subscript KEY would conclude
            # 'safe' and bury the container's config-file origin.  Before
            # giving up, run the 72c cross-method property union BFS from the
            # container (same-name property nodes carry the __init__ chain:
            # prop ← self.config[...] ← getConfig() summary=source).
            if _container_result is not None:
                for _cv, _role, _ in eidx['ast_ch'].get(start_vid, []):
                    if _role in ('object', 'callee', 'arg0', 'arg', 'value'):
                        _cnode = graph.vs[_cv]
                        _cname = _vattr(_cnode, "name", "")
                        if not _cname:
                            continue
                        _seeds = {v3.index for v3 in graph.vs
                                  if _vattr(v3, "type", "") == "property"
                                  and _vattr(v3, "name", "") == _cname}
                        _stack, _seen = list(_seeds), set()
                        _hop = 0
                        while _stack and _hop < 12:
                            cur = _stack.pop()
                            if cur in _seen:
                                continue
                            _seen.add(cur)
                            _hop += 1
                            if _vattr(graph.vs[cur], "taint_type", "") == "source":
                                return {"origin": vname, "origin_type": "source",
                                        "dep_params": [], "has_unresolved_call": False}
                            cur_node = graph.vs[cur]
                            if (_vattr(cur_node, "label", "") == NodeLabel.OPERATOR.value
                                    and _vattr(cur_node, "type", "") in _CALL_TYPES):
                                for uv in eidx["out"].get("use", {}).get(cur, []):
                                    if _vattr(graph.vs[uv], "func_summary_type", "") == "source":
                                        return {"origin": vname, "origin_type": "source",
                                                "dep_params": [], "has_unresolved_call": False}
                                # Fix 72g: a subscript call ('self.config[...]')
                                # carries its container on the ast callee/object
                                # role — dfg edges alone never cross it.  Jump
                                # to the container AND union its same-name
                                # property occurrences (L25 read vs L18 store).
                                _cur_nm = _vattr(cur_node, "name", "") or ""
                                if _cur_nm and ("[" in _cur_nm or _cur_nm.endswith("[]")):
                                    for _c2, _r2, _ in eidx["ast_ch"].get(cur, []):
                                        if _r2 in ("object", "callee", "arg0"):
                                            _c2n = _vattr(graph.vs[_c2], "name", "")
                                            if _c2n:
                                                for v4 in graph.vs:
                                                    if (_vattr(v4, "type", "") == "property"
                                                            and _vattr(v4, "name", "") == _c2n):
                                                        _stack.append(v4.index)
                                                _stack.append(_c2)
                            for pv in eidx["in"].get("dfg", {}).get(cur, []):
                                _stack.append(pv)
                return {"origin": vname, "origin_type": "unknown",
                        "dep_params": [], "has_unresolved_call": True}
            # container literal-only → fall to generic DFG below

        # 3b. call operator → 尝试 use → function（用户自定义函数的摘要）
        if vtype in _CALL_TYPES:
            result = _trace_call_to_function(graph, start_vid, own_vids, param_idx, visited, eidx, depth)
            # Fix 125b: 跨函数桥接通道的有界 source 证据 BFS（对任何
            # 摘要结果都跑——实案里 callee 摘要恰返回 unknown）。
            # call op 自身可携带 dfg 入边——Fix 123 的 store→load 桥、
            # 跨文件 Fix 124c 返回值绑定——这些通道天生跨函数，而下面
            # 的聚合递归（125）受 own_vids/同文件约束（Fix 117i-2），
            # 3f 只看 ast 实参，section 4 又跳过 foreign 源：实案
            # pfSense get_configured_vip_detail 内 config_get_path(
            # 'virtualip/vip') 的 op 入边带着 saveVIP 存入的 $vipent
            # （含 $_POST['vhid']），三条常规通路全部看不见，函数被误
            # 标 safe → sink 处 code=2 消毒。与 Fix 72c 同型的有界 BFS
            # （hop<12）沿 dfg 祖先直接找 taint_type=source 注解或
            # summary=source 的调用点；source 证据压过一切摘要结论。
            if not (result and result.get("origin_type") == "source"):
                _bfs_hit = _bridge_source_bfs(graph, start_vid, eidx, visited)
                if _bfs_hit:
                    return {"origin": vname, "origin_type": "source",
                            "dep_params": [], "has_unresolved_call": False}
            if result and result.get("origin_type") != "unknown":
                # Fix 125 (CVE-2026-111217): 图谱证据覆盖 callee 摘要。
                # own-vid 入边的聚合递归：call op 的 dfg 入边中属于本函数
                # 的部分（124c 返回值绑定等），按 117g 容器同型聚合，
                # source/param 证据压过 safe/literal 摘要。
                if result.get("origin_type") in ("safe", "literal", "param"):
                    _dyn_in = [s for s in (eidx["in"].get("dfg", {}).get(start_vid) or [])
                               if s not in visited]
                    if _dyn_in:
                        _flows, _unres = [], False
                        for _s in _dyn_in:
                            _sub = _trace_return_value(
                                graph, _s, own_vids, param_idx, visited, eidx, depth + 1)
                            if _sub:
                                _flows.append(_sub)
                                _unres = _unres or bool(_sub.get("has_unresolved_call"))
                        if _flows:
                            _agg_t, _agg_p = _aggregate_flows(_flows)
                            if _agg_t == "source":
                                return {"origin": vname, "origin_type": "source",
                                        "dep_params": [],
                                        "has_unresolved_call": _unres}
                            if _agg_t == "passthrough" and _agg_p:
                                return {"origin": vname, "origin_type": "param",
                                        "dep_params": list(_agg_p),
                                        "has_unresolved_call": _unres}
                return result
            # 3f. 目标函数无摘要（unknown）→ fallback 追踪 ast 实参
            #     如果实参中包含 source parameter 的引用，call 返回值也继承该 origin。
            #     这是保守估计：对于无摘要的外部/框架函数，假设返回值包含实参的污点。
            #
            # BUT: if the call target is a user-defined function whose summary
            # hasn't been computed yet (e.g. Format::htmlchars called by
            # Format::input before htmlchars's summary is ready), mark as
            # unresolved so build_function_summaries defers this function to
            # a later iteration round.
            has_use_target = bool(eidx["out"].get("use", {}).get(start_vid, []))
            if result and result.get("has_unresolved_call"):
                for arg_vid, role, arg_idx in eidx["ast_ch"].get(start_vid, []):
                    if not role.startswith("arg"):
                        continue
                    # 跳过 callee（ast child role 不是 arg 的部分）
                    arg_sub = _trace_return_value(graph, arg_vid, own_vids, param_idx, visited, eidx, depth + 1)
                    if arg_sub and arg_sub.get("origin_type") in ("source", "param"):
                        return {"origin": vname, "origin_type": arg_sub["origin_type"],
                                "dep_params": arg_sub.get("dep_params", []),
                                "has_unresolved_call": has_use_target}
                    # 如果实参中有 source 但 return type 是 unknown，优先报告 unknown
                    if arg_sub and arg_sub.get("origin_type") == "unknown":
                        # 继续检查其他实参
                        pass

        # 3c. 内置安全构造函数——不传播外部污点
        #     array() 是 PHP 数组字面量构造，返回值仅由参数决定，
        #     但其参数（如果有的话）已经通过 arg DFG 被单独追踪。
        #     call 本身视为 safe 容器。
        callee = _vattr(v, "callee", "")
        if callee == "array":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

        # 3d. type_cast → 追踪内部表达式（passthrough）
        #     (int)$x, (string)$x, (bool)$x — 类型转换不消除污点，
        #     结果取决于内部表达式。递归追踪 ast 子节点。
        if vtype == "type_cast":
            for inner in [t for t, r, _ in eidx["ast_ch"].get(start_vid, [])]:
                sub = _trace_return_value(graph, inner, own_vids, param_idx, visited, eidx, depth + 1)
                if sub["origin_type"] in ("source", "param", "safe"):
                    return sub
                # 内部是 unknown/literal → type_cast 也是 unknown
                return sub
            # 无子节点 → safe（如 return (int) 42 — 但正常不会被解析为 type_cast）
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

        # 3e. new → 安全构造（无外部输入）
        #     new ClassName() 创建新实例，不传播外部污点。
        #     Fix 143m (CVE-2026-129448): EXCEPT when the builtin knowledge
        #     explicitly declares the constructor as carrying its argument's
        #     taint — java ``Cls.Cls`` entries with a non-empty passthrough
        #     list and safe=False (ObjectInputStream(bais) wraps the
        #     attacker-controlled stream; ByteArrayInputStream(res) wraps the
        #     decoded buffer).  The blanket-safe here certified
        #     SerializableParser.getResult as 'safe' via ``return
        #     ois.readObject()`` (receiver ois ← new ObjectInputStream),
        #     and the scanner's safe-cut then severed the call-site return
        #     edges of the whole deserialization chain.  Honor the declared
        #     passthrough args: trace them and let the strongest verdict win;
        #     literal/safe/absent args keep the constructor-safe verdict.
        if vtype == "new":
            _new_cls = str(vname)
            if _new_cls.startswith("new "):
                _new_cls = _new_cls[4:].split("(", 1)[0].strip()
            if (_new_cls
                    and _vattr(v, "language", "") == "java"):
                try:
                    from core.core_engine.java.builtin_knowledge import KNOWLEDGE as _JAVA_BK_143M
                    _ctor_key = f"{_new_cls}.{_new_cls}"
                    _ctor_e = _JAVA_BK_143M.get(_ctor_key)
                except Exception:
                    _ctor_e = None
                if (_ctor_e and not _ctor_e.get("safe", True)
                        and _ctor_e.get("passthrough")):
                    _arg_flows_143m = []
                    for _a143_t, _a143_r, _a143_i in eidx["ast_ch"].get(start_vid, []):
                        if not (_a143_r or "").startswith("arg"):
                            continue
                        _asub = _trace_return_value(
                            graph, _a143_t, own_vids, param_idx,
                            visited, eidx, depth + 1)
                        if _asub:
                            _arg_flows_143m.append(_asub)
                    if _arg_flows_143m:
                        _agg143, _aggp143 = _aggregate_flows(_arg_flows_143m)
                        if _agg143 in ("source", "passthrough"):
                            return {"origin": vname, "origin_type": _agg143,
                                    "dep_params": [], "has_unresolved_call": False}
                        if _agg143 == "param":
                            return {"origin": vname, "origin_type": "param",
                                    "dep_params": list(_aggp143),
                                    "has_unresolved_call": False}
                        if _agg143 == "unknown":
                            return {"origin": vname, "origin_type": "unknown",
                                    "dep_params": [],
                                    "has_unresolved_call": any(
                                        f.get("has_unresolved_call")
                                        for f in _arg_flows_143m)}
            # Fix 145b (CVE-2026-124468): PHP corpus-class constructors
            # carry their argument's taint into the object state — the
            # 143m doctrine, but driven by the CORPUS ctor instead of
            # builtin knowledge.  OpenEMR's FhirSearchWhereClauseBuilder
            # ends ``return new SearchQueryFragment($where,
            # $sqlBindArray)`` where $where embeds the attacker-derived
            # WHERE fragment: the blanket constructor-safe certified
            # build() as 'safe', and Rule 3a2's summary veto severed the
            # whole REST search chain at every call site.  Only classes
            # with a file-backed __construct qualify (their state is
            # knowable); framework externals keep the safe verdict.
            if (_new_cls
                    and _vattr(v, "language", "") == "php"
                    and _php_corpus_ctor_idx(graph).get(
                        _new_cls.rsplit(chr(92), 1)[-1]) is not None):
                _arg_flows_145b = []
                for _a145_t, _a145_r, _ in eidx["ast_ch"].get(start_vid, []):
                    if not (_a145_r or "").startswith("arg"):
                        continue
                    _asub145 = _trace_return_value(
                        graph, _a145_t, own_vids, param_idx,
                        visited | {start_vid}, eidx, depth + 1)
                    if _asub145:
                        _arg_flows_145b.append(_asub145)
                if _arg_flows_145b:
                    _agg145, _aggp145 = _aggregate_flows(_arg_flows_145b)
                    if _agg145 in ("source", "passthrough"):
                        return {"origin": vname, "origin_type": _agg145,
                                "dep_params": [], "has_unresolved_call": any(
                                    f.get("has_unresolved_call")
                                    for f in _arg_flows_145b)}
                    if _agg145 == "param":
                        return {"origin": vname, "origin_type": "param",
                                "dep_params": list(_aggp145),
                                "has_unresolved_call": any(
                                    f.get("has_unresolved_call")
                                    for f in _arg_flows_145b)}
                    if _agg145 == "unknown":
                        return {"origin": vname, "origin_type": "unknown",
                                "dep_params": [], "has_unresolved_call": any(
                                    f.get("has_unresolved_call")
                                    for f in _arg_flows_145b)}
                # no args / literal-safe args → fall through to the
                # blanket constructor-safe below
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 3.5. Branch/Ternary 追踪 ──
    #    return $x ? $a : $b — 追踪 iftrue 和 iffalse 两个分支，
    #    聚合结果（condition 不影响污点传播）。
    if vlabel == NodeLabel.BRANCH.value:
        branch_flows = []
        for tgt, role, _ in eidx["ast_ch"].get(start_vid, []):
            if role in ("iftrue", "iffalse"):
                sub = _trace_return_value(graph, tgt, own_vids, param_idx, visited, eidx, depth + 1)
                branch_flows.append(sub)
        if branch_flows:
            # 用 _aggregate_flows 聚合所有分支
            agg_type, agg_params = _aggregate_flows(branch_flows)
            if agg_type in ("source", "param"):
                return {"origin": vname, "origin_type": agg_type,
                        "dep_params": list(agg_params), "has_unresolved_call": any(f.get("has_unresolved_call") for f in branch_flows)}
            if agg_type == "safe":
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            if agg_params:
                return {"origin": vname, "origin_type": "param",
                        "dep_params": list(agg_params), "has_unresolved_call": any(f.get("has_unresolved_call") for f in branch_flows)}
            # 所有分支都 unknown
            return {"origin": vname, "origin_type": "unknown", "dep_params": [],
                    "has_unresolved_call": any(f.get("has_unresolved_call") for f in branch_flows)}

    # ── 3.6. Return statement → trace AST[value] child ──
    #    return Format::htmlchars($var)
    #    → return node has AST child role=value → htmlchars call operator
    #    → trace into it to determine if it's safe/passthrough/source
    if vlabel == NodeLabel.RETURN.value:
        value_children = [
            (tgt, role, idx)
            for tgt, role, idx in eidx["ast_ch"].get(start_vid, [])
            if role == AstRole.VALUE.value
        ]
        if value_children:
            sub = _trace_return_value(graph, value_children[0][0], own_vids, param_idx, visited, eidx, depth + 1)
            if sub and sub.get("origin_type") != "unknown":
                return sub

    # ── 4. 通用 DFG 反向追踪 ──
    all_dep_params: list[int] = []
    has_source = False
    has_safe = False
    any_unresolved = False
    dfg_has_safe_source = False  # DFG 链中是否存在 safe/literal 源

    # Collect DFG sources, prioritizing safe/source over param.
    # When a binary_op has both h($x) (safe) and $x (param) as DFG sources,
    # safe should take precedence — the parameter is only reachable through
    # the safe function call, not directly.
    # Fix 90: parallel/multi DFG edges (e.g. `$where .= " . " . f() . " "`
    # inside a loop creates repeated def-use pairs) made dfg_src_list contain
    # the same vid many times; the per-source recursion below then fans out
    # exponentially through concat diamonds (ci_scan stuck 30min+ on the
    # openemr repro).  Duplicate sources carry no extra tracing information —
    # dedupe, preserving first-seen order.
    dfg_src_list = list(dict.fromkeys(eidx["in"].get("dfg", {}).get(start_vid, [])))

    # Fix 46d: for concat binary_op ('.'), a safe operand must NOT
    # short-circuit a param operand — "safe_prefix" . $param keeps the
    # parameter dependency.  Only a non-concat single-source (or an
    # operand pair where ALL sources are safe) may conclude safe.
    _is_concat = (vlabel == NodeLabel.OPERATOR.value
                  and _vattr(v, "type", "") == "binary_op"
                  and vname in (".", "+", "+="))
    _first_pass_safe = None
    _first_pass_source = None

    # Two-pass: first check for immediate safe/source taint on DFG sources
    for src_vid in dfg_src_list:
        src_taint = _vattr(graph.vs[src_vid], "taint_type", "")
        if src_taint == "source":
            if _is_concat:
                _first_pass_source = src_vid
                continue
            return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
        if src_taint == "safe":
            if _is_concat:
                _first_pass_safe = src_vid
                continue
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        # For call operators, check use→function for func_summary_type
        src_label = _vattr(graph.vs[src_vid], "label", "")
        src_type = _vattr(graph.vs[src_vid], "type", "")
        if src_label == NodeLabel.OPERATOR.value and src_type in _CALL_TYPES:
            result = _trace_call_to_function(graph, src_vid, own_vids, param_idx, visited, eidx, depth)
            if result and result.get("origin_type") in ("safe", "source"):
                return result

    # Fix 72c: cross-method self-property reachability.  `return
    # self.external_db9_serial_config['k']` in a getter cannot see the
    # assignment in __init__ (it lives outside own_vids), so the flow ends
    # 'unknown' and the whole config-file → getter → sink chain dies
    # (CVE-2026-109830 board-conf-tools).  For identifier/property nodes,
    # follow dfg in-edges ONE hop past the function boundary: if the
    # out-of-function dfg source (the __init__ assign) has any own dfg
    # ancestry annotated 'source', treat this flow as source-origin.
    _own_dfg_srcs = [s for s in dfg_src_list if s in own_vids]
    _foreign_dfg_srcs = [s for s in dfg_src_list if s not in own_vids]
    if (not _own_dfg_srcs and _foreign_dfg_srcs
            and vlabel in (NodeLabel.IDENTIFIER.value,)):
        # Fix 72c-2: python properties of the same attribute are separate
        # nodes per occurrence (L25 store vs L37 load, no dfg edge between)
        # — union all same-name property nodes before the bounded BFS.
        _prop_seed = set()
        for fv in _foreign_dfg_srcs:
            fnode = graph.vs[fv]
            if _vattr(fnode, "type", "") not in ("property", "variable"):
                continue
            _prop_seed.add(fv)
        if _prop_seed:
            _seed_names = {_vattr(graph.vs[fv], "name", "") for fv in _prop_seed}
            # Fix 87: bucket-index lookup replaces the per-call full
            # graph.vs linear scan (O(N) each → O(N) once per graph).
            _pidx = _property_name_index(graph)
            for _pn in _seed_names:
                _prop_seed.update(_pidx.get(_pn, ()))
            for fv in _prop_seed:
                fnode = graph.vs[fv]
            # BFS the foreign node's dfg ancestry (bounded) for a source
            # annotation — the __init__ chain: prop ← config ← json.load.
            _stack, _seen = [fv], set()
            _hop = 0
            while _stack and _hop < 12:
                cur = _stack.pop()
                if cur in _seen:
                    continue
                _seen.add(cur)
                _hop += 1
                if _vattr(graph.vs[cur], "taint_type", "") == "source":
                    return {"origin": vname, "origin_type": "source",
                            "dep_params": [], "has_unresolved_call": False}
                # Fix 72c-3: a call node's summary lives on its use-target
                # function (func_summary_type) — the static taint_type of a
                # method_call node stays empty even when the callee is a
                # known source producer (self.getConfig() → source).
                cur_node = graph.vs[cur]
                if (_vattr(cur_node, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(cur_node, "type", "") in _CALL_TYPES):
                    for uv in eidx["out"].get("use", {}).get(cur, []):
                        if _vattr(graph.vs[uv], "func_summary_type", "") == "source":
                            return {"origin": vname, "origin_type": "source",
                                    "dep_params": [], "has_unresolved_call": False}
                for pv in eidx["in"].get("dfg", {}).get(cur, []):
                    _stack.append(pv)
        # fall through to normal handling below

    # Second pass: trace into own-vid sources
    # CVE-2026-62007: when multiple DFG sources feed a use (e.g. a variable
    # that was initialized from a literal AND later received an array-item
    # write-back `$arr['k'] = $param`), a safe source must NOT short-circuit
    # a param source.  "safe wins" is only correct when ALL sources are
    # safe/literal.  Generalizes Fix 46d (which fixed this for concat only)
    # to any operator: collect safe/literal flags, keep scanning for
    # source/param, and only conclude safe when nothing stronger was found.
    # Fix 117i (CVE-2026-110279): python def-use chains hop
    # identifier-to-identifier (assign-LHS def occurrence → later use
    # occurrence).  Identifier occurrences are NEVER own_vids (they are
    # ast children of their assign op), so a two-hop chain
    # (``x = f(param); y = x``) died 'unknown' after one hop — the
    # subscript write-back value (sanitized_value@L23 ← def@L20) never
    # reached the container's return trace.  Python-only: also trace
    # foreign IDENTIFIER sources (visited/depth bounds hold); PHP def-use
    # semantics stay calibrated on the php anchors.
    _py_ident_hop = _vattr(v, "language", "") == "python"
    _second_safe_seen = False
    _second_unknown_seen = False  # Fix 98c: an unknown source means the trace
    # was incomplete (e.g. a chain that leaves the function).  A single
    # literal/safe source must NOT certify the whole node as safe — that
    # turned container-building functions (`rows.append(derived_from_param)`
    # next to a literal init) into "sanitizers" and silently killed the
    # CVE-2026-29080 FilterEngine chain.  Only conclude safe when every
    # traced source is safe/literal.
    for src_vid in dfg_src_list:
        if src_vid not in own_vids:
            # Fix 117i: python foreign-identifier def-use hop (see comment
            # above).  Also admit foreign CONST nodes that carry dynamic
            # dfg in-edges — the Fix 117b/117c container/comprehension
            # results are emitted as CONSTs and never live in own_vids
            # (``x = {.. for .. in tainted.items()}`` — the IfExp/branch
            # assign links the container CONST straight to the LHS def).
            # Pure literals (no dfg in-edges) stay skipped — they can
            # only resolve 'literal'.
            # Every other foreign source keeps the skip.
            # Fix 117i-2 (CVE-2026-110279): bound the admission to
            # SAME-FILE hops.  The def-use chains this fix exists for are
            # function-local (``x = f(param); y = x`` inside one function);
            # admitting every foreign identifier in the module let one
            # trace fan out across the whole file's def-use graph —
            # mcpgateway corpus (1553 files / 12k summaries) spent >12min
            # inside build_function_summaries (py-spy: 14-deep
            # _trace_return_value chains at the dfg-source loop) where the
            # pre-117i build finished in seconds.  Cross-file def-use is
            # the analyzer's (parameters_back) job at scan time, not the
            # summary contract's.
            if _py_ident_hop:
                _sl = _vattr(graph.vs[src_vid], "label", "")
                _sf_ok = (_vattr(graph.vs[src_vid], "file_path", "")
                          == _vattr(v, "file_path", ""))
                if not _sf_ok:
                    continue
                if _sl == NodeLabel.IDENTIFIER.value:
                    pass  # admitted
                elif (_sl == NodeLabel.CONST.value
                        and (eidx["in"].get("dfg", {}).get(src_vid) or [])):
                    pass  # dynamic container const — admitted
                else:
                    continue
            else:
                continue
        sub = _trace_return_value(graph, src_vid, own_vids, param_idx, visited, eidx, depth + 1)
        if sub["origin_type"] == "source":
            if _is_concat:
                continue  # collect; concat may also carry params
            return sub  # source 立即返回
        if sub["origin_type"] == "safe":
            if _is_concat:
                dfg_has_safe_source = True
                continue  # safe operand doesn't erase other operands
            _second_safe_seen = True
            dfg_has_safe_source = True
            continue  # keep scanning — another source may be param/source
        if sub["origin_type"] == "literal":
            dfg_has_safe_source = True
            continue  # 字面量不传播污点，忽略此 DFG 源
        if sub["origin_type"] == "unknown":
            _second_unknown_seen = True
        all_dep_params.extend(sub.get("dep_params", []))
        if sub.get("has_unresolved_call"):
            any_unresolved = True
    if not all_dep_params and not any_unresolved and _second_safe_seen:
        # Fix 98c-gate: python-only.  Ungated, the unknown-mix veto flipped
        # hundreds of PHP method summaries (safe → unknown) corpus-wide:
        # PHP functions routinely mix a literal/safe init with a chain that
        # leaves the function, and the calibrated safe verdict there is what
        # the osticket anchor (88) is measured against — ungated 98c alone
        # added +260 XSS rows (task 6162: 340 vs baseline 88).  The veto is
        # only needed for the python FilterEngine container-building shape
        # (`rows.append(derived_from_param)` next to a literal init).
        _py98c = _vattr(graph.vs[start_vid], "language", "") == "python"
        if _second_unknown_seen and _py98c:
            # safe + unknown mix → inconclusive, not proven safe
            return {"origin": vname, "origin_type": "unknown", "dep_params": [], "has_unresolved_call": False}
        # every own-vid source resolved safe/literal → safe
        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 5. Member 边检查（$obj[$key] / obj.prop 等成员访问） ──
    #    identifier 通过 member 边连接到容器对象，如果容器是 source，
    #    则 member access 的结果也是 source。
    #    e.g. $_COOKIE['theme'] → member ← $_COOKIE (source)
    #    e.g. $array[array_rand($array)] → member ← $array (parameter)
    if vlabel == NodeLabel.IDENTIFIER.value:
        _unknown_origin = None  # Fix 53-scope: hoisted — de-indent moved the
        _pn = None  # Fix 145f static-safety init (bound in the $this branch)
        # 52z-8 consumer (L772) outside the `if isinstance(_prop_name...)`
        # block while its init stayed inside → UnboundLocalError killed
        # build_function_summaries on osticket (whole summaries silently
        # skipped).  Initialize at the identifier branch top instead.
        for container_vid in eidx["in"].get("member", {}).get(start_vid, []):
            container = graph.vs[container_vid]
            container_taint = _vattr(container, "taint_type", "")
            # $this / self：链式调用或属性访问，返回对象实例，非外部输入
            container_name = _vattr(container, "name", "")
            if isinstance(container_name, str) and container_name in ("$this", "self"):
                # Fix 52z-3: $this->prop is not inherently safe — the
                # property is assigned in the class __construct
                # ($this->data = JSON::decode($node['data'])).  Scan
                # every __construct in the graph for an assign whose LHS
                # resolves to this property name; trace its RHS.  Only
                # fall back to safe when no such assign exists.
                _prop_name = _vattr(v, "name", "")
                if isinstance(_prop_name, str) and _prop_name:
                    _pn = _prop_name.strip(chr(39) + chr(34))
                    _unknown_origin = None  # Fix 52z-8
                    # Fix 53-perf: the 52z-3 full-graph __construct scan ran
                    # per property-hit inside _trace_return_value — on
                    # osticket (370k nodes) that's a 370k-node linear scan
                    # fired thousands of times (quadratic blowup, scan stuck
                    # >20min in build_function_summaries).  Index all
                    # __construct function nodes once per graph (id() keyed).
                    _gk = id(graph)
                    _ctors = _CTOR_NODES_CACHE.get(_gk)
                    if _ctors is None:
                        # Fix 98b: python constructors are named __init__ —
                        # scanning only PHP's __construct left every python
                        # self-field read in a method to fall through to the
                        # "chained $this/self" safe verdict, so a tainted
                        # field written in __init__ (self._rows = <param-
                        # derived>) read in another method was certified safe
                        # and the return summary of the reading method became
                        # 'safe' (CVE-2026-29080 FilterEngine t18 shape).
                        _ctors = [
                            _fv2.index for _fv2 in graph.vs
                            if (_vattr(_fv2, "label", "") == NodeLabel.FUNCTION.value
                                and str(_vattr(_fv2, "name", "")) in ("__construct", "__init__"))
                        ]
                        _CTOR_NODES_CACHE[_gk] = _ctors
                    for _fv_idx in _ctors:
                        _fv = graph.vs[_fv_idx]
                        # Fix 52z-4: build the ctor's own param_idx —
                        # the RHS references ctor parameters ($node),
                        # invisible under the outer function's params.
                        _ctor_pidx = {}
                        for _cp, _ci in eidx["own_ch"].get(_fv.index, []):
                            if (_vattr(graph.vs[_cp], "label", "") == NodeLabel.PARAMETER.value
                                    and _ci not in (None, "")):
                                _ctor_pidx[_cp] = int(_ci)
                        # Fix 63b: memoized per-(ctor, prop) assign lookup
                        # (BFS result depends only on graph+eidx).
                        _assign_key = (id(graph), _fv.index, _pn)
                        _memo_assign = _CTOR_ASSIGN_CACHE.get(_assign_key, _CTOR_MISS)
                        if _memo_assign is not _CTOR_MISS:
                            if _memo_assign is not None:
                                for _rt, _rr, _ in eidx["ast_ch"].get(_memo_assign, []):
                                    if _rr in ("rhs", "right"):
                                        _sub = _trace_return_value(
                                            graph, _rt, own_vids, _ctor_pidx,
                                            visited | {start_vid}, eidx, depth + 1)
                                        if _sub.get("origin_type") in ("source", "param"):
                                            return _sub
                                        if _sub.get("dep_params"):
                                            return _sub
                                        if _unknown_origin is None:
                                            _unknown_origin = _sub
                            _resolved = True
                            break
                        # BFS the ctor subtree (own + ast edges); an
                        # assign node hangs off own, so check each
                        # POPPED node itself (v2 fix: children of ast
                        # edges are operands, never the assign).
                        _stack = [_fv.index]
                        _seen = set()
                        _resolved = False
                        while _stack and not _resolved:
                            _x = _stack.pop()
                            if _x in _seen:
                                continue
                            _seen.add(_x)
                            _xv = graph.vs[_x]
                            _xl = _vattr(_xv, "label", "")
                            if _xl == NodeLabel.FUNCTION.value and _x != _fv.index:
                                continue  # don't cross into siblings
                            if (_xl == NodeLabel.OPERATOR.value
                                    and _vattr(_xv, "type", "") in ("assign", "aug_assign")):
                                for _lt, _lr, _ in eidx["ast_ch"].get(_x, []):
                                    if _lr in ("lhs", "left"):
                                        _lname = str(_vattr(graph.vs[_lt], "name", ""))
                                        if _pn and _pn == _lname.strip(chr(39) + chr(34)):
                                            for _rt, _rr, _ in eidx["ast_ch"].get(_x, []):
                                                if _rr in ("rhs", "right"):
                                                    _sub = _trace_return_value(
                                                        graph, _rt, own_vids, _ctor_pidx,
                                                        visited | {start_vid}, eidx, depth + 1)
                                                    if _sub.get("origin_type") in ("source", "param"):
                                                        return _sub
                                                    if _sub.get("dep_params"):
                                                        return _sub
                                                    # Fix 52z-8 (CVE-2026-110185): the
                                                    # property IS assigned in a ctor but
                                                    # its RHS origin is unknown (e.g.
                                                    # GlobalNodes::$this->nodeData =
                                                    # fetchNodeData() → FlowNode::where()
                                                    # ->all() ORM read).  "origin
                                                    # unresolved" is NOT evidence of
                                                    # safety — an ORM/DB read returns
                                                    # stored user input.  Record the
                                                    # unresolved origin and fall through
                                                    # to unknown instead of safe.
                                                    if _unknown_origin is None:
                                                        _unknown_origin = _sub
                                            _CTOR_ASSIGN_CACHE[_assign_key] = _x
                                            _resolved = True
                                            break
                            # expand: ast children + own children
                            for _t, _r, _ in eidx["ast_ch"].get(_x, []):
                                if _t not in _seen:
                                    _stack.append(_t)
                            for _t2 in eidx["out"].get("own", {}).get(_x, []):
                                if _t2 not in _seen:
                                    _stack.append(_t2)
                        if not _resolved:
                            # BFS exhausted: this ctor never assigns the
                            # property — memoize the miss too (Fix 63b).
                            _CTOR_ASSIGN_CACHE[_assign_key] = None
                        if _resolved:
                            break
            # Fix 145d (CVE-2026-124468): no ctor DIRECTLY assigns this
            # property — but fluent value objects write state through
            # setters ($this->setField($field) in the ctor, the assign
            # living in the setter body).  Resolve prop -> setter(method,
            # param) -> ctor call-site arg and trace THAT with the ctor's
            # param_idx (52z-4 doctrine).  Only php ctors/php setters;
            # only fires when the traced arg is non-literal (source/param/
            # unknown) — a value object setter called with a literal keeps
            # the historic safe verdict (anchor-preserving).
            # Fix 145e: the 145d consumer sits at for-body level, but
            # _prop_name/_pn are bound at L1418-20 INSIDE the $this/self
            # branch — a member edge from a non-$this container ($arr[k],
            # $obj->prop with $obj a param) reached this guard with the
            # names unbound → UnboundLocalError killed the whole
            # build_function_summaries (ci line-2 warning; osticket anchor
            # first attempt +805 FP flood; AppDispatch repro row lost —
            # task 7255).  Scope the guard to $this/self containers so the
            # non-$this path falls through to the historic 52z-8 tail
            # unchanged (HEAD-identical semantics); _prop_name is then
            # always bound earlier in the same iteration.
            if (_unknown_origin is None
                    and isinstance(container_name, str)
                    and container_name in ("$this", "self")
                    and isinstance(_prop_name, str) and _prop_name):
                # Fix 145f: scope every hop to the READER's enclosing class
                # (the function whose summary is being built — carried on
                # eidx by build_function_summaries).  Cross-class
                # same-named props must not flip (osticket +15 anchor FP).
                _reader145f = eidx.get("__reader_fvid145f__")
                _rcls145f = (_php_fn_class_map(graph, eidx).get(_reader145f, "")
                             if _reader145f is not None else "")
                _setters_145d = (
                    [(_sv, _spn) for (_sv, _spn, _scls) in _php_prop_setter_idx(graph, eidx).get(
                        _pn if isinstance(_pn, str) else '', [])
                     if _rcls145f and _scls == _rcls145f]
                    if _rcls145f else [])
                if _setters_145d:
                    _sparams_145d = _PHP_SETTER_PARAM_CACHE.get(id(graph), {})
                    _ctors_145d = _CTOR_NODES_CACHE.get(id(graph)) or []
                    for _fv_idx in _ctors_145d:
                        if _vattr(graph.vs[_fv_idx], "language", "") != "php":
                            continue
                        if _php_fn_class_map(graph, eidx).get(_fv_idx, "") != _rcls145f:
                            continue
                        _ctor_pidx_145d = {}
                        for _cp, _ci in eidx["own_ch"].get(_fv_idx, []):
                            if (_vattr(graph.vs[_cp], "label", "") == NodeLabel.PARAMETER.value
                                    and _ci not in (None, "")):
                                _ctor_pidx_145d[_cp] = int(_ci)
                        for _sv, _spn in _setters_145d:
                            _sname = str(_vattr(graph.vs[_sv], "name", ""))
                            _ck145 = (id(graph), _fv_idx, _sname)
                            _calls145 = _CTOR_SETTER_CALL_CACHE.get(_ck145, _CTOR_MISS)
                            if _calls145 is _CTOR_MISS:
                                _calls145 = []
                                _stk145 = [_fv_idx]
                                _seen145 = set()
                                while _stk145:
                                    _x = _stk145.pop()
                                    if _x in _seen145:
                                        continue
                                    _seen145.add(_x)
                                    _xv = graph.vs[_x]
                                    _xl = _vattr(_xv, "label", "")
                                    if _xl == NodeLabel.FUNCTION.value and _x != _fv_idx:
                                        continue
                                    if _xl == NodeLabel.OPERATOR.value:
                                        for _t, _r, _ in eidx["ast_ch"].get(_x, []):
                                            if (_r or "") == "callee" and str(
                                                    _vattr(graph.vs[_t], "name", "")) == _sname:
                                                _calls145.append(_x)
                                                break
                                    for _t, _r, _ in eidx["ast_ch"].get(_x, []):
                                        if _t not in _seen145:
                                            _stk145.append(_t)
                                    for _t2 in eidx["out"].get("own", {}).get(_x, []):
                                        if _t2 not in _seen145:
                                            _stk145.append(_t2)
                                _CTOR_SETTER_CALL_CACHE[_ck145] = _calls145 or None
                                _calls145 = _calls145 or []
                            if not _calls145:
                                continue
                            _spos145 = _sparams_145d.get(_sv, {}).get(_spn, 0)
                            for _callv in _calls145:
                                for _t, _r, _ai in eidx["ast_ch"].get(_callv, []):
                                    if not (_r or "").startswith("arg"):
                                        continue
                                    if str(_ai if _ai not in (None, "") else 0) != str(_spos145):
                                        continue
                                    _sub145 = _trace_return_value(
                                        graph, _t, own_vids, _ctor_pidx_145d,
                                        visited | {start_vid}, eidx, depth + 1)
                                    if _sub145.get("origin_type") in ("source", "param"):
                                        return _sub145
                                    if _sub145.get("dep_params"):
                                        return _sub145
                                    if _sub145.get("origin_type") == "unknown" and _unknown_origin is None:
                                        _unknown_origin = _sub145
            # Fix 52z-8: a ctor assign WAS found but its RHS origin is
            # unknown — report unknown (unresolved ≠ safe).  Only when no
            # ctor assigns this property at all does the historic safe
            # fallback stands (plain fluent-API state object).
            if _unknown_origin is not None:
                return {"origin": vname, "origin_type": "unknown",
                        "dep_params": [], "has_unresolved_call": True}
            # Fix 158b (CVE-2026-124444): the read property IS a PHP 8
            # promoted ctor param (``$this->_constructor_order`` — the
            # promotion IS the assignment, so no ctor assign will ever be
            # found and the historic fallback below certified it 'safe').
            # That collapsed every getter returning such a member
            # (Criteria::GetOrder/GetWhere/GetJoin returning $this->_order,
            # assigned from the promoted $_constructor_order) into a safe
            # summary; the scanner's safe-cut then deleted the getter
            # calls' arg DFG edges and the Phreeze ORDER BY chain died in
            # every full-tree scan (mini detected natively — no stamp).
            # A promoted param is CALLER-FED (new Criteria($where, $order))
            # — its literal default only applies when the caller omits the
            # argument, which is not a safety proof.  Scope to the reader's
            # own class (145f doctrine), match by stripped param name.
            # 158b binding: _pn is pre-initialized to None at the identifier
            # branch top (145f init) and only set inside the $this/self
            # branch — _prop_name is NOT pre-initialized (145e precedent:
            # referencing it at for-body level raises UnboundLocalError on
            # non-$this containers).  Use _pn only.
            if (isinstance(container_name, str)
                    and container_name in ("$this", "self")
                    and isinstance(_pn, str) and _pn):
                _reader158b = eidx.get("__reader_fvid145f__")
                _rcls158b = (_php_fn_class_map(graph, eidx).get(_reader158b, "")
                             if _reader158b is not None else "")
                if _rcls158b:
                    _ctor_cache158b = _CTOR_NODES_CACHE.get(id(graph)) or []
                    for _fv158b in _ctor_cache158b:
                        if _vattr(graph.vs[_fv158b], "language", "") != "php":
                            continue
                        if _php_fn_class_map(graph, eidx).get(_fv158b, "") != _rcls158b:
                            continue
                        for _cp158b, _ci158b in eidx["own_ch"].get(_fv158b, []):
                            if (_vattr(graph.vs[_cp158b], "label", "") != NodeLabel.PARAMETER.value
                                    or not _vattr(graph.vs[_cp158b], "promoted", "")):
                                continue
                            _ppn158b = str(_vattr(graph.vs[_cp158b], "name", "")).lstrip("$").strip("'\"")
                            if _ppn158b == _pn:
                                return {"origin": vname, "origin_type": "unknown",
                                        "dep_params": [], "has_unresolved_call": False}
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            if container_taint == "source":
                return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
            # 容器直接是函数参数 → 返回值与该参数关联
            #   注意：normalizer 对同一变量名可能创建多个 vid，
            #   所以需要按 name 匹配而非 vid。
            container_name_raw = _vattr(container, "name", "")
            if isinstance(container_name_raw, str) and container_name_raw.startswith("$"):
                for pvid, pidx in param_idx.items():
                    pname = _vattr(graph.vs[pvid], "name", "")
                    if pname == container_name_raw:
                        return {"origin": vname, "origin_type": "param",
                                "dep_params": [pidx], "has_unresolved_call": False}
                        break
            # 容器可能是 passthrough 函数的返回值——递归追踪
            if container_vid in own_vids:
                sub = _trace_return_value(graph, container_vid, own_vids, param_idx, visited, eidx, depth + 1)
                if sub["origin_type"] in ("source", "param"):
                    return sub

    # ── 6. AST 赋值 fallback（DFG 缺失时，通过 assignment AST 追踪） ──
    #    当 identifier 无 DFG 且 member 追踪无果时，在 own subtree 内搜索
    #    同名 identifier 作为 assignment LHS 的节点，追踪 RHS 表达式。
    #    这弥补了 PHP normalizer 不生成 assignment DFG 边的缺陷。
    #    e.g. $markup = $this->elements($Elements); return $markup;
    if vlabel == NodeLabel.IDENTIFIER.value and depth < 3:
        ret_name = _vattr(v, "name", "")
        if ret_name:
            assign_found = _trace_assign_fallback(
                graph, ret_name, start_vid, own_vids, param_idx, visited, eidx, depth
            )
            # Fix 52z-2: same-name variables often have MULTIPLE assigns
            # ($path = []; $path[$i] = str_replace(...)) — the fallback
            # returns whichever assign iterates first (the array literal
            # → safe), discarding a param dependency the DFG pass already
            # established.  Mixed assigns are passthrough (46d rule):
            # an established param verdict beats a fallback safe.
            if all_dep_params:
                _fb_type = (assign_found or {}).get("origin_type", "")
                if _fb_type in ("param", "source"):
                    # Fix 117j (CVE-2026-110279): the DFG pass and the AST
                    # fallback are two PARTIAL views of the same
                    # function's defs — DFG sees the subscript write-back
                    # value (Fix 117a: sanitized_value → container def),
                    # the fallback sees the literal-init assign.  Returning
                    # the fallback's verdict alone discards the DFG
                    # deps (pt=[1] instead of [0,1] — the whole
                    # request_headers leg vanished).  Source dominates;
                    # param verdicts UNION their dep sets.
                    if _fb_type == "source":
                        return assign_found
                    _af = assign_found or {}
                    _merged = dict(_af)
                    _merged["dep_params"] = list(dict.fromkeys(
                        list(_af.get("dep_params", []))
                        + list(all_dep_params)))
                    _merged["has_unresolved_call"] = bool(
                        _af.get("has_unresolved_call")) or any_unresolved
                    return _merged
                return {
                    "origin": vname, "origin_type": "param",
                    "dep_params": list(dict.fromkeys(all_dep_params)),
                    "has_unresolved_call": any_unresolved,
                }
            if assign_found and assign_found["origin_type"] != "unknown":
                return assign_found
            if assign_found and assign_found.get("dep_params"):
                return assign_found

    # Filter out reference parameters from dep_params
    # (they are write-back semantics, not read-through)
    ref_param_indices = set()
    for pvid, pidx in param_idx.items():
        if _vattr(graph.vs[pvid], "is_reference", ""):
            ref_param_indices.add(pidx)
    if ref_param_indices:
        all_dep_params = [p for p in all_dep_params if p not in ref_param_indices]

    if all_dep_params:
        unique = list(dict.fromkeys(all_dep_params))
        return {
            "origin": vname,
            "origin_type": "param",
            "dep_params": unique,
            "has_unresolved_call": any_unresolved,
        }

    # 4c. DFG 链全部追溯到 safe/literal 但无 dep_params → safe
    #     e.g. return $compiled; // $compiled = $a . $b . ' ' （DFG 链到 string literal）
    if dfg_has_safe_source and not any_unresolved:
        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # Fix 46d concat epilogue: source operand anywhere in a concat wins;
    # safe-only concat stays safe.
    if _is_concat:
        if _first_pass_source is not None:
            return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": any_unresolved}
        if all_dep_params:
            return {"origin": vname, "origin_type": "param", "dep_params": list(dict.fromkeys(all_dep_params)), "has_unresolved_call": any_unresolved}
        if _first_pass_safe is not None:
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    return {"origin": vname, "origin_type": "unknown", "dep_params": [], "has_unresolved_call": any_unresolved}


def _trace_assign_fallback(
    graph: ig.Graph,
    target_name: str,
    origin_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    eidx: dict,
    depth: int,
) -> dict | None:
    """在 own subtree 内搜索 assignment LHS 同名 identifier，追踪 RHS 表达式。

    用于弥补 PHP/JS 等语言 normalizer 不生成 assignment DFG 边的缺陷。
    e.g. $x = call($param); return $x; → 追踪 call 的返回值。

    Returns: _trace_return_value 的结果 dict，或 None（未找到匹配赋值）。
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    new_visited = visited | {origin_vid}
    for n in own_vids:
        if _vattr(graph.vs[n], "label") != NodeLabel.OPERATOR.value:
            continue
        if _vattr(graph.vs[n], "type") not in ("assign", "aug_assign"):
            continue
        # 检查 LHS —— 直接 identifier 或 ArrayOffset（映射为 identifier/property）
        for lhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "left"]:
            lhs = graph.vs[lhs_vid]
            lhs_label = _vattr(lhs, "label", "")
            lhs_name = _vattr(lhs, "name", "")

            matched_lhs = False
            if lhs_label == NodeLabel.IDENTIFIER.value and lhs_name == target_name:
                matched_lhs = True
            elif lhs_label == NodeLabel.IDENTIFIER.value and _vattr(lhs, "type") == "property":
                # ArrayOffset 返回 identifier/property
                # 检查 member 边是否来自目标变量
                # $arr[$key] = $val → member($arr → $key)，LHS 是 $key (property)
                # 搜索 member 边的 source（container = $arr）
                for container_vid in eidx["in"].get("member", {}).get(lhs_vid, []):
                    container = graph.vs[container_vid]
                    if (_vattr(container, "label") == NodeLabel.IDENTIFIER.value and
                            _vattr(container, "name", "") == target_name):
                        matched_lhs = True
                        break

            if matched_lhs:
                # 找到匹配的赋值，追踪 RHS
                for rhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "right"]:
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, eidx, depth + 1)
                    return sub
                # PHP normalizer 用 "lhs"/"rhs"，兼容
                for rhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "rhs"]:
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, eidx, depth + 1)
                    return sub
                return None  # RHS 不存在
        # PHP normalizer 兼容：lhs role
        for lhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "lhs"]:
            lhs = graph.vs[lhs_vid]
            lhs_label = _vattr(lhs, "label", "")
            lhs_name = _vattr(lhs, "name", "")

            matched_lhs = False
            if lhs_label == NodeLabel.IDENTIFIER.value and lhs_name == target_name:
                matched_lhs = True
            elif lhs_label == NodeLabel.IDENTIFIER.value and _vattr(lhs, "type") == "property":
                for container_vid in eidx["in"].get("member", {}).get(lhs_vid, []):
                    container = graph.vs[container_vid]
                    if (_vattr(container, "label") == NodeLabel.IDENTIFIER.value and
                            _vattr(container, "name", "") == target_name):
                        matched_lhs = True
                        break

            if matched_lhs:
                for rhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "rhs"]:
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, eidx, depth + 1)
                    return sub
                return None
    return None  # 未找到同名赋值


# ---------------------------------------------------------------------------
# Internal: short-name index (Fix 16 perf)
# ---------------------------------------------------------------------------

_short_name_index_cache: dict[int, tuple[int, dict]] = {}  # id(graph) -> (vcount, index)


def _get_short_name_index(graph: "ig.Graph") -> dict[str, list[int]]:
    """Build (once per graph) a short-name → [function vids] index.

    Keyed on the last segment of the function name, so a bare-name stub
    node ("keep_in_string") can find qualified definition nodes
    ("pts_strings.keep_in_string" / "pts_strings::keep_in_string").
    igraph Graph is unhashable, so we key on id(graph) and invalidate
    when the vertex count changes.
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    key = id(graph)
    entry = _short_name_index_cache.get(key)
    if entry is not None and entry[0] == graph.vcount():
        return entry[1]

    idx: dict[str, list[int]] = {}
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.FUNCTION.value:
            continue
        n = _vattr(v, "name", "")
        if not n:
            continue
        short = n
        for sep in ("::", "."):
            if sep in short:
                short = short.rsplit(sep, 1)[-1]
        short = short.lstrip("\\")
        if short:
            idx.setdefault(short, []).append(v.index)

    _short_name_index_cache[key] = (graph.vcount(), idx)
    return idx


# ── Fix 142i (CVE-2026-104126): python callee-identity caches ──────────
_py_builtin_names_cache = None


def _python_builtin_names():
    """Bare (unqualified) builtin names carrying knowledge entries."""
    global _py_builtin_names_cache
    if _py_builtin_names_cache is None:
        try:
            from core.core_engine.python import builtin_knowledge as _bk
            _py_builtin_names_cache = frozenset(
                k for k in _bk.KNOWLEDGE if "." not in k)
        except Exception:
            _py_builtin_names_cache = frozenset()
    return _py_builtin_names_cache


_class_ctx_cache: dict[int, tuple[int, dict, dict]] = {}  # id(graph) -> (vcount, enc, own)


def _get_class_ctx_caches(graph):
    """Per-graph memo dicts: vid -> enclosing-class vid / def-owner-class vid."""
    key = id(graph)
    entry = _class_ctx_cache.get(key)
    if entry is not None and entry[0] == graph.vcount():
        return entry[1], entry[2]
    if len(_class_ctx_cache) > 8:
        for k in [k for k, v in _class_ctx_cache.items() if v[0] != graph.vcount()][:4]:
            _class_ctx_cache.pop(k, None)
    enc: dict[int, int] = {}
    own: dict[int, int] = {}
    _class_ctx_cache[key] = (graph.vcount(), enc, own)
    return enc, own


def _enclosing_class_fs(graph, vid, eidx, cache):
    """Nearest class node enclosing vid via own (fallback ast) parents."""
    from utils.igraph_compat import _vattr
    if vid in cache:
        return cache[vid] or None
    hop = vid
    found = None
    for _ in range(24):
        pars = (eidx["in"].get("own", {}).get(hop)
                or eidx["in"].get("ast", {}).get(hop))
        if not pars:
            break
        hop = pars[0]
        if _vattr(graph.vs[hop], "label", "") == "class":
            found = hop
            break
    cache[vid] = found or -1
    return found


def _owner_class_fs(graph, fvid, eidx, cache):
    """Class node owning function fvid (method, or one nesting level)."""
    from utils.igraph_compat import _vattr
    if fvid in cache:
        return cache[fvid] or None
    found = None
    for p in eidx["in"].get("own", {}).get(fvid, []):
        pl = _vattr(graph.vs[p], "label", "")
        if pl == "class":
            found = p
            break
        if pl == "function":
            for p2 in eidx["in"].get("own", {}).get(p, []):
                if _vattr(graph.vs[p2], "label", "") == "class":
                    found = p2
                    break
            break
    cache[fvid] = found or -1
    return found


# Fix 52z-9 (CVE-2026-110185): ORM query-chain terminator methods.  A call
# like ``FlowNode::where('flow_id', $id)->all()`` / ``->get()`` / ``->first()``
# terminates a static ORM query chain — its return value is DB row data, i.e.
# STORED user input (second-order/stored XSS/LFI/SQLi sink feed).  The
# historical KNOWLEDGE entries (added for a Laravel baseline) mark these
# safe=True ("DB records, not user input directly"), which silently kills
# every stored-taint chain (bit-pi: FlowController::store writes
# $request->validated() into FlowNode rows; GlobalNodes::fetchNodeData reads
# them back through where()->all() and feeds ImageHelperTool get_contents).
# Discriminator: ONLY treat these as DB reads when the call's receiver chain
# comes from a ``where``/``select`` method call (static ORM chain shape,
# Model::where(...)->get()).  A bare ``$collection->all()`` / ``$http->get()``
# keeps its old verdict — no regression for accessor-style calls (osTicket
# has 714 bare ->get() calls that are NOT ORM reads).
_ORM_QUERY_CHAIN_STARTS = frozenset({"where", "select"})
_ORM_QUERY_TERMINATORS = frozenset({
    "all", "get", "first", "firstOrFail", "find", "findMany",
    "findOrFail", "pluck", "whereKey", "value", "lists",
})


def _is_orm_query_chain_terminator(graph, call_vid: int, eidx: dict) -> bool:
    """True when call_vid ends a static ORM query chain
    (X::where(...)->terminator()).  The chain shape is detected on the graph:
    the terminator's callee identifier's incoming member edge originates from
    a where/select CALL operator (not a plain identifier receiver)."""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    short = _vattr(graph.vs[call_vid], "name", "")
    if not isinstance(short, str) or not short:
        return False
    for sep in ("::", "."):
        if sep in short:
            short = short.rsplit(sep, 1)[-1]
    if short not in _ORM_QUERY_TERMINATORS:
        return False
    # callee identifier (ast/callee) → member in-edge source = chain upstream
    for callee_vid, role, _ in eidx["ast_ch"].get(call_vid, []):
        if role != "callee":
            continue
        for upstream_vid in eidx["in"].get("member", {}).get(callee_vid, []):
            uv = graph.vs[upstream_vid]
            if (_vattr(uv, "label", "") == NodeLabel.OPERATOR.value
                    and _vattr(uv, "type", "") in ("method_call", "static_call")
                    and str(_vattr(uv, "name", "")).rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                    in _ORM_QUERY_CHAIN_STARTS):
                return True
    return False


def _bridge_source_bfs(
    graph: ig.Graph,
    call_vid: int,
    eidx: dict,
    visited: set[int],
    max_depth: int = 12,
    max_nodes: int = 512,
) -> bool:
    """Fix 125b + Fix 127 (CVE-2026-111217): call op 的 dfg 入边上存在 source 证据吗？

    沿 call op 的 dfg 入边做有界祖先 BFS（Fix 72c 同型）。专治跨函数通道
    （Fix 123 store→load 桥、跨文件 124c 返回值绑定）：这些边落在调用点上、
    绕过被调形参，callee 摘要对它们结构性失明。visited 传入以避免与主递归
    成环。按**代数**限界（max_depth 层祖先）而非按节点数——数组项写回链
    每代扇出 N 倍，按节点计 hop 会在宽扇出处耗尽预算而错过 3 代外的
    source；另有总展开节点上限防稠密图发散。

    Fix 127 (anchor 回归 osticket +571)：原版接受**任何** taint_type=source
    祖先。Fix 124a/c 打通全语料返回值绑定后，两条不健全通道立即爆炸：
      1. param 反向回走——dfg 实参绑定边横穿调用图，$_POST 在**某一个**
         调用点传给 db_query/Format::htmlchars，就使该函数**所有**调用点
         的返回值被判 source（跨调用点合并；Fix 84b 当年正是为 osticket
         wrapper 这类 FP 立的 param 边界判例）。
      2. 被溯源调用点自身的实参边——消毒器 callee（db_input/htmlchars）
         的 safe 摘要被它消毒的那份污点证据压过（125b 注释原文「source
         证据压过一切摘要结论」在此语义下是错的）。
    规则：直连 source 节点命中**仅在 store_mode 下计数**——即走查已跨越
    Fix 123 桥的持久化存储写侧（cfg_store=1 标记节点；存储值的溯源包含
    param 回走，这是健全的）。'parameter' 节点是硬边界，除非 store_mode。
    call→source-summary 子句不受限：callee 摘要为 'source' 意味着其返回值
    按定义在所有调用点带污点（存储配置读取器家族的合法放大器）。
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    def _parents(vid: int) -> list[int]:
        out = list(eidx["in"].get("dfg", {}).get(vid) or [])
        # Fix 125d (CVE-2026-111217): member-read nodes derive their value
        # from the *container*, but that edge is labeled 'member', not
        # 'dfg' — a dfg-only walk dies one hop short of the source.
        # 容器污点蕴含成员污点（与 analyzer 侧 _is_source_via_member_chain
        # 同义）；member 边不跨语句边界（98a 判语），有界 BFS 内跟随是
        # 污点健全的。
        out += list(eidx["in"].get("member", {}).get(vid) or [])
        return out

    call_types = ("call", "method_call", "static_call")
    seen: set[int] = set()
    # Fix 127: per-node best store_mode；升级到 store 模式时允许重展开。
    best_mode: dict[int, bool] = {}
    frontier: list[tuple[int, bool]] = [
        (s, False) for s in (eidx["in"].get("dfg", {}).get(call_vid) or [])
        if s not in visited
    ]
    for _gen in range(max_depth):
        if not frontier:
            break
        nxt: list[tuple[int, bool]] = []
        for cur, mode in frontier:
            if cur in visited:
                continue
            prev = best_mode.get(cur, False)
            if cur in best_mode and not (mode and not prev):
                # 已以相同或更高模式处理过
                continue
            mode = mode or prev
            best_mode[cur] = mode
            seen.add(cur)
            if len(seen) > max_nodes:
                return False
            node = graph.vs[cur]
            if not mode and _vattr(node, "cfg_store", ""):
                # Fix 127: 跨越持久化存储桥的写侧节点 → 进入 store 模式
                mode = True
                best_mode[cur] = True
            if mode and _vattr(node, "taint_type", "") == "source":
                return True
            if (_vattr(node, "label", "") == NodeLabel.OPERATOR.value
                    and _vattr(node, "type", "") in call_types):
                for uv in eidx["out"].get("use", {}).get(cur, []):
                    if _vattr(graph.vs[uv], "func_summary_type", "") == "source":
                        return True
            # Fix 127 / 84b: 入口参数终止本路径——污点来自调用方时，安全性
            # 由各调用方判定；除非走查携带存储写侧溯源（store_mode）。
            if _vattr(node, "label", "") == "parameter" and not mode:
                continue
            nxt.extend((s, mode) for s in _parents(cur) if s not in visited)
        # dedupe preserving order
        frontier = list(dict.fromkeys(nxt))
    return False


def _trace_call_to_function(
    graph: ig.Graph,
    call_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    eidx: dict,
    depth: int,
) -> dict | None:
    """追踪 call → use → function，读取目标函数的摘要。

    Fix 16: use-edge targets may include bare-name stub nodes (created by
    the normalizer for cross-file static calls like
    pts_strings::keep_in_string()) that never receive a summary, while the
    real definition node (fullname pts_strings.keep_in_string) holds one.
    Therefore:
      1. Iterate ALL use targets; prefer one that carries a summary/taint.
      2. If none has one, do a same-short-name lookup across the graph
         (mirrors graph_analyzer Rule 3a2's same-name safe lookup).
      3. If still nothing, consult builtin_knowledge — builtin functions
         (strtolower, substr, ...) never get function-def summaries, so
         deferring on them loops _MAX_ITERATIONS times and leaves the
         CALLER function unannotated entirely (silent FP factory).
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    call_vname = _vattr(graph.vs[call_vid], "name", "")

    # Fix 52z-9: ORM query-chain terminator — where/select chain ends in
    # all/get/first/... whose KNOWLEDGE entry says safe.  That verdict is a
    # Laravel-baseline shortcut ("DB records ≠ user input") that kills stored
    # taint.  When the graph shape proves a static ORM chain, the return is
    # DB row data = stored user input → source (second-order taint).
    if _is_orm_query_chain_terminator(graph, call_vid, eidx):
        return {"origin": call_vname, "origin_type": "source",
                "dep_params": [], "has_unresolved_call": False}

    targets = [t for t in eidx["out"].get("use", {}).get(call_vid, [])
               if _vattr(graph.vs[t], "label") == NodeLabel.FUNCTION.value]

    # ── Fix 144c (CVE-2026-124463): framework repair registry (L1) —
    # channel consistency between the analyzer's per-svid repair vetoes
    # and summary space.  scanner.py folds each detected framework's
    # FILTER_FUNCTIONS into the L1 registry BEFORE summaries are built
    # (scanner.py L1 load at ~377 precedes build_function_summaries at
    # ~714), but this tracer only consulted the svid-blind engine
    # _REPAIR_FUNCTIONS (Pass 2 fallback) — a framework-registered
    # sanitizer whose body reads a second-order source got its def
    # summary stamped 'source' and poisoned every caller.  OpenEMR
    # escape_table_name → QueryUtils::escapeTableName reads the SHOW
    # TABLES whitelist via fetchArrayFromResultSet (Fix 144a source)
    # and returns a whitelist member through escape_identifier (also a
    # registered repair): 46 SQLi FPs across the CAMOS corpus
    # (task 7202, every reason "return of source-summary function
    # 'escapeTableName'").  A function the framework itself registers
    # as a repair can never be a taint source (rule self-lock
    # doctrine); its call origin is 'safe'.  Summary space is
    # svid-blind — registered-for-ANY-svid wins, the same tradeoff the
    # engine-set fallback below already makes.  Name forms: raw,
    # '::'→'.' qualified, and bare tail of the SAME callee/target-def
    # names (name-form resolution of one function, not bare-name
    # def fanout — the 142i hijack concern does not apply).
    try:
        from core.filter_functions import _registry as _l1_reg_144c
        _l1_lang_144c = (_vattr(graph.vs[call_vid], "language", "")
                         or (targets and _vattr(graph.vs[targets[0]], "language", "")) or "")
        if _l1_reg_144c is not None and _l1_lang_144c:
            _names_144c = {call_vname,
                           _vattr(graph.vs[call_vid], "callee", "") or ""}
            _names_144c.update(_vattr(graph.vs[t], "name", "") for t in targets)
            _forms_144c = set()
            for _n in _names_144c:
                if not _n:
                    continue
                _forms_144c.add(_n)
                _d = _n.replace("::", ".")
                _forms_144c.add(_d)
                _forms_144c.add(_d.rsplit("\\", 1)[-1])
                if "." in _d:
                    _forms_144c.add(_d.rsplit(".", 1)[-1])
            for _store_144c in (_l1_reg_144c._rule,
                                _l1_reg_144c._summary,
                                _l1_reg_144c._builtin):
                _lang_store = _store_144c.get(_l1_lang_144c)
                if not _lang_store:
                    continue
                if any(_f in _lang_store for _f in _forms_144c):
                    return {"origin": call_vname, "origin_type": "safe",
                            "dep_params": [], "has_unresolved_call": False}
    except Exception:
        pass

    # ── Fix 142i (CVE-2026-104126 JumpServer): identity-aware candidate
    # ordering for python calls.  Bare-name use-edge fanout binds a call
    # to EVERY same-named def corpus-wide; legacy Pass 1 read the FIRST
    # target carrying a summary, so an unrelated foreign def (even a user
    # def named ``list``/``filter``) decided the flow, and the aggregated
    # literal/safe return flows stamped the genuine callee ``safe``
    # (JMSInventory.generate) — the summary-tracer twin of the
    # analyzer-side hijack fixed by 142g/142h.  Ordering, python-scoped:
    #   same-class def > same-file def > builtin knowledge > foreign defs;
    # and when several genuine candidates remain (polymorphic fanout), a
    # veto-grade 'safe'/'literal' needs EVERY candidate safe/literal
    # (Fix 101 asymmetry) — mixed/unannotated falls through unresolved.
    _py142i = bool(targets) and _vattr(graph.vs[call_vid], "language", "") == "python"
    _ordered_142i = targets
    _skip_pass2_142i = False
    if _py142i:
        _enc_cache, _own_cache = _get_class_ctx_caches(graph)
        _call_cls = _enclosing_class_fs(graph, call_vid, eidx, _enc_cache)
        _call_file = _vattr(graph.vs[call_vid], "file_path", "") or ""
        _same_cls, _same_file = [], []
        for _t in targets:
            if (_call_cls is not None
                    and _owner_class_fs(graph, _t, eidx, _own_cache) == _call_cls):
                _same_cls.append(_t)
            elif _call_file and (_vattr(graph.vs[_t], "file_path", "") or "") == _call_file:
                _same_file.append(_t)
        if _same_cls or _same_file:
            _ordered_142i = _same_cls or _same_file
            _skip_pass2_142i = True
        elif ((_vattr(graph.vs[call_vid], "callee", "") or call_vname or "")
                .rsplit(".", 1)[-1] in _python_builtin_names()):
            _ordered_142i = []
            _skip_pass2_142i = True

    # ── Pass 1: a use target that already has a summary / taint ──
    _veto_pool_142i = []
    for target_vid in _ordered_142i:
        target = graph.vs[target_vid]
        target_summary = _vattr(target, "func_summary_type", "")
        target_pt = _vattr(target, "func_summary_pt", [])

        if target_summary == "passthrough" and target_pt:
            return _trace_passthrough_call(graph, call_vid, target_pt, own_vids, param_idx, visited, eidx, depth)
        if target_summary == "source":
            return {"origin": call_vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
        if target_summary == "safe":
            if _py142i and len(_ordered_142i) > 1:
                _veto_pool_142i.append("safe")
                continue
            return {"origin": call_vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        if target_summary in ("literal",):
            if _py142i and len(_ordered_142i) > 1:
                _veto_pool_142i.append("literal")
                continue
            return {"origin": call_vname, "origin_type": "literal", "dep_params": [], "has_unresolved_call": False}

        # 目标无 func_summary_type → fallback 检查 enrich_taint 标注的 taint_type
        # （内置 source/safe 函数由 source_registry 通过 enrich_taint 标注）
        target_taint = _vattr(target, "taint_type", "")
        if target_taint in ("source", "safe"):
            if _py142i and len(_ordered_142i) > 1 and target_taint == "safe":
                _veto_pool_142i.append("safe")
                continue
            return {"origin": call_vname, "origin_type": target_taint, "dep_params": [], "has_unresolved_call": False}
        if target_taint == "passthrough" and _vattr(target, "taint_passthrough", []):
            return _trace_passthrough_call(
                graph, call_vid, list(_vattr(target, "taint_passthrough", [])),
                own_vids, param_idx, visited, eidx, depth)
        if _py142i and len(_ordered_142i) > 1:
            _veto_pool_142i.append(None)
    if _py142i and len(_ordered_142i) > 1 and _veto_pool_142i \
            and all(_p in ("safe", "literal") for _p in _veto_pool_142i):
        return {"origin": call_vname, "origin_type": "safe" if "safe" in _veto_pool_142i else "literal",
                "dep_params": [], "has_unresolved_call": False}

    # ── Pass 2: short-name graph lookup ──
    # A stub use target has a bare name; the definition node's name is
    # qualified (Class.method / Class::method).  Match on the last segment.
    # Uses a module-level cached short-name → vids index (built once per
    # graph via a WeakKeyDictionary) instead of a full graph scan per call.
    def _short(n: str) -> str:
        if not n:
            return ""
        for sep in ("::", "."):
            if sep in n:
                n = n.rsplit(sep, 1)[-1]
        return n.lstrip("\\")

    short_index = _get_short_name_index(graph)

    # Fix 142i: an identity-restricted (same-class/same-file) or
    # builtin-resolved python call must not consult OTHER same-name defs —
    # that lookup is a bare-name hijack by construction here.
    if targets and not _skip_pass2_142i:
        stub_names = {_short(_vattr(graph.vs[t], "name", "")) for t in targets}
        stub_names.discard("")
        if stub_names:
            best = ("", [])
            for sname in stub_names:
                for fvid in short_index.get(sname, ()):
                    if fvid in targets:
                        continue
                    fst = _vattr(graph.vs[fvid], "func_summary_type", "")
                    if not fst:
                        continue
                    if fst in ("safe", "source") and best[0] != "safe":
                        best = (fst, [])
                        break
                    if fst == "passthrough" and best[0] != "passthrough":
                        best = (fst, list(_vattr(graph.vs[fvid], "func_summary_pt", []) or []))
                if best[0] in ("safe", "source"):
                    break
            if best[0] == "safe":
                return {"origin": call_vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            if best[0] == "source":
                return {"origin": call_vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
            if best[0] == "passthrough" and best[1]:
                return _trace_passthrough_call(graph, call_vid, best[1], own_vids, param_idx, visited, eidx, depth)

            # fallback: GraphAnalyzer._REPAIR_FUNCTIONS whitelist (pre-existing
            # behaviour — repair functions not in builtin_knowledge still count
            # as safe origins, not unresolved).
            from core.graph.graph_analyzer import _REPAIR_FUNCTIONS
            if stub_names & _REPAIR_FUNCTIONS:
                return {"origin": call_vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── Pass 3: builtin_knowledge fallback ──
    # Builtin functions have no function-def node with a summary and never
    # will.  Without this, a call like strtolower($input) is reported as
    # has_unresolved_call=True forever, deferring the caller's summary
    # until _MAX_ITERATIONS runs out — the caller stays unannotated and
    # every sanitized return through it becomes a false positive.
    if targets:
        # Fix 117h-1 (CVE-2026-110279): language must come from the CALL
        # node first — stub use-targets (bare 'get'/'copy'/… function
        # nodes) carry an EMPTY language, and the old `or "php"` fallback
        # made python graphs consult the PHP knowledge base, whose
        # generic-getter entry ('get' => safe) silently killed every
        # ``tainted_dict.get(k)`` value chain (cross-language
        # external-stub poisoning, same family as the ljavalang Fix 61
        # precedent).  Verified shape: call ops carry language on both
        # php and python graphs; stubs never do.
        _lang = (_vattr(graph.vs[call_vid], "language", "")
                 or _vattr(graph.vs[targets[0]], "language", ""))
        if not _lang:
            _fp = (_vattr(graph.vs[call_vid], "file_path", "")
                   or _vattr(graph.vs[targets[0]], "file_path", "") or "")
            _ext = _fp.rsplit(".", 1)[-1].lower() if "." in _fp else ""
            _lang = {"py": "python", "js": "javascript", "mjs": "javascript",
                     "jsx": "javascript", "ts": "typescript",
                     "tsx": "typescript", "java": "java"}.get(_ext, "php")
        lang = _lang
        try:
            import importlib
            mod = importlib.import_module(f"core.core_engine.{lang}.builtin_knowledge")
            knowledge_get = getattr(mod, "lookup", None)
        except (ImportError, AttributeError):
            knowledge_get = None

        # Fix 117h-2 (CVE-2026-110279): python method-call RECEIVER flow.
        # In python graphs the receiver of ``recv.method(args)`` reaches
        # the call op via a dfg in-edge (never an ast child).  Builtin
        # safe/generic-getter verdicts (and 'unknown' fallbacks) describe
        # ARGUMENT independence — they say nothing about the receiver, so
        # ``tainted_container.get(k)`` must still carry the container's
        # taint into the result (container element read, the call-op
        # analog of the Fix 117e subscript-read flow).  Trace the
        # receivers first; a source/param receiver wins over both the
        # generic-safe verdict and the unresolved fallback.  Guarded to
        # python: the php method-call receiver shape is name-embedded /
        # member-edge (Fix 44b model) and is handled there.
        _recv_flow = None
        if (lang == "python"
                and _vattr(graph.vs[call_vid], "type", "") == "method_call"):
            _recv_flow = _trace_method_receivers(
                graph, call_vid, own_vids, param_idx, visited, eidx, depth)

        if knowledge_get is not None:
            for t in targets:
                tname = _vattr(graph.vs[t], "name", "")
                entry = knowledge_get(tname) or knowledge_get(_short(tname))
                if not entry:
                    continue
                if entry.get("safe"):
                    if _recv_flow and _recv_flow.get("origin_type") in ("source", "param"):
                        return _recv_flow
                    return {"origin": call_vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
                pt = [i for i in entry.get("passthrough", []) if isinstance(i, int)]
                if pt:
                    return _trace_passthrough_call(graph, call_vid, pt, own_vids, param_idx, visited, eidx, depth)
                # Known but no passthrough and not safe → return value does
                # not depend on any argument in a tracked way.
                if _recv_flow and _recv_flow.get("origin_type") in ("source", "param"):
                    return _recv_flow
                return {"origin": call_vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    if targets:
        if _recv_flow and _recv_flow.get("origin_type") in ("source", "param"):
            return _recv_flow
        # 目标完全未知 → 返回 None，让调用方继续 DFG 追踪
        return {"origin": "", "origin_type": "unknown", "dep_params": [], "has_unresolved_call": True}

    return None  # 无 use 边，让调用方继续


def _trace_method_receivers(
    graph: ig.Graph,
    call_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    eidx: dict,
    depth: int,
) -> dict | None:
    """Fix 117h-2 (CVE-2026-110279): trace a python method-call's receivers.

    The receiver(s) of ``recv.method(args)`` are the call op's dfg
    in-edge sources that are NOT ast children of the call (explicit args
    and the callee identifier are ast children; the receiver reaches the
    op only via dfg).  Returns the strongest receiver verdict:
    source > param (dep_params aggregated) > None (literal/safe/absent
    receivers leave the entry-based verdict untouched).
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    _ast_child_vids = {t for t, _role, _ in eidx["ast_ch"].get(call_vid, [])}
    dep_params: list[int] = []
    any_unresolved = False
    best_param: dict | None = None
    for src in (eidx["in"].get("dfg", {}).get(call_vid) or []):
        if src in _ast_child_vids:
            continue  # explicit argument / callee — not the receiver
        if src == call_vid:
            continue
        src_label = _vattr(graph.vs[src], "label", "")
        if src_label not in (NodeLabel.IDENTIFIER.value, NodeLabel.PARAMETER.value):
            continue
        sub = _trace_return_value(graph, src, own_vids, param_idx, visited, eidx, depth + 1)
        if not sub:
            continue
        if sub.get("origin_type") == "source":
            return sub
        if sub.get("origin_type") == "param":
            best_param = sub
            dep_params.extend(sub.get("dep_params", []))
            any_unresolved = any_unresolved or bool(sub.get("has_unresolved_call"))
        elif sub.get("origin_type") == "unknown":
            any_unresolved = any_unresolved or bool(sub.get("has_unresolved_call", True))
    if best_param is not None:
        merged = dict(best_param)
        merged["dep_params"] = sorted(set(dep_params))
        merged["has_unresolved_call"] = any_unresolved
        return merged
    return None


def _trace_passthrough_call(
    graph: ig.Graph,
    call_vid: int,
    pt_indices: list,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    eidx: dict,
    depth: int,
) -> dict:
    """追踪 passthrough call 的参数——将 passthrough 索引映射到 call 的 ast[arg] 实参，递归追踪。"""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    all_dep_params: list[int] = []
    any_unresolved = False
    arg_counter = 0

    # Fix 44b: Java/JS method_call receiver model.  For String methods in
    # KNOWLEDGE (replace/trim/substring/...) passthrough index 0 refers to
    # the RECEIVER (this), but the method_call's ast children only carry
    # callee + explicit args — arg0 is the first *explicit* argument, not
    # the receiver.  When passthrough includes 0 and the call name is
    # 'recv.method', resolve the receiver's same-name use-site in own_vids
    # and trace it first (CVE-2026-38158: sqlForUse.replace(substr, result)
    # traced substr→substring→safe while the receiver held the sql param).
    _call_name = _vattr(graph.vs[call_vid], "name", "") or ""
    _receiver_traced = False
    # Fix 93c: 'all' = 无界元数透传（str.format）——receiver 与全部实参
    # 都流入返回值，不做索引过滤。
    _pt_all = "all" in pt_indices
    if (0 in pt_indices or _pt_all) and isinstance(_call_name, str) and "." in _call_name:
        _recv_name = _call_name.split(".", 1)[0]
        # skip literal receivers (e.g. "foo".replace(...)) — chr(34)/chr(39)
        # avoid nested-quote escaping entirely
        if _recv_name and _recv_name[0] not in (chr(34), chr(39)):
            _recv_vids = [
                ov for ov in own_vids
                if ov != call_vid
                and _vattr(graph.vs[ov], "label", "") == NodeLabel.IDENTIFIER.value
                and _vattr(graph.vs[ov], "name", "") == _recv_name
            ]
            for _rv in _recv_vids:
                _sub = _trace_return_value(
                    graph, _rv, own_vids, param_idx, visited, eidx, depth + 1
                )
                if _sub["origin_type"] in ("source", "param"):
                    return _sub
                if _sub["origin_type"] == "safe":
                    # receiver resolves safe (e.g. literal) — fall through
                    # to explicit args without treating it as a verdict.
                    _receiver_traced = True
                    break
            if _recv_vids and not _receiver_traced:
                # receiver traced to unknown/literal — non-verdict; fall
                # through to explicit-arg tracing below.
                pass

    for tgt, role, arg_idx in eidx["ast_ch"].get(call_vid, []):
        if role != "arg":
            continue
        actual_idx = int(arg_idx) if arg_idx else arg_counter
        if actual_idx in pt_indices or _pt_all:
            arg_vid = tgt
            # 实参为字面量 const（如 str_repeat('<br>', $n)）→ 直接标 safe
            # Fix 93c: 'all' 模式下常量实参只是并行流之一，不是安全判据
            # （'x {}'.format('c', tainted) 的 arg0 是常量但 arg1 仍污点）。
            if _vattr(graph.vs[arg_vid], "label") == NodeLabel.CONST.value:
                if _pt_all:
                    continue
                # Fix 117k (CVE-2026-110279): a literal pt-arg cannot
                # ERASE param deps already proven from earlier pt-args.
                # ``get_passthrough_headers(request_headers, {"CT": "json"})``
                # (callee pt=[0,1]): arg0 → param[0], arg1 → const dict —
                # the old immediate `return safe` discarded the dep and
                # collapsed invoke_tool to 'safe' (Fix 93c fixed this for
                # 'all' mode only).  Continue scanning; the no-deps fast
                # path (every pt-arg const) still returns safe below.
                if all_dep_params or any_unresolved:
                    continue
                vname = _vattr(graph.vs[call_vid], "name", "")
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            sub = _trace_return_value(graph, arg_vid, own_vids, param_idx, visited, eidx, depth + 1)
            if sub["origin_type"] == "source":
                return sub
            if sub["origin_type"] == "safe":
                # Fix 93c: 'all' 模式下单个实参 safe 只是并行流之一，
                # 不能对整个调用下 safe 判定——继续看其余实参。
                # Fix 117l (CVE-2026-110279): indexed 模式同理——一个
                # safe pt-arg 不能抹掉更早 pt-arg 已证实的 param 依赖
                # (arg0=param、arg1=literal-container 时旧逻辑直接
                # return safe)。仅在尚无任何依赖时保留快速路径。
                if _pt_all:
                    continue
                if all_dep_params or any_unresolved:
                    continue
                return sub
            # str_replace / str_ireplace with literal search/replace args
            # acts as a sanitizer on the subject (e.g. adminer's h() =
            # str_replace(array('&','<','"',"'"), array('&amp;',...), $s)).
            # When ALL non-passthrough args are constants, the function
            # performs a fixed mapping → safe, not passthrough.
            if sub["origin_type"] == "param":
                callee = _vattr(graph.vs[call_vid], "callee", "") or ""
                if callee in ("str_replace", "str_ireplace"):
                    non_pt_args_all_const = True
                    for tgt2, role2, arg_idx2 in eidx["ast_ch"].get(call_vid, []):
                        if role2 != "arg":
                            continue
                        aidx2 = int(arg_idx2) if arg_idx2 else 0
                        if aidx2 in pt_indices:
                            continue
                        lbl2 = _vattr(graph.vs[tgt2], "label", "")
                        # array() literal is an operator with callee="array"
                        if lbl2 == NodeLabel.OPERATOR.value:
                            callee2 = _vattr(graph.vs[tgt2], "callee", "")
                            if callee2 == "array":
                                continue
                        if lbl2 != NodeLabel.CONST.value:
                            non_pt_args_all_const = False
                            break
                    if non_pt_args_all_const:
                        vname = _vattr(graph.vs[call_vid], "name", "")
                        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            all_dep_params.extend(sub.get("dep_params", []))
            if sub.get("has_unresolved_call"):
                any_unresolved = True
        arg_counter += 1

    # Filter out reference parameters from dep_params
    ref_param_indices = set()
    for pvid, pidx in param_idx.items():
        if _vattr(graph.vs[pvid], "is_reference", ""):
            ref_param_indices.add(pidx)
    if ref_param_indices:
        all_dep_params = [p for p in all_dep_params if p not in ref_param_indices]

    vname = _vattr(graph.vs[call_vid], "name", "")
    unique = list(dict.fromkeys(all_dep_params))
    if unique:
        return {
            "origin": vname,
            "origin_type": "param",
            "dep_params": unique,
            "has_unresolved_call": any_unresolved,
        }
    return {"origin": vname, "origin_type": "unknown", "dep_params": [], "has_unresolved_call": any_unresolved}


# ---------------------------------------------------------------------------
# Internal: parameter 标记
# ---------------------------------------------------------------------------


def _mark_passthrough_params(graph: ig.Graph, func_vid: int, passthrough_indices: list[int], eidx: dict):
    """标记 function 下对应的 parameter 节点为 passthrough_arg。

    遍历 function → own → parameter，匹配 own 边的 index 属性。
    注意：index 在 own 边上，不在 parameter 节点上。
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    idx_set = set(i for i in passthrough_indices if isinstance(i, int))
    for child_vid, edge_idx in eidx["own_ch"].get(func_vid, []):
        target_label = _vattr(graph.vs[child_vid], "label")
        if target_label != NodeLabel.PARAMETER.value:
            continue
        # index 在 own 边上（不在 parameter 节点上）
        pidx = edge_idx
        if pidx is not None and int(pidx) in idx_set:
            graph.vs[child_vid]["taint_type"] = "passthrough_arg"
