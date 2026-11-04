# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7002(SingleRuleMixin):
    """
    Python SQL 注入
    覆盖: cursor.execute, Django ORM raw/extra, SQLAlchemy, psycopg2 等
    """
    def __init__(self):
        self.svid = 7002
        self.language = "python"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能存在SQL注入风险的数据库操作函数"
        self.level = 7
        self.match_mode = "function-param-regex"
        self.match = r"cursor\.execute|connection\.execute|session\.execute|engine\.execute|db\.execute|\.raw\(|\.extra\(|RawSQL\(|cursor\.executemany|connection\.cursor|text\(|\.from_statement\("
        self.vul_function = ["execute", "cursor.execute", "raw", "extra"]
        # CVE-2026-63489 (Yeti <=2.5.0): ArangoDB AQL injection.  User-controlled
        # `sorting` / `filter_aliases` from POST /api/v2/*/search are f-string
        # interpolated into AQL identifier/expression positions in
        # core/database_arango.py (o.{field} SORT / o.{alias} FILTER) and the
        # assembled string is executed via `_db.aql.execute(aql, bind_vars=...)`
        # (commit 89d8b61c fixed with a strict [a-zA-Z0-9_.]+ allowlist).  The
        # sink is an attribute-chain call (`cls._db.aql.execute`) whose receiver
        # is a library object with no user-defined function node — qualified
        # matching can never hit, so declare the bare method name (Path C,
        # receiver-agnostic) and fall back to presence reporting: the AQL text
        # is built from crosses-frame f-string fragments the source model
        # cannot back-trace, but every real AQL-write goes through this call.
        self.method_sinks = ["execute"]
        # CVE-2026-63489: AQL text is assembled from cross-frame f-string
        # fragments (sorting/filter_aliases flow through neighbors()/filter()
        # into o.{field}/o.{alias} positions) — the source model cannot
        # back-trace the identifier interpolation, so this rule reports on
        # sink presence at aql.execute sites (opt out of taint proof).
        self.require_taint = False
        # Fix 53c: presence fires only at AQL execution sites (the source
        # line contains the aql attribute chain, e.g. `._db.aql.execute(`) —
        # classic cursor/requests .execute() keeps full taint semantics.
        self.presence_filter = r'\baql\s*\.\s*execute\b|\baql\.execute\b'

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: detect parameterized queries.
        execute(sql, params) with 2+ args → safe (parameterized).
        """
        if sink_args:
            # CVE-2026-63489 (Yeti AQL): `aql.execute(aql_string,
            # bind_vars=aql_args, count=True, full_count=True)` looks like a
            # parameterized call but bind_vars does NOT sanitize the
            # identifier/expression positions — the AQL text itself is
            # f-string assembled from user-controlled sorting/filter_aliases.
            # AQL execution sites are identifiable from the source line
            # (`._db.aql.execute(`); never acquit those via the params
            # heuristic.
            if regex_string and re.search(r'\baql\b', regex_string, re.I):
                return None
            names = [str(sa.get('name') or '').strip() for sa in sink_args]
            # arg#0 may be the receiver pseudo-arg ('execute(property)') —
            # drop it before parameterization heuristics.
            if names and names[0].lower() in ('execute', 'aql.execute', 'aql'):
                names = names[1:]
            if len(names) >= 2:
                second = names[1].lower()
                if second in ('true', 'false', 'none', ''):
                    return None  # option flag, not params — keep reporting
                if any(k in second for k in ('param', 'arg', 'var', 'value', 'bind', 'seq')):
                    return None  # bind container: identifier positions still injectable
                return False  # classic parameterized query
            return None

        # Regex fallback
        if not regex_string:
            return None
        execute_match = re.search(
            r'(?:cursor|connection|conn|session|engine|db)\.execute\s*\((.+)', regex_string, re.I)
        if execute_match:
            args_str = execute_match.group(1).strip()
            depth = 0
            for i, ch in enumerate(args_str):
                if ch in '([{':
                    depth += 1
                elif ch in ')]}':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    second_arg = args_str[i+1:].strip()
                    if second_arg and second_arg != 'None':
                        return False
        return None
