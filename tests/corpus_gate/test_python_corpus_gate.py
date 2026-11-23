"""Python frozen-corpus parse gate (Fix 64).

Mirrors the JS consumer-side gate (tests/corpus_gate/test_js_corpus_gate.py):
the engine's python frontend is the stdlib `ast` module (graph_pipeline
_parse_source), so this gate pins the *runtime's* parse capability over a
frozen corpus + edge-syntax golden set.

Runtime note (2026-11-08): the engine moved to CPython 3.12 — PEP 695
syntax (type X = ..., def f[T], class C[T]) and nested f-strings now
parse (previously whole-file drops on 3.11; that boundary was measured
and locked in Fix 64, promoted here after the 3.12 upgrade passed the
full anchor matrix). KNOWN_312_GAPS is retained (empty-able) for future
boundary discoveries.
"""

import ast
import json
from pathlib import Path

import pytest

CORPUS_DIR = Path(__file__).parent / "python"
MANIFEST = CORPUS_DIR / "MANIFEST.json"
MIN_FILES = 90

GOLDEN_SYNTAX = {
    "match-stmt": "match p:\n case (1, 2): pass\n case [x, *y]: pass",
    "walrus": "if (n := len(a)) > 3: pass",
    "positional-only": "def f(a, /, b): pass",
    "async-await": "async def f():\n await g()",
    "decorator-chain": "@a\n@b\nclass C: pass",
    "star-expr": "a, *b, c = [1,2,3,4]",
    "annotated-assign": "x: int = 1",
    "lambda-default": "f = lambda a, b=2: a+b",
    "try-star": "try:\n pass\nexcept* TypeError: pass",
    "type-alias": "type Alias = int | str",
    "type-params": "def f[T](x: T) -> T: return x",
    "generic-class": "class C[T, U]: pass",
    "f-string-nested": 'x = f"{f"{y}"}"',
}

# Future runtime boundaries get reverse-pinned here (pattern proven by
# the PEP 695 lock on 3.11).
KNOWN_312_GAPS = {}

import sys

IS_312_PLUS = sys.version_info >= (3, 12)


def _frozen_files():
    if not MANIFEST.exists():
        return []
    data = json.loads(MANIFEST.read_text())
    return [CORPUS_DIR / item["file"] for item in data]


def test_corpus_manifest_present():
    assert MANIFEST.exists(), "MANIFEST.json missing"
    files = _frozen_files()
    assert len(files) >= MIN_FILES, (
        f"frozen python corpus shrank: {len(files)} < {MIN_FILES} — "
        "regenerate MANIFEST.json deliberately, never shrink silently"
    )


@pytest.mark.parametrize("path", _frozen_files(), ids=lambda p: p.name)
def test_frozen_file_parses(path):
    src = path.read_text(encoding="utf-8", errors="replace")
    ast.parse(src)


@pytest.mark.parametrize("name,code", sorted(GOLDEN_SYNTAX.items()))
def test_edge_syntax_supported(name, code):
    ast.parse(code)


@pytest.mark.parametrize("name,code", sorted(KNOWN_312_GAPS.items()) or [("none", "pass")])
def test_known_gap_stays_pinned(name, code):
    """On 3.11 these must FAIL; on 3.12+ they must PASS and be promoted."""
    try:
        ast.parse(code)
        parses = True
    except SyntaxError:
        parses = False
    if IS_312_PLUS:
        assert parses, (
            f"{name} should parse on Python {sys.version_info} — "
            "promote to GOLDEN_SYNTAX and extend the corpus"
        )
    else:
        assert not parses, (
            f"{name} unexpectedly parses on {sys.version_info} — "
            "runtime gained the syntax: promote to GOLDEN_SYNTAX"
        )
