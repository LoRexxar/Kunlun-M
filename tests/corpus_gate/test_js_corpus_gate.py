"""Frozen-corpus parse gate for the JavaScript frontend (py-esprima).

Java/PHP twins live in the parser repos (ljavalang/lphply tests);
esprima is a third-party PyPI dependency, so its gate lives here —
the consumer side — guarding the exact parse entry the graph pipeline
uses (esprima.parse with tolerant+loc, graph_pipeline._parse_source).

Guards against: silent parser regressions from dependency bumps and
"extension liars" (PHP files wearing .js) sneaking into the corpus.
"""
import json
import os

import esprima
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, 'js')
MANIFEST = os.path.join(CORPUS, 'MANIFEST.json')


def _entries():
    if not os.path.exists(MANIFEST):
        return []
    with open(MANIFEST, encoding='utf-8') as f:
        return json.load(f)


def test_corpus_present_and_sized():
    """The frozen corpus must exist and stay above the shrink floor."""
    entries = _entries()
    assert len(entries) >= 60, (
        f'JS frozen corpus shrank to {len(entries)} files (<60). '
        'Corpus must not be reduced without recording the reason in the manifest.')


@pytest.mark.parametrize('entry', _entries(), ids=lambda e: e['name'])
def test_corpus_file_parses(entry):
    path = os.path.join(CORPUS, entry['name'])
    with open(path, encoding='utf-8', errors='ignore') as f:
        code = f.read()
    # Same entry as production: graph_pipeline._parse_source('javascript')
    esprima.parse(code, {'loc': True, 'tolerant': True})


# Modern-syntax capability set. All must parse except the recorded gap.
SYNTAX_OK = [
    ('optional_chaining', 'const x = a?.b?.c;'),
    ('nullish_coalescing', 'const x = a ?? b;'),
    ('logical_assignment', 'a ||= b; c &&= d; e ??= f;'),
    ('class_fields', 'class A { x = 1; static y = 2; #priv = 3; }'),
    ('async_arrow', 'const f = async (x) => await x;'),
    ('template_nested', 'const s = `a${`b${c}`}d`;'),
    ('spread', 'const a = [...b, ...c]; f(...a);'),
    ('destructuring', 'const {a: {b}, c = 1, ...rest} = obj; const [x, , y] = arr;'),
    ('getter_setter', 'class A { get x() { return 1; } set x(v) {} }'),
    ('generator', 'function* g() { yield* other(); }'),
    ('labeled_break', 'outer: for(;;) { break outer; }'),
    ('regex_lookbehind', 'const r = /(?<=a)b/g;'),
    ('exponent', 'const p = a ** b;'),
]

# Known gap, locked so a dependency bump that fixes it updates this test.
SYNTAX_KNOWN_GAPS = [
    ('bigint_literal', 'const n = 123n;'),
]


@pytest.mark.parametrize('name,code', SYNTAX_OK, ids=[n for n, _ in SYNTAX_OK])
def test_modern_syntax_parses(name, code):
    esprima.parse(code, {'loc': True, 'tolerant': True})


@pytest.mark.parametrize('name,code', SYNTAX_KNOWN_GAPS, ids=[n for n, _ in SYNTAX_KNOWN_GAPS])
def test_known_gap_still_gaps(name, code):
    """BigInt literals fail today; if esprima gains support, move the
    case to SYNTAX_OK — this pin prevents silent drift in either
    direction."""
    with pytest.raises(Exception):
        esprima.parse(code, {'loc': True, 'tolerant': True})
