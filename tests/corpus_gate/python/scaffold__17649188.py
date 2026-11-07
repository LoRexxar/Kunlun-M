# -*- coding: utf-8 -*-

import codecs
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from Kunlun_M.settings import RULES_PATH
from utils.utils import file_output_format


LANG_SVID_BASE = {
    "php": 1000,
    "javascript": 2000,
    "solidity": 3000,
    "chrome_ext": 4000,
}


def _ensure_dir(path: str) -> None:
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def _read_template(filename: str) -> str:
    with codecs.open(os.path.join(RULES_PATH, filename), "rb+", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _format_py_literal(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, dict, tuple)):
        return str(value)
    s = str(value).strip()
    if not s or s.lower() == "none":
        return "None"
    if s.startswith(("r\"", "r'", "\"", "'", "[", "{", "(")):
        return s
    return file_output_format(s)


def _parse_json_or_kv(text: str) -> Dict[str, Any]:
    raw = text.strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        return json.loads(raw)
    result: Dict[str, Any] = {}
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    for p in parts:
        if "=" not in p:
            raise ValueError("invalid kv pair: {}".format(p))
        k, v = p.split("=", 1)
        result[k.strip()] = v.strip()
    return result


def next_svid(language: str) -> int:
    lan = (language or "").strip().lower()
    if lan not in LANG_SVID_BASE:
        raise ValueError("unsupported language: {}".format(language))

    base = LANG_SVID_BASE[lan]
    lan_dir = os.path.join(RULES_PATH, lan)
    _ensure_dir(lan_dir)

    max_id = None
    for name in os.listdir(lan_dir):
        m = re.match(r"^CVI_(\d+)\.py$", name)
        if not m:
            continue
        rid = int(m.group(1))
        if rid < base:
            continue
        if max_id is None or rid > max_id:
            max_id = rid

    return base if max_id is None else max_id + 1


def render_rule(
    svid: int,
    language: str,
    rule_name: str,
    author: str,
    description: str,
    level: int = 1,
    status: bool = True,
    match_mode: str = "function-param-regex",
    match: Optional[str] = None,
    match_name: Optional[str] = None,
    black_list: Optional[str] = None,
    keyword: Optional[str] = None,
    unmatch: Optional[str] = None,
    vul_function: Optional[str] = None,
    main_function: Optional[str] = None,
) -> str:
    tpl = _read_template("rule.template")

    if not main_function:
        main_function = (
            "    def main(self, regex_string):\n"
            "        return None\n"
        )

    return tpl.format(
        rule_name=str(rule_name),
        svid=int(svid),
        language=str(language).strip().lower(),
        author=str(author),
        description=str(description),
        level=int(level),
        status="True" if status else "False",
        match_mode=str(match_mode),
        match=_format_py_literal(match),
        match_name=_format_py_literal(match_name),
        black_list=_format_py_literal(black_list),
        keyword=_format_py_literal(keyword),
        unmatch=_format_py_literal(unmatch),
        vul_function=_format_py_literal(vul_function),
        main_function=main_function.rstrip() + "\n",
    )


def write_rule_file(
    language: str,
    rule_name: str,
    author: str,
    description: Optional[str] = None,
    svid: Optional[int] = None,
    level: int = 1,
    status: bool = True,
    match_mode: str = "function-param-regex",
    match: Optional[str] = None,
    unmatch: Optional[str] = None,
    force: bool = False,
) -> Tuple[int, str]:
    lan = (language or "").strip().lower()
    if not description:
        description = rule_name

    rid = int(svid) if svid is not None else next_svid(lan)
    lan_dir = os.path.join(RULES_PATH, lan)
    _ensure_dir(lan_dir)

    rule_path = os.path.join(lan_dir, "CVI_{}.py".format(rid))
    if os.path.exists(rule_path) and not force:
        raise FileExistsError(rule_path)

    content = render_rule(
        svid=rid,
        language=lan,
        rule_name=rule_name,
        author=author,
        description=description,
        level=level,
        status=status,
        match_mode=match_mode,
        match=match,
        unmatch=unmatch,
    )

    with codecs.open(rule_path, "wb+", encoding="utf-8", errors="ignore") as f:
        f.write(content)

    return rid, rule_path


def render_tamper(tam_name: str, filter_function: Dict[str, Any], input_control: List[str]) -> str:
    tpl = _read_template("tamper.template")
    return tpl.format(tam_name=tam_name, filter_function=filter_function, input_control=input_control)


def write_tamper_file(
    tam_name: str,
    filter_func: Optional[str] = None,
    controlled: Optional[str] = None,
    force: bool = False,
) -> str:
    name = (tam_name or "").strip()
    if not name:
        raise ValueError("tamper name is required")

    filter_function = _parse_json_or_kv(filter_func) if filter_func else {}
    input_control = [x.strip() for x in (controlled or "").split(",") if x.strip()]

    tamp_dir = os.path.join(RULES_PATH, "tamper")
    _ensure_dir(tamp_dir)

    tamper_path = os.path.join(tamp_dir, "{}.py".format(name))
    if os.path.exists(tamper_path) and not force:
        raise FileExistsError(tamper_path)

    content = render_tamper(name, filter_function, input_control)
    with codecs.open(tamper_path, "wb+", encoding="utf-8", errors="ignore") as f:
        f.write(content)

    return tamper_path

