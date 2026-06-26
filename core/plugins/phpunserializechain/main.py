#!/usr/bin/env python
# encoding: utf-8
"""PHP Unserialize Chain Finder — 基于图引擎的反序列化链发现插件。

从 AST 图中提取 PHP 类/方法结构，递归追踪反序列化魔法方法调用链
(__destruct, __wakeup, __toString, __call, __get, __set, __invoke)，
自动生成 PoC 文件。

用法:
    python kunlun.py plugin phpunserializechain -t <target> [-o <output>] [--no-poc]
"""

import ast as ast_module
import json
import os
import re
import traceback
from datetime import datetime

from core.plugins.baseplugin import BasePluginClass
from utils.file import Directory
from utils.log import logger
from utils.igraph_compat import _vattr


class PhpUnserializeChain(BasePluginClass):
    """PHP 反序列化链分析 — 基于图引擎重写版"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args)
        self.plugin_name = 'php_unserialize_chain'

        self.parser_group_plugin.add_argument(
            '-o', '--output', dest='output', action='store', default='',
            help='Output directory for PoC files (default: <target>/.kunlunm_unserialize_poc)',
        )
        self.parser_group_plugin.add_argument(
            '--no-poc', dest='no_poc', action='store_true', default=False,
            help='Skip PoC file generation, only output chain analysis',
        )

        self.required_arguments_list = ['target']
        self.arguments_list = ['target', 'debug', 'output', 'no_poc']
        self.check_args()
        self.eval_args()

        # 链分析状态
        self.graph = None
        self.chain_fingerprints = set()
        self.available_chains = []
        self.current_chain_relations = []
        self.current_chain_properties = []

        self.main()

    def main(self):
        self._load_and_build_graph()
        self._find_all_chains()
        if not self.no_poc:
            self.generate_poc_files()
        else:
            logger.info("[PhpUnSerChain] --no-poc mode, skip PoC generation.")
        self._print_summary()

    # ===========================================================================
    # Graph Loading
    # ===========================================================================

    def _load_and_build_graph(self):
        from core.pretreatment import ast_object
        from core.graph.graph_pipeline import build_ast_graph

        target = self.target
        logger.info("[PhpUnSerChain] Target: {}".format(target))

        files, file_count, _ = Directory(target).collect_files()
        ast_object.init_pre(target, files)
        ast_object.pre_ast_all(['php'])

        self.graph = build_ast_graph(ast_object)

        if not self.graph or self.graph.vcount() == 0:
            logger.warn("[PhpUnSerChain] Graph is empty, skip chain analysis.")
            return

        # 索引：name → [vid, ...]  (function/method/class 节点)
        self.func_vids = {}  # function name → [vid]
        self.class_vids = {}  # class name → [vid]
        self.method_in_class = {}  # (class_vid, method_name) → [method_vid]
        self.class_children = {}  # class_name → [child_class_vid]
        self.method_body_vids = {}  # method_vid → [body_vid] (通过 own 边直接可达的子节点)

        for vid in range(self.graph.vcount()):
            label = self.graph.vs[vid]["label"]
            name = self.graph.vs[vid]["name"]

            if label == "function":
                self.func_vids.setdefault(name, []).append(vid)
            elif label == "class":
                self.class_vids.setdefault(name, []).append(vid)

                # 提取类中的方法
                self.method_in_class.setdefault((vid, "__class__"), [])
                for eid in self.graph.incident(vid, mode="out"):
                    e = self.graph.es[eid]
                    if e["label"] == "own":
                        target_vid = e.target
                        t_label = self.graph.vs[target_vid]["label"]
                        if t_label == "function":
                            t_name = self.graph.vs[target_vid]["name"]
                            self.method_in_class.setdefault((vid, t_name), []).append(target_vid)
                            # 提取方法体节点
                            body_vids = []
                            for sub_eid in self.graph.incident(target_vid, mode="out"):
                                sub_e = self.graph.es[sub_eid]
                                if sub_e["label"] == "own":
                                    body_vids.append(sub_e.target)
                            self.method_body_vids[target_vid] = body_vids

        # 提取继承关系（crg extends 边）
        for vid in range(self.graph.vcount()):
            label = self.graph.vs[vid]["label"]
            if label == "class":
                cname = self.graph.vs[vid]["name"]
                for eid in self.graph.incident(vid, mode="out"):
                    e = self.graph.es[eid]
                    if e["label"] == "crg":
                        parent_vid = e.target
                        parent_name = self.graph.vs[parent_vid]["name"]
                        crg_type = _vattr(e, "type", "")
                        if crg_type == "extends":
                            self.class_children.setdefault(parent_name, []).append(vid)

        logger.info("[PhpUnSerChain] Graph loaded: {} classes, {} functions".format(
            len(self.class_vids), len(self.func_vids)))

    # ===========================================================================
    # Chain Analysis
    # ===========================================================================

    def _find_all_chains(self):
        if not self.graph:
            return

        magic_methods = ["__destruct", "__wakeup", "__toString", "__call", "__get", "__set", "__invoke"]

        for class_name, class_vids in self.class_vids.items():
            for class_vid in class_vids:
                for magic in magic_methods:
                    method_vids = self.method_in_class.get((class_vid, magic), [])
                    for mvid in method_vids:
                        logger.debug("[PhpUnSerChain] Checking {}::{}".format(class_name, magic))
                        body_vids = self.method_body_vids.get(mvid, [])

                        for bvid in body_vids:
                            unserchain = []
                            chain_relations = []
                            chain_properties = []

                            if self._check_node_danger(bvid, class_name, mvid, unserchain,
                                                       chain_relations, chain_properties, depth=0):
                                # 检查是否已存在指纹
                                fp = json.dumps([self._vid_to_label(v) for v in unserchain], sort_keys=True)
                                if fp not in self.chain_fingerprints:
                                    self.chain_fingerprints.add(fp)
                                    self.available_chains.append({
                                        'chain_id': "{}::{}=>{}".format(
                                            class_name, magic,
                                            self._vid_to_label(unserchain[-1]) if unserchain else "unknown"
                                        ),
                                        'trigger_magic_method': magic,
                                        'entry_class': class_name,
                                        'entry_locate': class_name,
                                        'has_wakeup': magic == "__wakeup",
                                        'class_sequence': [class_name],
                                        'method_sequence': [magic],
                                        'chain_nodes': [
                                            {
                                                'node_type': self.graph.vs[v]["label"],
                                                'class': class_name,
                                                'method': _vattr(self.graph.vs[v], "name", ""),
                                                'source_node': self._vid_to_label(v),
                                                'sink_node': '',
                                                'vid': v,
                                            } for v in unserchain
                                        ],
                                        'recursive_relations': chain_relations,
                                        'analysis_properties': chain_properties,
                                    })

    def _vid_to_label(self, vid):
        return "{}:{}".format(self.graph.vs[vid]["label"], _vattr(self.graph.vs[vid], "name", ""))

    def _check_node_danger(self, node_vid, class_name, method_vid, unserchain,
                            chain_relations, chain_properties, depth=0):
        """检查节点是否触发危险 sink 或可继续递归。"""
        if depth > 40:
            logger.warn("[PhpUnSerChain] Too much depth. return.")
            return False

        if not self.graph or node_vid < 0 or node_vid >= self.graph.vcount():
            return False

        label = self.graph.vs[node_vid]["label"]
        name = _vattr(self.graph.vs[node_vid], "name", "")

        # 检查是否为危险 sink
        if self._is_danger_sink(node_vid, label, name):
            unserchain.append(node_vid)
            return True

        # Function 节点 — 检查调用图
        if label == "function":
            # 方法调用 → 跟入
            if self._try_follow_method_call(node_vid, name, class_name, method_vid,
                                             unserchain, chain_relations, chain_properties, depth):
                return True

        # Operator 节点 — 检查是否为成员访问链 ($this->a->b)
        if label == "operator":
            op_type = _vattr(self.graph.vs[node_vid], "type", "")
            if op_type in ("method_call",):
                if self._try_follow_member_call(node_vid, class_name, method_vid,
                                                unserchain, chain_relations, chain_properties, depth):
                    return True

        # 递归检查子节点（own/ast 边）
        for eid in self.graph.incident(node_vid, mode="out"):
            e = self.graph.es[eid]
            if e["label"] in ("own", "ast", "dfg"):
                target_vid = e.target
                if self._check_node_danger(target_vid, class_name, method_vid,
                                           unserchain, chain_relations, chain_properties, depth + 1):
                    return True

        return False

    def _is_danger_sink(self, vid, label, name):
        """检查是否为危险函数调用 sink。"""
        if label == "operator":
            op_type = _vattr(self.graph.vs[vid], "type", "")
            if op_type in ("call", "method_call", "static_call"):
                # 检查 sink 名称
                sink_names = {"eval", "system", "exec", "passthru", "shell_exec",
                              "popen", "proc_open", "assert", "preg_replace",
                              "create_function", "call_user_func", "call_user_func_array",
                              "array_map", "usort", "uasort", "array_filter",
                              "file_put_contents", "file_get_contents",
                              "include", "require", "include_once", "require_once"}
                if name in sink_names:
                    return True
        return False

    def _try_follow_method_call(self, node_vid, call_name, current_class, method_vid,
                                unserchain, chain_relations, chain_properties, depth):
        """尝试跟入方法调用。"""
        # 查找当前类中是否有该方法
        class_vids = self.class_vids.get(current_class, [])
        for cvid in class_vids:
            target_method_vids = self.method_in_class.get((cvid, call_name), [])
            for tmvid in target_method_vids:
                if tmvid == method_vid:
                    continue  # 避免自递归

                unserchain.append(node_vid)
                body_vids = self.method_body_vids.get(tmvid, [])
                for bvid in body_vids:
                    if self._check_node_danger(bvid, current_class, tmvid,
                                               unserchain, chain_relations, chain_properties, depth + 1):
                        return True
                unserchain.pop()

        # 尝试父类/子类
        return self._try_find_method_in_hierarchy(call_name, current_class, node_vid,
                                                   method_vid, unserchain, chain_relations,
                                                   chain_properties, depth)

    def _try_find_method_in_hierarchy(self, method_name, current_class, node_vid,
                                      current_method_vid, unserchain,
                                      chain_relations, chain_properties, depth):
        """在类继承层次中查找方法。"""
        # 查找父类
        class_vids = self.class_vids.get(current_class, [])
        for cvid in class_vids:
            for eid in self.graph.incident(cvid, mode="out"):
                e = self.graph.es[eid]
                if e["label"] == "crg":
                    parent_vid = e.target
                    parent_name = self.graph.vs[parent_vid]["name"]

                    # 查找父类中的方法
                    pm_vids = self.method_in_class.get((parent_vid, method_name), [])
                    for pmvid in pm_vids:
                        unserchain.append(node_vid)
                        body_vids = self.method_body_vids.get(pmvid, [])
                        for bvid in body_vids:
                            if self._check_node_danger(bvid, parent_name, pmvid,
                                                       unserchain, chain_relations,
                                                       chain_properties, depth + 1):
                                return True
                        unserchain.pop()

        # 查找子类
        child_vids = self.class_children.get(current_class, [])
        for child_vid in child_vids:
            child_name = self.graph.vs[child_vid]["name"]
            cm_vids = self.method_in_class.get((child_vid, method_name), [])
            for cmvid in cm_vids:
                unserchain.append(node_vid)
                body_vids = self.method_body_vids.get(cmvid, [])
                for bvid in body_vids:
                    if self._check_node_danger(bvid, child_name, cmvid,
                                               unserchain, chain_relations,
                                               chain_properties, depth + 1):
                        return True
                unserchain.pop()

        return False

    def _try_follow_member_call(self, node_vid, current_class, method_vid,
                                unserchain, chain_relations, chain_properties, depth):
        """跟踪 $this->a->b 形式的链式调用。"""
        name = _vattr(self.graph.vs[node_vid], "name", "")

        # 提取链式属性名
        chain_parts = name.split("->")
        if len(chain_parts) < 2:
            return False

        # 最后一个属性名可能触发 __call/__get/__set
        prop_name = chain_parts[-1]

        # 检查 __call
        for magic in ["__call", "__get"]:
            class_vids = self.class_vids.get(current_class, [])
            for cvid in class_vids:
                m_vids = self.method_in_class.get((cvid, magic), [])
                for mvid in m_vids:
                    unserchain.append(node_vid)
                    body_vids = self.method_body_vids.get(mvid, [])
                    for bvid in body_vids:
                        if self._check_node_danger(bvid, current_class, mvid,
                                                   unserchain, chain_relations,
                                                   chain_properties, depth + 1):
                            return True
                    unserchain.pop()

        return False

    # ===========================================================================
    # PoC Generation (preserved from original)
    # ===========================================================================

    def _print_summary(self):
        if not self.available_chains:
            logger.info("[PhpUnSerChain] No unserialize chain found.")
            return

        logger.info("[PhpUnSerChain] Found {} chain(s):".format(len(self.available_chains)))
        for chain in self.available_chains:
            logger.info("[PhpUnSerChain]   {}".format(chain['chain_id']))

    def generate_poc_files(self):
        if not self.available_chains:
            logger.info("[PhpUnSerChain] No complete unserialize chain found, skip poc generation.")
            return

        output_base_path = self.get_output_base_path()
        if not os.path.exists(output_base_path):
            os.makedirs(output_base_path)

        summary_path = os.path.join(output_base_path, 'php_unserialize_chain_summary.json')
        with open(summary_path, 'w', encoding='utf-8') as summary_file:
            json.dump({
                'generated_at': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                'target': self.target,
                'chain_count': len(self.available_chains),
                'chains': self.available_chains,
            }, summary_file, indent=2, ensure_ascii=False)

        for index, chain in enumerate(self.available_chains, start=1):
            poc_filename = "chain_{0:02d}.php".format(index)
            poc_path = os.path.join(output_base_path, poc_filename)
            with open(poc_path, 'w', encoding='utf-8') as poc_file:
                poc_file.write(self.render_chain_php(chain, index))

        all_chains_path = os.path.join(output_base_path, 'poc_all_chains.php')
        with open(all_chains_path, 'w', encoding='utf-8') as all_chain_file:
            all_chain_file.write(self.render_all_chains_php())

        logger.info("[PhpUnSerChain] Generated {} poc files (+1 launcher) in {}".format(
            len(self.available_chains), output_base_path))

    def get_output_base_path(self):
        output = self.output.strip() if self.output else ''
        if output:
            return os.path.abspath(output)
        return os.path.abspath(os.path.join(self.target, '.kunlunm_unserialize_poc'))

    def safe_php_identifier(self, value, default='UnknownClass'):
        if not value:
            return default
        safe = re.sub(r'[^a-zA-Z0-9_]', '_', value)
        if re.match(r'^[0-9]', safe):
            safe = 'C_' + safe
        return safe or default

    def extract_controllable_properties(self, chain):
        if chain.get('analysis_properties'):
            return chain.get('analysis_properties')
        props = []
        seen = set()
        pattern = re.compile(r'\$[a-zA-Z_]\w*(?:->([a-zA-Z_]\w*))')
        for item in chain.get('chain_nodes', []):
            for field in ['source_node', 'sink_node']:
                value = item.get(field, '')
                if not isinstance(value, str):
                    continue
                for prop in pattern.findall(value):
                    if prop and prop not in seen:
                        seen.add(prop)
                        props.append(prop)
        return props

    def render_chain_php(self, chain, chain_index):
        classes = chain['class_sequence']
        methods = chain['method_sequence']
        entry_class = self.safe_php_identifier(chain['entry_class'])
        trigger_method = chain['trigger_magic_method']

        controllable_props = self.extract_controllable_properties(chain)
        safe_props = [p for p in controllable_props if isinstance(p, str) and re.match(r'^[a-zA-Z_]\w*$', p)]
        safe_props = list(dict.fromkeys(safe_props))

        class_stub_lines = []
        for class_name in classes:
            safe_name = self.safe_php_identifier(class_name)
            props_set = set()
            for prop in safe_props:
                props_set.add(prop)
            extra_props = " ".join(["public ${};".format(p) for p in sorted(props_set)])
            if extra_props:
                extra_props = " " + extra_props
            class_stub_lines.append("if (!class_exists('{0}')) {{ class {0} {{{1} }} }}".format(safe_name, extra_props))
        if not class_stub_lines:
            class_stub_lines = ["class UnknownClass {}"]

        has_wakeup = 'true' if chain.get('has_wakeup') else 'false'
        return """<?php
/**
 * Auto generated by KunLun-M phpunserializechain plugin (graph engine).
 * Chain ID: {chain_id}
 * Trigger: {entry_class}::{trigger_method}
 */

{class_stubs}

function build_payload_chain_{chain_index:02d}() {{
    $root = new {entry_class}();

    // Set controllable properties
{props}

    // Trigger magic method
    {trigger_code}

    $payload = serialize($root);
    return ['payload' => $payload, 'urlencode' => urlencode($payload)];
}}

$result = build_payload_chain_{chain_index:02d}();
echo "[+] Chain Index: {chain_index}\\n";
echo "[+] Chain: {chain_id}\\n";
echo '[+] Methods: {methods}' . "\\n";
echo "[+] Controllable Props: {echo_props}\n";
echo "[+] Payload: " . $result['payload'] . "\\n";
echo "[+] Payload(urlencode): " . $result['urlencode'] . "\\n";

if ({has_wakeup}) {{
    echo "[!] Note: class has __wakeup(). If target is not vulnerable, __wakeup will execute during unserialize().\\n";
}}
""".format(
            chain_id=chain['chain_id'],
            entry_class=entry_class,
            trigger_method=trigger_method,
            methods=' -> '.join(methods),
            chain_index=chain_index,
            class_stubs="\n".join(class_stub_lines),
            props="\n".join(["    $root->{0} = 'PAYLOAD_{0}';".format(prop) for prop in safe_props]) or "    // No controllable properties found",
            trigger_code=self.build_trigger_code(trigger_method),
            echo_props=",".join(controllable_props) if controllable_props else "N/A",
            has_wakeup=has_wakeup,
        )

    def build_trigger_code(self, trigger_method):
        m = (trigger_method or '').lower()
        if m == '__tostring':
            return "// Trigger hint: (string)$root;"
        if m == '__call':
            return "// Trigger hint: $root->undefinedMethod('PAYLOAD_CALL');"
        if m == '__invoke':
            return "// Trigger hint: $root();"
        if m == '__wakeup':
            return "// Trigger hint: target-side unserialize() will invoke __wakeup automatically."
        if m == '__sleep':
            return "// Trigger hint: target-side serialize() will invoke __sleep automatically."
        return "// Trigger hint: target-side unserialize() may invoke the magic method depending on lifecycle."

    def render_all_chains_php(self):
        return """<?php
/**
 * Auto generated by KunLun-M phpunserializechain plugin (graph engine).
 * Multi-chain PoC launcher.
 */
$chainFiles = glob(__DIR__ . '/chain_*.php');
sort($chainFiles);
echo '[+] Found ' . count($chainFiles) . ' chain poc files' . PHP_EOL;
foreach ($chainFiles as $chainFile) {{
    echo '[+] Run ' . basename($chainFile) . PHP_EOL;
    passthru('php ' . escapeshellarg($chainFile));
    echo str_repeat('-', 60) . PHP_EOL;
}}
"""


PLUGIN_NAME = 'phpunserializechain'
PLUGIN_OBJECT = PhpUnserializeChain
PLUGIN_STATUS = True
PLUGIN_DESCRIPTION = 'Find PHP unserialize chains via AST graph analysis and generate PoC'
