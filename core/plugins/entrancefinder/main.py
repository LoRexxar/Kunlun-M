#!/usr/bin/env python
# encoding: utf-8
"""EntranceFinder — 基于 AST 图引擎的入口文件发现插件。

通过分析 igraph 图中每个 File 节点的子图规模（子节点数量、边数量、
函数/类数量），找出"最复杂"的文件作为入口点。

用法:
    python kunlun.py plugin entrancefinder -t <target> [-l 2] [-b "vendor,tests"]
"""

import os

from core.plugins.baseplugin import BasePluginClass
from utils.file import Directory
from utils.log import logger
from utils.igraph_compat import _vattr


class EntranceFinder(BasePluginClass):
    """发现入口文件 — 基于图引擎重写版"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args)
        self.plugin_name = 'entrance_finder'

        self.parser_group_plugin.add_argument(
            '-l', '--limit', dest='limit', action='store', default=2,
            help='Minimum subgraph size to be considered an entrance (default: 2)',
        )
        self.parser_group_plugin.add_argument(
            '-b', '--blackwords', dest='blackwords', action='store', default='',
            help='File path blacklist (comma-separated substrings)',
        )

        self.required_arguments_list = ['target']
        self.arguments_list = ['target', 'debug', 'limit', 'blackwords']
        self.check_args()
        self.eval_args()
        self.limit = int(self.limit)
        self.black_list = self.blackwords.split(',') if self.blackwords else []

        self.main()

    def main(self):
        self._load_and_build_graph()
        self._get_statistics()

    def _load_and_build_graph(self):
        """解析目标目录，构建 AST 图，提取每个文件的子图指标。"""
        from core.pretreatment import ast_object
        from core.graph.graph_pipeline import build_ast_graph

        target = self.target
        logger.info('[EntranceFinder] Target: {}'.format(target))
        logger.info('[EntranceFinder] Limit: {}'.format(self.limit))

        if self.black_list:
            logger.info('[EntranceFinder] Blacklist: {}'.format(self.black_list))

        # 收集文件
        files, file_count, _ = Directory(target).collect_files()

        # AST 预处理
        ast_object.init_pre(target, files)
        ast_object.pre_ast_all(['php'])

        # 构建图
        graph = build_ast_graph(ast_object)

        if not graph or graph.vcount() == 0:
            logger.warn('[EntranceFinder] Graph is empty, no files to analyze.')
            self.file_stats = {}
            return

        # 提取每个 File 节点的子图规模
        self.file_stats = {}

        for vid in range(graph.vcount()):
            v = graph.vs[vid]
            vlabel = _vattr(v, "label", "")
            if vlabel != "file":
                continue

            # graph_builder 将 attrs 展开到 vertex attribute 顶层
            fpath = _vattr(v, "location", "") or _vattr(v, "path", "")

            fname = _vattr(v, "name", "")

            # 检查黑名单
            is_black = False
            for bword in self.black_list:
                if bword in fpath or bword in fname:
                    is_black = True
                    break

            if is_black:
                continue

            # 提取子图：BFS 收集该 File 节点下所有可达的节点
            sub_nodes = self._collect_subgraph_nodes(graph, vid)

            # 统计
            func_count = 0
            class_count = 0
            edge_count = 0
            for sn in sub_nodes:
                sl = _vattr(graph.vs[sn], "label", "")
                if sl == "function":
                    func_count += 1
                elif sl == "class":
                    class_count += 1

            # 统计子图内部边数
            sub_set = set(sub_nodes)
            for ei in range(graph.ecount()):
                s_vid = graph.es[ei].source
                t_vid = graph.es[ei].target
                if s_vid in sub_set and t_vid in sub_set:
                    edge_count += 1

            node_count = len(sub_nodes) - 1  # 排除 file 节点本身

            self.file_stats[fpath] = {
                'filename': fname,
                'nodes': node_count,
                'functions': func_count,
                'classes': class_count,
                'edges': edge_count,
            }

        logger.info('[EntranceFinder] Analyzed {} files.'.format(len(self.file_stats)))

    def _collect_subgraph_nodes(self, graph, file_vid):
        """BFS 收集 File 节点下所有通过 own/ast 边可达的节点。"""
        visited = set()
        queue = [file_vid]
        visited.add(file_vid)

        while queue:
            current = queue.pop(0)
            neighbors = graph.successors(current)

            for nb in neighbors:
                if nb in visited:
                    continue
                visited.add(nb)
                # 所有后继都纳入子图
                queue.append(nb)

        return list(visited)

    def _get_statistics(self):
        """输出统计结果。"""
        more_than_limit = []
        less_than_limit = []

        for fpath, stats in self.file_stats.items():
            entry = (stats['filename'], stats['nodes'], stats['functions'],
                     stats['classes'], stats['edges'])
            if stats['nodes'] > self.limit:
                more_than_limit.append(entry)
            elif 0 < stats['nodes'] <= self.limit:
                less_than_limit.append(entry)

        more_than_limit.sort(key=lambda x: x[1], reverse=True)
        less_than_limit.sort(key=lambda x: x[1], reverse=True)

        logger.info("[EntranceFinder] ===== Entrance candidates (> {} nodes) =====".format(self.limit))
        for entry in more_than_limit:
            logger.info("[EntranceFinder]   {} — {} nodes ({} funcs, {} classes, {} edges)".format(*entry))

        logger.info("[EntranceFinder] ===== Small files (<= {} nodes) =====".format(self.limit))
        for entry in less_than_limit:
            logger.info("[EntranceFinder]   {} — {} nodes ({} funcs, {} classes, {} edges)".format(*entry))


PLUGIN_NAME = 'entrancefinder'
PLUGIN_OBJECT = EntranceFinder
PLUGIN_STATUS = True
PLUGIN_DESCRIPTION = 'Find entry files based on AST graph subgraph complexity analysis'
