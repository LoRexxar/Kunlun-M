#!/usr/bin/env python
# encoding: utf-8
"""EntranceFinder plugin — graph engine version."""

from .main import EntranceFinder

PLUGIN_NAME = 'entrancefinder'
PLUGIN_OBJECT = EntranceFinder
PLUGIN_STATUS = True
PLUGIN_DESCRIPTION = 'Find entry files based on AST graph subgraph complexity analysis'
