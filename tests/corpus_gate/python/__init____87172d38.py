#!/usr/bin/env python
# encoding: utf-8
"""PHP Unserialize Chain Finder plugin — graph engine version."""

from .main import PhpUnserializeChain

PLUGIN_NAME = 'phpunserializechain'
PLUGIN_OBJECT = PhpUnserializeChain
PLUGIN_STATUS = True
PLUGIN_DESCRIPTION = 'Find PHP unserialize chains via AST graph analysis and generate PoC'
