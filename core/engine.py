# -*- coding: utf-8 -*-

"""
    engine
    ~~~~~~

    Implements scan engine (兼容层，从子模块 re-export)

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""

from .scanner import scan, scan_single, oldscan, Running, score2level, SingleRule
from .matcher import VulnerabilityMatcher as Core
from .filters import VulnerabilityFilter
from .rule_generator import init_match_rule, NewCore

VulnerabilityMatcher = Core

__all__ = [
    'scan', 'oldscan', 'scan_single', 'Running', 'score2level', 'SingleRule',
    'Core', 'VulnerabilityMatcher', 'VulnerabilityFilter',
    'init_match_rule', 'NewCore',
]
