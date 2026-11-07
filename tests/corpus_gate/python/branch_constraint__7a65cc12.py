# -*- coding: utf-8 -*-
"""
branch_constraint
~~~~~~~~~~~~~~~~~

分支条件约束追踪 — 公共数据结构。

所有语言引擎共享此模块，用于在 parameters_back 递归回溯中
携带和管理分支条件约束信息，从而减少因忽略 if/else 条件
导致的误报。
"""


class BranchConstraint:
    """单个条件约束"""

    __slots__ = ('var_name', 'op', 'value')

    def __init__(self, var_name: str, op: str, value=None):
        self.var_name = var_name
        self.op = op
        self.value = value

    def __repr__(self):
        if self.value is not None:
            return f"BranchConstraint({self.var_name!r} {self.op} {self.value!r})"
        return f"BranchConstraint({self.var_name!r} {self.op})"

    def __eq__(self, other):
        if not isinstance(other, BranchConstraint):
            return False
        return (self.var_name == other.var_name
                and self.op == other.op
                and self.value == other.value)

    def __hash__(self):
        return hash((self.var_name, self.op, self.value))

    def negate(self):
        """取反约束，用于 else/else if 分支。"""
        neg_map = {
            '==': '!=', '===': '!==',
            '!=': '==', '!==': '===',
            'isset': '!isset', '!isset': 'isset',
            'in': 'not in', 'not in': 'in',
            'type_validated': 'not_type_validated',
            'regex_validated': 'not_regex_validated',
        }
        return BranchConstraint(
            var_name=self.var_name,
            op=neg_map.get(self.op, self.op),
            value=self.value,
        )

