# -*- coding: utf-8 -*-

"""
    TypeScript SQL注入规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9705(SingleRuleMixin):
    """
    TypeScript SQL注入规则
    匹配 ORM/查询构建器的 query、execute 等数据库操作函数（sequelize/knex/typeorm）
    注意：callee 在 normalizer 中为方法名（如 query、execute），不含对象前缀
          这些方法名较通用，需结合上下文（ORM 对象调用）进行二次筛选
    """

    def __init__(self):
        self.svid = 9705
        self.language = "typescript"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能存在SQL注入风险的数据库查询函数（ORM的query、execute方法，如 sequelize.query、knex.raw、typeorm.createQueryRunner().query等），且查询参数可能受用户控制。攻击者可注入恶意SQL语句获取、修改或删除数据库数据。建议使用参数化查询（如 sequelize 的 replacements/namedReplacements 选项，knex 的绑定参数 ?），避免使用字符串拼接构建SQL。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.(?:query|execute|raw|createQueryBuilder)\s*\("

        self.vul_function = ["query", "execute", "raw", "createQueryBuilder"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的SQL操作。
        排除硬编码SQL字符串参数的情况（如 .query('SELECT 1')）。
        对纯字面量参数的安全调用进行排除。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'\.(?:query|execute|raw|createQueryBuilder)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 提取关键参数（第一个参数——SQL语句或查询条件）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            key_arg = arg_parts[0].strip()
        else:
            return None

        # createQueryBuilder() 通常不直接带SQL字符串参数，标记为潜在风险
        if re.search(r'\.createQueryBuilder\s*\(', regex_string):
            return True

        # 如果关键参数是纯硬编码字符串字面量（不含模板变量），排除
        if re.match(r'^\"[^\"]*\"$', key_arg) or re.match(r"^'[^']*'$", key_arg):
            return False
        if re.match(r'^`[^`]*`$', key_arg):
            return False

        # 确认包含危险的SQL操作调用
        dangerous_patterns = [
            r"\.query\s*\(",
            r"\.execute\s*\(",
            r"\.raw\s*\(",
            r"\.createQueryBuilder\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号、字符串和模板字符串"""
        args = []
        depth = 0
        in_single = False
        in_double = False
        in_template = False
        current = []
        i = 0
        while i < len(args_str):
            ch = args_str[i]
            if in_template and ch == '$' and i + 1 < len(args_str) and args_str[i + 1] == '{':
                depth += 1
                current.append('${')
                i += 2
                continue
            if ch == '"' and not in_single and not in_template and depth == 0:
                in_double = not in_double
                current.append(ch)
            elif ch == "'" and not in_double and not in_template and depth == 0:
                in_single = not in_single
                current.append(ch)
            elif ch == '`' and not in_single and not in_double and depth == 0:
                in_template = not in_template
                current.append(ch)
            elif in_single or in_double or in_template:
                current.append(ch)
            elif ch in ('(', '{', '['):
                depth += 1
                current.append(ch)
            elif ch in (')', '}', ']'):
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
            i += 1
        if current:
            args.append(''.join(current))
        return args
