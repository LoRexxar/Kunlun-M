# -*- coding: utf-8 -*-
"""
    filter_functions
    ~~~~~~~~~~~~~~~~
    三层修复函数（filter functions）统一管理模块

    三层加载体系：
      L1 (Builtin): 内置修复函数表，从 IS_REPAIR_DEFAULT + builtin_knowledge 合并。
                    精确函数名 → CVI 列表，数据来源于 rules/tamper/demo_*.py。
      L2 (Summary): 运行时函数摘要继承。当分析函数定义时，若 return 语句调用了
                    L1/L3 中的已知安全函数，则将当前函数也标记为安全（继承 safe_for）。
      L3 (Rule):    CVI 规则级自定义。规则可在 init 时声明额外的修复函数，
                    运行时通过 register_rule_functions() 追加，优先级最高。

    查询接口：
      is_safe_function(func_name, svid, language) -> bool
        精确匹配函数名，按 L3 > L2 > L1 优先级判定是否对给定 svid 安全。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT
"""

import logging

logger = logging.getLogger(__name__)


class FilterFunctionRegistry:
    """
    修复函数注册表，支持三层加载。

    数据结构：
      L1 _builtin:  {language: {func_name: set_of_svid}}
      L2 _summary:  {language: {func_name: set_of_svid}}
      L3 _rule:     {language: {func_name: set_of_svid}}

    查询：is_safe_function 在 L3 → L2 → L1 中依次查找，
         只要任一层命中且 svid 在对应的 set 中，即返回 True。
    """

    def __init__(self):
        self._builtin = {}   # L1: {language: {func_name: set(svid)}}
        self._summary = {}   # L2: {language: {func_name: set(svid)}}
        self._rule = {}      # L3: {language: {func_name: set(svid)}}
        self._loaded_languages = set()

    def _ensure_lang(self, store, language):
        """确保语言子表存在。"""
        if language not in store:
            store[language] = {}

    def load_builtin(self, language, repair_dict):
        """
        L1 加载：从 IS_REPAIR_DEFAULT 字典加载。

        :param language: 语言标识 (php/python/go/java/javascript/c)
        :param repair_dict: {func_name: [svid1, svid2, ...]} — 原始 IS_REPAIR_DEFAULT 格式
        """
        self._ensure_lang(self._builtin, language)
        for func_name, svid_list in repair_dict.items():
            if not isinstance(svid_list, (list, tuple)):
                continue
            svid_set = set(svid_list)
            if func_name in self._builtin[language]:
                self._builtin[language][func_name] |= svid_set
            else:
                self._builtin[language][func_name] = svid_set
        self._loaded_languages.add(language)
        logger.debug("[FILTER] L1 loaded for {}: {} functions".format(
            language, len(self._builtin.get(language, {}))))

    def register_summary(self, language, func_name, svid_set):
        """
        L2 注册：函数摘要分析继承。

        当分析一个函数定义时，如果 return 语句调用了已知安全函数，
        则将当前函数也标记为安全，继承同样的 svid 集合。

        :param language: 语言标识
        :param func_name: 被分析的函数名
        :param svid_set: 继承的 svid 集合 (set)
        """
        self._ensure_lang(self._summary, language)
        if func_name in self._summary[language]:
            self._summary[language][func_name] |= svid_set
        else:
            self._summary[language][func_name] = svid_set.copy()
        logger.debug("[FILTER] L2 registered: {} -> {} svids={}".format(
            language, func_name, svid_set))

    def register_rule_functions(self, language, svid, func_names):
        """
        L3 注册：CVI 规则级自定义修复函数。

        :param language: 语言标识
        :param svid: 当前 CVI 规则编号
        :param func_names: 额外声明的修复函数名列表
        """
        self._ensure_lang(self._rule, language)
        for func_name in func_names:
            if func_name in self._rule[language]:
                self._rule[language][func_name].add(svid)
            else:
                self._rule[language][func_name] = {svid}

    def is_safe_function(self, func_name, svid, language):
        """
        查询函数是否为指定 CVI 的修复函数。

        精确匹配函数名（不做字符串包含），按 L3 > L2 > L1 优先级查询。

        :param func_name: 精确函数名（如 "html.escape", "intval"）
        :param svid: CVI 编号 (int)
        :param language: 语言标识
        :return: True 表示该函数对该 svid 是安全修复
        """
        # L3: 规则级自定义（最高优先级）
        if language in self._rule and func_name in self._rule[language]:
            if svid in self._rule[language][func_name]:
                return True

        # L2: 摘要分析继承
        if language in self._summary and func_name in self._summary[language]:
            if svid in self._summary[language][func_name]:
                return True

        # L1: 内置表
        if language in self._builtin and func_name in self._builtin[language]:
            if svid in self._builtin[language][func_name]:
                return True

        return False

    def is_safe_function_any(self, func_name, language):
        """
        查询函数是否为任何 CVI 的修复函数（不限定 svid）。

        用于 scan_parser 中的通用修复判定，如 is_repair() 替代。

        :param func_name: 精确函数名
        :param language: 语言标识
        :return: True 表示该函数在任何 CVI 下都被视为安全修复
        """
        for store in (self._rule, self._summary, self._builtin):
            if language in store and func_name in store[language]:
                return True
        return False

    def get_repair_functions(self, language, svid):
        """
        获取指定语言和 svid 下所有修复函数名列表。

        兼容现有 matcher/scan_parser 的 repair_functions 参数接口。

        :param language: 语言标识
        :param svid: CVI 编号
        :return: 修复函数名列表 [func_name, ...]
        """
        result = set()
        for store in (self._rule, self._summary, self._builtin):
            if language in store:
                for func_name, svid_set in store[language].items():
                    if svid in svid_set:
                        result.add(func_name)
        return list(result)

    def get_summary_safe_set(self, language, func_name):
        """
        获取函数的 L1+L3 safe_for 集合（供 L2 继承使用）。

        当分析函数 return 语句时，需要知道调用的子函数的 safe_for 集合，
        以便继承到当前函数。

        :param language: 语言标识
        :param func_name: 子函数名
        :return: svid set 或空 set
        """
        result = set()
        # L1 + L3（不含 L2，避免循环继承）
        for store in (self._builtin, self._rule):
            if language in store and func_name in store[language]:
                result |= store[language][func_name]
        return result

    def clear_runtime(self):
        """清除 L2（summary）和 L3（rule）运行时数据，保留 L1（builtin）。"""
        self._summary.clear()
        self._rule.clear()

    def stats(self):
        """返回各层统计信息。"""
        result = {}
        for lang in sorted(self._loaded_languages):
            result[lang] = {
                "L1_builtin": len(self._builtin.get(lang, {})),
                "L2_summary": len(self._summary.get(lang, {})),
                "L3_rule": len(self._rule.get(lang, {})),
            }
        return result


# 全局单例
_registry = FilterFunctionRegistry()


def load_builtin(language, repair_dict):
    """加载 L1 内置修复函数。"""
    _registry.load_builtin(language, repair_dict)


def register_summary(language, func_name, svid_set):
    """L2 注册：函数摘要继承。"""
    _registry.register_summary(language, func_name, svid_set)


def register_rule_functions(language, svid, func_names):
    """L3 注册：规则级自定义。"""
    _registry.register_rule_functions(language, svid, func_names)


def is_safe_function(func_name, svid, language):
    """查询函数是否为指定 CVI 的修复函数。"""
    return _registry.is_safe_function(func_name, svid, language)


def is_safe_function_any(func_name, language):
    """查询函数是否为任何 CVI 的修复函数。"""
    return _registry.is_safe_function_any(func_name, language)


def get_repair_functions(language, svid):
    """获取指定语言/svid 的修复函数名列表（兼容现有接口）。"""
    return _registry.get_repair_functions(language, svid)


def get_summary_safe_set(language, func_name):
    """获取函数的 L1+L3 safe_for 集合（供 L2 继承）。"""
    return _registry.get_summary_safe_set(language, func_name)


def clear_runtime():
    """清除运行时数据，保留内置表。"""
    _registry.clear_runtime()


def stats():
    """统计信息。"""
    return _registry.stats()
