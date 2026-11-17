"""
追踪缓存模块

为扫描引擎提供两层缓存：
1. 内置知识库预载：语言内置函数的可控性信息，无需运行时分析
2. 运行时缓存：追踪过程中缓存已分析的变量可控性结果，避免重复计算

使用方式：
    from core.core_engine.trace_cache import TraceCache

    cache = TraceCache("python")

    # 查询缓存
    result = cache.get(file_path, var_name, lineno)

    # 写入缓存
    cache.put(file_path, var_name, lineno, result)

    # 查询内置知识库
    knowledge = cache.lookup_builtin(func_name)

    # 每次新扫描清空运行时缓存（内置知识库不受影响）
    cache.clear()
"""

import importlib
from typing import Dict, List, Optional, Union


class TraceCache:
    """变量追踪结果缓存，含内置知识库预载"""

    def __init__(self, language):
        """
        :param language: "python", "php", "javascript", "java", "go"
        """
        self.language = language
        self._runtime_cache = {}  # key: (file_path, var_name, lineno) → value: (code, cp, expr_lineno)
        self._builtin_module = None  # 延迟加载的语言知识库模块

    def _load_builtin_module(self):
        """延迟加载语言知识库模块"""
        if self._builtin_module is None:
            try:
                module_path = f"core.core_engine.{self.language}.builtin_knowledge"
                self._builtin_module = importlib.import_module(module_path)
            except ImportError:
                # 知识库模块不存在，使用空模块
                self._builtin_module = False
        return self._builtin_module

    def _make_key(self, file_path, var_name, lineno):
        """生成缓存 key"""
        return (file_path, str(var_name), int(lineno))

    def get(self, file_path, var_name, lineno):
        """
        查询运行时缓存

        :return: (code, cp, expr_lineno) 或 None
        """
        key = self._make_key(file_path, var_name, lineno)
        return self._runtime_cache.get(key)

    def put(self, file_path, var_name, lineno, result):
        """
        写入运行时缓存

        :param result: (code, cp, expr_lineno)
        """
        key = self._make_key(file_path, var_name, lineno)
        self._runtime_cache[key] = result

    def lookup_builtin(self, func_name):
        """
        查询内置知识库

        :param func_name: 函数/方法名（支持 "module.func" 和 "func" 两种格式）
        :return: {"passthrough": [...], "safe": bool} 或 None
        """
        module = self._load_builtin_module()
        if module and hasattr(module, 'lookup'):
            # Fix 100 (CVE-2026-29080 gates): "__method__.<name>" probes
            # (knowledge_bridge Fix 93c, method-form overrides) are
            # EXACT-ONLY.  Every builtin_knowledge.lookup() has a bare
            # short-name fallback ("a.b" -> KNOWLEDGE["b"]), so probing
            # "__method__.entries" against a language that defines no
            # __method__ entries fell back to KNOWLEDGE["entries"] —
            # cross-language poisoning: JS KNOWLEDGE["entries"/"format"]
            # are {safe: True} (string-method tables), which certified
            # Object.entries(...)'s return as clean and killed the Fix 78
            # saltcorn sync.js chain (repro gate sync.js 3104: 3 -> 1).
            # Only a language that ships a literal "__method__.<name>" key
            # (python, Fix 93c) may answer the probe.
            if func_name.startswith("__method__."):
                k = getattr(module, "KNOWLEDGE", None)
                if k and func_name in k:
                    return k[func_name]
                return None
            return module.lookup(func_name)
        return None

    def clear(self):
        """清空运行时缓存（内置知识库不受影响）"""
        self._runtime_cache.clear()

    def invalidate(self, file_path, var_name, lineno):
        """删除指定缓存条目"""
        key = self._make_key(file_path, var_name, lineno)
        self._runtime_cache.pop(key, None)

    @property
    def size(self):
        """当前缓存条目数"""
        return len(self._runtime_cache)

    def stats(self):
        """缓存统计信息"""
        module = self._load_builtin_module()
        builtin_count = len(getattr(module, 'KNOWLEDGE', {})) if module else 0
        return {
            "language": self.language,
            "runtime_entries": len(self._runtime_cache),
            "builtin_entries": builtin_count,
        }
