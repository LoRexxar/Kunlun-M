"""igraph 1.0.x 兼容层。

igraph 1.0 的 Vertex / Edge 对象没有 dict 风格的 ``.get()`` 方法：
- ``v["name"]`` 读取属性
- ``v["nonexist"]`` 抛 KeyError
- ``v.get("name")`` 抛 AttributeError

本模块提供 ``vattr()`` 作为安全属性访问的唯一入口，
所有操作 igraph 对象的代码统一使用此函数。
"""

from __future__ import annotations

from typing import Any


def vattr(vertex_or_edge, key: str, default: Any = None) -> Any:
    """安全读取 igraph Vertex/Edge 属性，等价于 dict.get(key, default)。

    Usage::

        from utils.igraph_compat import vattr

        name = vattr(v, "name", "")
        label = vattr(e, "label", "")

    禁止直接使用 ``vertex_or_edge["key"]`` 访问可能不存在的属性。
    """
    try:
        val = vertex_or_edge[key]
        return val if val is not None else default
    except (KeyError, TypeError):
        return default


# 向后兼容别名
_vattr = vattr
