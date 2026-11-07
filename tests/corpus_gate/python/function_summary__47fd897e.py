from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from utils.log import logger


@dataclass
class ReturnFlowItem:
    """单条返回值数据流"""

    order: int
    return_index: int
    origin: str
    origin_type: str
    dep_params: List[int] = field(default_factory=list)
    path: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "order": self.order,
            "return_index": self.return_index,
            "origin": self.origin,
            "origin_type": self.origin_type,
            "dep_params": self.dep_params,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ReturnFlowItem:
        return cls(
            order=data["order"],
            return_index=data["return_index"],
            origin=data["origin"],
            origin_type=data["origin_type"],
            dep_params=data.get("dep_params", []),
            path=data.get("path", []),
        )


@dataclass
class FunctionSummary:
    """单个函数的完整摘要"""

    name: str
    params: List[str]
    line_range: Tuple[int, int]
    return_flow: List[ReturnFlowItem] = field(default_factory=list)
    receiver_name: str = ""
    is_method: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "params": self.params,
            "line_range": list(self.line_range),
            "return_flow": [item.to_dict() for item in self.return_flow],
            "receiver_name": self.receiver_name,
            "is_method": self.is_method,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FunctionSummary:
        return cls(
            name=data["name"],
            params=data["params"],
            line_range=tuple(data["line_range"]),
            return_flow=[ReturnFlowItem.from_dict(item) for item in data.get("return_flow", [])],
            receiver_name=data.get("receiver_name", ""),
            is_method=data.get("is_method", False),
        )


@dataclass
class FileSummary:
    """单文件摘要"""

    file: str
    content_hash: str
    functions: List[FunctionSummary] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "content_hash": self.content_hash,
            "functions": [fn.to_dict() for fn in self.functions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> FileSummary:
        return cls(
            file=data["file"],
            content_hash=data["content_hash"],
            functions=[FunctionSummary.from_dict(fn) for fn in data.get("functions", [])],
        )


class SummaryCacheManager:
    """函数摘要缓存管理器"""

    def __init__(self, cache_dir: str = ".kunlun_cache"):
        self.cache_dir = cache_dir

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _cache_dir_path(self, target_path: str) -> str:
        return os.path.join(target_path, self.cache_dir)

    def load_or_generate(self, target_path: str, files_dict: Dict[str, str]) -> Dict[str, FileSummary]:
        """
        加载缓存或标记需要重新生成的文件。

        :param files_dict: {file_path: file_content}
        :return: {file_path: FileSummary}，需要重新生成的文件 functions 为空列表
        """
        result: Dict[str, FileSummary] = {}
        cache_base = self._cache_dir_path(target_path)
        index_path = os.path.join(cache_base, "index.json")
        summaries_dir = os.path.join(cache_base, "summaries")

        index: Dict[str, str] = {}
        if os.path.isfile(index_path):
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    index = json.load(f).get("files", {})
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"读取缓存索引失败: {e}")
                index = {}

        for file_path, content in files_dict.items():
            current_hash = self._hash_content(content)
            cached_hash = index.get(file_path)

            if cached_hash == current_hash:
                summary_filename = self._hash_content(file_path)[:16] + ".json"
                summary_path = os.path.join(summaries_dir, summary_filename)
                if os.path.isfile(summary_path):
                    try:
                        with open(summary_path, "r", encoding="utf-8") as f:
                            summary = FileSummary.from_dict(json.load(f))
                        result[file_path] = summary
                        logger.debug(f"缓存命中: {file_path}")
                        continue
                    except (json.JSONDecodeError, OSError, KeyError) as e:
                        logger.warning(f"加载缓存摘要失败 {file_path}: {e}")

            result[file_path] = FileSummary(
                file=file_path,
                content_hash=current_hash,
                functions=[],
            )
            logger.debug(f"需要重新生成: {file_path}")

        return result

    def save_file_summary(self, target_path: str, file_path: str, summary: FileSummary) -> None:
        """保存单个文件的摘要到缓存。"""
        cache_base = self._cache_dir_path(target_path)
        summaries_dir = os.path.join(cache_base, "summaries")
        index_path = os.path.join(cache_base, "index.json")
        os.makedirs(summaries_dir, exist_ok=True)

        summary_filename = self._hash_content(file_path)[:16] + ".json"
        summary_path = os.path.join(summaries_dir, summary_filename)

        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, ensure_ascii=False, indent=2)

        index: Dict[str, str] = {}
        if os.path.isfile(index_path):
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    index = json.load(f).get("files", {})
            except (json.JSONDecodeError, OSError):
                index = {}

        index[file_path] = summary.content_hash

        with open(index_path, "w", encoding="utf-8") as f:
            json.dump({"files": index}, f, ensure_ascii=False, indent=2)

        logger.debug(f"已保存摘要缓存: {file_path}")

    def clear(self, target_path: str) -> None:
        """删除整个缓存目录。"""
        import shutil

        cache_base = self._cache_dir_path(target_path)
        if os.path.isdir(cache_base):
            shutil.rmtree(cache_base)
            logger.debug(f"已清除缓存: {cache_base}")
