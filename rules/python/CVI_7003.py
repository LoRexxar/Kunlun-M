# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7003(SingleRuleMixin):
    """
    Python 反序列化
    覆盖: pickle, yaml, marshal, shelve, jsonpickle, pandas.read_pickle, torch.load 等
    """
    def __init__(self):
        self.svid = 7003
        self.language = "python"
        self.vulnerability = "反序列化"
        self.description = "使用了可能存在反序列化漏洞的危险函数"
        self.level = 7
        self.match_mode = "function-param-regex"
        self.match = r"pickle\.loads|pickle\.load|yaml\.load|yaml\.unsafe_load|yaml\.full_load|marshal\.loads|marshal\.load|shelve\.open|jsonpickle\.decode|pandas\.read_pickle|torch\.load|numpy\.load|joblib\.load|dill\.loads|dill\.load|cloudpickle\.loads|cloudpickle\.load"

    def main(self, regex_string, sink_args=None):
        pass
