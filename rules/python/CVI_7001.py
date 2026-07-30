# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7001(SingleRuleMixin):
    """
    Python 代码执行
    匹配 eval/exec/compile/__import__ 等
    """
    def __init__(self):
        self.svid = 7001
        self.language = "python"
        self.vulnerability = "代码执行"
        self.description = "使用了可能执行动态代码的函数，可能导致代码注入"
        self.level = 8
        self.match_mode = "function-param-regex"
        self.match = r"eval|exec|compile|__import__|ast\.literal_eval|importlib\.import_module"
        self.vul_function = ["eval", "exec", "compile", "__import__", "import_module"]

    def main(self, regex_string, sink_args=None):
        pass
