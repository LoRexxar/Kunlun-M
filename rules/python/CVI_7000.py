# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7000(SingleRuleMixin):
    """
    Python 命令注入
    匹配 os.system/os.popen/subprocess.*/commands.* 等
    """
    def __init__(self):
        self.svid = 7000
        self.language = "python"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数，可能导致命令注入"
        self.level = 8
        self.match_mode = "function-param-regex"
        self.match = r"os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen|subprocess\.check_output|subprocess\.check_call|subprocess\.getoutput|subprocess\.getstatusoutput|commands\.getoutput|commands\.getstatusoutput"

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：过滤硬编码常量字符串参数
        os.system('ls -la') -> False (硬编码)
        os.system(cmd) -> True (变量)
        """
        if not regex_string:
            return None

        # 提取函数调用参数部分: func(arg1, arg2, ...)
        match = re.search(r'(?:os\.system|os\.popen|subprocess\.[\w]+|commands\.[\w]+)\s*\((.*)\)', regex_string, re.I)
        if not match:
            return None

        arg = match.group(1).strip()

        # 纯字符串字面量（单引号/双引号包裹）
        if re.match(r'^[\'\"](.*?)[\'\"]$', arg):
            return False

        # f-string 无插值变量: f"constant string"
        if re.match(r'^f[\'\"](.*?)[\'\"]$', arg):
            # 检查是否有 {} 插值
            if '{' not in arg:
                return False

        return None
