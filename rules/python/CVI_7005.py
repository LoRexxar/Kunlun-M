# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7005(SingleRuleMixin):
    """
    Python 文件操作 / 路径遍历
    覆盖: open, shutil, os.path, pathlib, Django FileResponse/send_file 等
    """
    def __init__(self):
        self.svid = 7005
        self.language = "python"
        self.vulnerability = "文件操作"
        self.description = "使用了可能存在路径遍历或文件操作风险的函数"
        self.level = 6
        self.match_mode = "function-param-regex"
        # 仅保留执行实际文件 I/O 的函数
        # path.join/basename/dirname/exists/abspath 已移除：纯字符串操作，不执行文件 I/O
        self.match = r"\bopen\s*\(|shutil\.copy|shutil\.copyfile|shutil\.move|os\.remove|os\.unlink|os\.rename|send_file|FileResponse|os\.mkdir|os\.makedirs|shutil\.rmtree|shutil\.make_archive|shutil\.unpack_archive|tempfile\.mktemp"
        self.vul_function = [
            # 实际执行文件 I/O 的函数
            "open", "send_file", "FileResponse",
            "os.remove", "os.unlink", "os.rename", "os.mkdir", "os.makedirs",
            "shutil.copy", "shutil.copyfile", "shutil.move",
            "shutil.rmtree", "shutil.make_archive", "shutil.unpack_archive",
            "tempfile.mktemp",
        ]

    def main(self, regex_string):
        """
        二次筛选：过滤非文件操作的同名函数调用 + 硬编码路径

        安全模式 (return False):
        - "; ".join(segments)    str.join 非文件操作
        - data.copy()            dict/list.copy 非文件操作
        - open('/etc/hosts')     硬编码路径
        - shutil.copy('a.txt', 'b.txt')  硬编码

        危险模式 (return None):
        - os.path.join('/var/data/', filename)  路径拼接
        - open(user_input)  变量
        - send_file(filepath)  变量
        """
        if not regex_string:
            return None

        # 过滤 str.join — normalizer 将 "; ".join() 和 os.path.join()
        # 都解析为 callee="path.join"，需要从源码行区分
        if re.search(r'\.join\s*\(', regex_string):
            # str.join 模式: "sep".join(items) — 字面量字符串调用 join
            if re.search(r'["\'][^"\']*["\']\s*\.\s*join', regex_string):
                return False
            # 变量.join() where 变量名不含 path（非 os.path.join）
            if re.search(r'\b\w+\s*\.\s*join\s*\(', regex_string):
                # 检查是否是 os.path.join 或 path.join 模式
                if not re.search(r'os\.path\.join|path\.join', regex_string):
                    # 进一步检查：如果行中有 return/赋值前缀 + 非 path 变量
                    if not re.search(r'\bpath\b', regex_string):
                        return False

        # 过滤 dict.copy / list.copy — shutil.copy 有参数，.copy() 无参
        if re.search(r'\.copy\s*\(\s*\)', regex_string):
            return False

        # 过滤 receiver.open() — self.open()/obj.open() 是方法调用，非内置 open()
        if re.search(r'\w+\s*\.\s*open\s*\(', regex_string):
            return False

        # 检查 open() 的参数
        open_match = re.search(r'\bopen\s*\(\s*(.+)', regex_string, re.I)
        if open_match:
            arg = open_match.group(1).strip()
            # 纯字符串字面量（硬编码路径）
            if re.match(r'^[\'"][^\'"]*[\'"]\s*(?:,|\))', arg):
                return False

        return None
