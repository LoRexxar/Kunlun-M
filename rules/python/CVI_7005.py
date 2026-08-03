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

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: filter hardcoded paths and non-file-IO calls.
        open('/etc/hosts') → False (const)
        open(filepath) → None (variable)
        send_file(BytesIO_obj) → False (content, not path)
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # const/string literal → hardcoded path, safe
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
                # send_file / FileResponse with function-return argument:
                # if arg0 comes from a function call (e.g. dump_csv(),
                # generate_csv(), BytesIO()), the return value is typically
                # an in-memory content object, not a file path.
                # Only applies to send_file/FileResponse (not open/shutil
                # which always take paths).
                sn = str(regex_string).lower() if regex_string else ''
                if 'send_file' in sn or 'fileresponse' in sn:
                    if arg0.get('is_func_return'):
                        callee = arg0.get('return_callee', '')
                        # Whitelist of functions that DO return paths
                        path_funcs = ('join', 'abspath', 'realpath', 'dirname',
                                       'basename', 'normpath', 'expanduser')
                        if callee not in path_funcs:
                            return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        # 过滤 str.join
        if re.search(r'\.join\s*\(', regex_string):
            if re.search(r'["\'][^"\']*["\']\s*\.\s*join', regex_string):
                return False
            if re.search(r'\b\w+\s*\.\s*join\s*\(', regex_string):
                if not re.search(r'os\.path\.join|path\.join', regex_string):
                    if not re.search(r'\bpath\b', regex_string):
                        return False
        # dict.copy / list.copy
        if re.search(r'\.copy\s*\(\s*\)', regex_string):
            return False
        # receiver.open()
        if re.search(r'\w+\s*\.\s*open\s*\(', regex_string):
            return False
        open_match = re.search(r'\bopen\s*\(\s*(.+)', regex_string, re.I)
        if open_match:
            arg = open_match.group(1).strip()
            if re.match(r'^[\'"][^\'"]*[\'"]\s*(?:,|\))', arg):
                return False
        return None
