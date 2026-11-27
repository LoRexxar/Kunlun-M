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
        # Fix 160b (CVE-2026-97677 Langflow): pathlib/pandas 方法形态。
        # pathlib 的文件原语此前整个缺席——write_text/read_text/mkdir/unlink/
        # iterdir 以方法调用出现（接收者是 Path 对象），read_parquet/to_parquet
        # 以 pandas 模块/方法调用出现。方法名走 method_sinks（Path C 接收者
        # 无关准入，判例=Fix 142e CVI_7017 'write'）；构造器链/模块限定形态
        # （Path(tmp).open、pd.read_parquet）走 qualified vul_function 直接匹配。
        # 'open'/'replace' 绝不进 method_sinks：str.replace/socket.open 碰撞面
        # 太大，只保留 Path.open/Path.replace 限定形态。
        self.match = (r"\bopen\s*\(|shutil\.copy|shutil\.copyfile|shutil\.move|os\.remove|os\.unlink|os\.rename|send_file|FileResponse|os\.mkdir|os\.makedirs|shutil\.rmtree|shutil\.make_archive|shutil\.unpack_archive|tempfile\.mktemp"
                      r"|\.write_text\s*\(|\.read_text\s*\(|\.write_bytes\s*\(|\.read_bytes\s*\("
                      r"|\.mkdir\s*\(|\.rmdir\s*\(|\.unlink\s*\(|\.iterdir\s*\("
                      r"|\.read_parquet\s*\(|\.to_parquet\s*\(|pd\.read_parquet\s*\(|pd\.to_parquet\s*\(")
        self.vul_function = [
            # 实际执行文件 I/O 的函数
            "open", "send_file", "FileResponse",
            "os.remove", "os.unlink", "os.rename", "os.mkdir", "os.makedirs",
            "shutil.copy", "shutil.copyfile", "shutil.move",
            "shutil.rmtree", "shutil.make_archive", "shutil.unpack_archive",
            "tempfile.mktemp",
            # Fix 160b: pathlib 对象方法（qualified 形态，构造器链
            # Path(tmp).method 直接文本匹配；本地接收者形态由 method_sinks
            # 承接）
            "Path.write_text", "Path.read_text",
            "Path.write_bytes", "Path.read_bytes",
            "Path.mkdir", "Path.rmdir", "Path.unlink", "Path.iterdir",
            "Path.open", "Path.replace",
            # Fix 160b: pandas 模块限定形态（import pandas as pd / pandas）
            "pd.read_parquet", "pandas.read_parquet",
            "pd.to_parquet", "pandas.to_parquet",
        ]
        # Fix 160b: 接收者无关的方法名准入（find_sinks Path C）。这些名字
        # 在 python 生态中与路径语义强绑定（str/dict/list 无同名方法），
        # 第二阶段 main() 常量否决 + PB 污点门槛过滤无污点调用点。
        # 'open'/'replace' 故意缺席（碰撞面：socket.open/str.replace）。
        self.method_sinks = [
            "write_text", "read_text", "write_bytes", "read_bytes",
            "mkdir", "rmdir", "unlink", "iterdir",
            "read_parquet", "to_parquet",
        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: filter hardcoded paths and non-file-IO calls.
        open('/etc/hosts') → False (const)
        open(filepath) → None (variable)
        send_file(BytesIO_obj) → False (content, not path)
        """
        if sink_args:
            # Fix 156c (CVE-2026-133968): the hardcoded-path veto must hold
            # only when EVERY argument is a constant.  Two-arg copy/rename
            # sinks carry the attacker-controlled destination in arg1 while
            # arg0 is routinely a constant-ish source path
            # (shutil.copy(image_file, dest) — MONAI Label add_image), and
            # the old arg0-only const check returned False for the whole
            # call although the tainted dest arg had already been judged
            # controllable — a second-stage filter vetoing the taint stage.
            # Fix 160c (CVE-2026-97677): pathlib OBJECT method forms carry
            # the path on the RECEIVER — mkdir(parents=True, exist_ok=True)
            # / read_text(encoding=...) keyword args are modes/encodings,
            # never the traversal surface.  When every arg is constant the
            # admission necessarily came from the receiver-channel
            # parameters_back (the only other channel), so the
            # hardcoded-path veto must not second-guess it.
            # read_parquet/to_parquet are NOT in this family — their arg0
            # IS the path (pd.read_parquet('fixed.parquet') stays vetoed).
            # Module-qualified os.* calls keep the veto: a const arg there
            # is the hardcoded path, and with no receiver-object dfg flow
            # the receiver-PB finds nothing, so no finding exists to
            # second-guess (no-taint-result skip upstream).
            _recv_path_family = re.search(
                r'\.\s*(?:write_text|read_text|write_bytes|read_bytes'
                r'|mkdir|rmdir|unlink|iterdir)\s*\(', regex_string or '')
            _any_var = False
            for _arg in sink_args:
                if _arg.get('label') == 'const' or _arg.get('type') in ('string', 'constant'):
                    continue
                if _arg.get('resolved_value', ''):
                    continue
                _any_var = True
                break
            if not _any_var and not _recv_path_family:
                return False
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # send_file / FileResponse with function-return argument:
                # if arg0 comes from a function call, the return value is
                # typically an in-memory content object (BytesIO, string),
                # not a file path.  Path arguments are almost always string
                # variables, not function returns.
                sn = str(regex_string).lower() if regex_string else ''
                if 'send_file' in sn or 'fileresponse' in sn:
                    if arg0.get('is_func_return'):
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
