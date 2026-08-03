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
        self.vul_function = [
            "os.system", "os.popen",
            "subprocess.call", "subprocess.run", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "subprocess.getoutput", "subprocess.getstatusoutput",
            "commands.getoutput", "commands.getstatusoutput",
        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: filter hardcoded constant string arguments.
        os.system('ls -la') -> False (const)
        os.system(cmd) -> None (variable)
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # const/string literal → hardcoded command, not dangerous
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                # resolved_value: identifier with const assignment upstream
                rv = arg0.get('resolved_value', '')
                if rv:
                    return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        match = re.search(r'(?:os\.system|os\.popen|subprocess\.[\w]+|commands\.[\w]+)\s*\((.*)\)', regex_string, re.I)
        if not match:
            return None
        arg = match.group(1).strip()
        if re.match(r'^[\'\"](.*?)[\'\"]$', arg):
            return False
        if re.match(r'^f[\'\"](.*?)[\'\"]$', arg):
            if '{' not in arg:
                return False
        return None
