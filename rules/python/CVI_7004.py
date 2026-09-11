# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7004(SingleRuleMixin):
    """
    Python SSRF
    覆盖: requests, urllib, http.client, aiohttp, httpx 等

    NOTE: requests/urllib HTTP requests are normal client behavior.
    SSRF requires URL pointing to internal resources, which static
    analysis cannot determine. Filter hardcoded URLs.
    """
    def __init__(self):
        self.svid = 7004
        self.language = "python"
        self.vulnerability = "SSRF"
        self.description = "使用了可能存在SSRF风险的HTTP请求函数"
        self.level = 6
        self.match_mode = "function-param-regex"
        self.match = r"requests\.get|requests\.post|requests\.put|requests\.delete|requests\.head|requests\.patch|requests\.options|requests\.request|urllib\.request\.urlopen|urllib\.request\.urlretrieve|urlopen|http\.client\.HTTPConnection|http\.client\.HTTPSConnection|aiohttp\.ClientSession|httpx\.Client|httpx\.get|httpx\.post|httpx\.request|treq\.get|treq\.post"

    def main(self, regex_string, sink_args=None):
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
                if arg0.get('is_func_return') and arg0.get('return_callee', '').lower() in ('urljoin', 'urlunparse'):
                    return False
            return None

        if not regex_string:
            return None
        m = re.search(r'(?:requests|httpx|urllib)\.\w+\s*\(\s*(.+?)[\),]', regex_string)
        if m:
            arg = m.group(1).strip()
            if re.match(r'^[\'"][^\'"]*[\'"]$', arg):
                return False
        return None
