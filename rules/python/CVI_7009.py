# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7009(SingleRuleMixin):
    """
    Python 开放重定向
    覆盖: Flask redirect, Django HttpResponseRedirect, redirect, RedirectResponse
    """
    def __init__(self):
        self.svid = 7009
        self.language = "python"
        self.vulnerability = "开放重定向"
        self.description = "使用了可能存在开放重定向风险的跳转函数"
        self.level = 4
        self.match_mode = "function-param-regex"
        self.match = r"redirect\(|HttpResponseRedirect\(|RedirectResponse\(|Redirect\(|flask\.redirect|django\.http\.HttpResponseRedirect"
        self.vul_function = ["redirect", "HttpResponseRedirect", "RedirectResponse", "Redirect"]

    def main(self, regex_string):
        """
        二次筛选：过滤硬编码URL重定向

        安全模式 (return False):
        - redirect('/home')  硬编码路径
        - redirect(url_for('index'))  内部路由
        - HttpResponseRedirect('/login')  硬编码

        危险模式 (return None):
        - redirect(url)  变量
        - redirect(request.GET.get('next'))  用户输入
        """
        if not regex_string:
            return None

        redirect_match = re.search(
            r'(?:redirect|HttpResponseRedirect|RedirectResponse|Redirect)\s*\(\s*(.+)', regex_string, re.I)
        if redirect_match:
            arg = redirect_match.group(1).strip()
            # 纯字符串字面量（硬编码路径）
            if re.match(r'^[\'"][^\'"]*[\'"]\s*\)', arg):
                return False
            # url_for() 内部路由是安全的
            if re.match(r'^url_for\s*\(', arg):
                return False
            # Flask PRG (Post-Redirect-Get): redirect(request.url) 重定向回
            # 当前页面，不是开放重定向（用户已经在该页面）
            if re.match(r'^request\.url\s*\)', arg):
                return False

        return None
