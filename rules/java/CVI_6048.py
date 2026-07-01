# -*- coding: utf-8 -*-
from utils.api import *

class CVI_6048(SingleRuleMixin):
    """
    Hibernate HQL Injection — 检测 EntityManager.createQuery / Session.createQuery 
    的参数是否来自用户可控输入的字符串拼接 HQL
    """
    def __init__(self):
        self.svid = 6048
        self.language = "java"
        self.vulnerability = "Hibernate HQL Injection"
        self.description = "检测Hibernate EntityManager.createQuery/Session.createQuery参数是否为用户可控的拼接HQL"
        self.level = 9
        self.match_mode = "java-function-param-regex"
        self.match = r"\.createQuery\("
        self.unmatch = []
        self.black_list = []
        # AST 搜索 sink 函数名
        self.vul_function = ["EntityManager.createQuery", "Session.createQuery"]

    def main(self, regex_string):
        """二次筛选：确认是 createQuery 调用上下文"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 确认代码行包含 createQuery 调用
        if re.search(r'\.createQuery\s*\(', regex_string):
            return True
        return False
