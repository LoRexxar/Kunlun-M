# -*- coding: utf-8 -*-

"""
    CVI-1010
    ~~~~

    ldap injection
    
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""


class CVI_1010():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1010
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "LDAPI"
        self.description = "LDAP injection"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "(ldap_add|ldap_delete|ldap_list|ldap_read|ldap_search|ldap_bind)"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
