# -*- coding: utf-8 -*-

"""
    CVI-1006
    ~~~~

    Sqli

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1006():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1006
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SQLI"
        self.description = "SQL injection"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "(mysqli_query|pg_execute|pg_insert|pg_query|pg_select|pg_update|sqlite_query|msql_query|mssql_query|odbc_exec|fbsql_query|sybase_query|ibase_query|dbx_query|ingres_query|ifx_query|oci_parse|sqlsrv_query|maxdb_query|db2_exec)\s?\(]"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
