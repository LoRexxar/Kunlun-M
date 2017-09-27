# -*- coding: utf-8 -*-

"""
    templates
    ~~~~

    just tamplates for rule

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""


class temlates():
    """
    rule class
    
    ps: must temlates() for temlates.py
        just like CVI-1000() for CVI-1000.py
    """
    def __init__(self, target_file):
        self.target_file = target_file

        self.author = "LoRexxxar"
        self.languages = "PHP"
        self.vulnerability = "XSS"
        self.description = "Reflected XSS(description for vulnerabilty)"
        self.regexp = "echo|print|print_r|exit|die|printf|vprintf|trigger_error|user_error|odbc_result_all|ovrimos_result_all|ifx_htmltbl_result"

    def main(self, regex_string):
        """
        regex string input
        return all parm by list
        :regex_string: regex match string
        :return:
        """
        pass
