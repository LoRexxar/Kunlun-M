# -*- coding: utf-8 -*-

"""
    export
    ~~~~~~

    Export scan result to files or console

    :author:    LoRexxar <lorexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Cobra-W
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""


class DeepAst:
    """
        deepast for more file 
    """
    def __init__(self, file_path, scan_result):
        self.file_path = file_path
        self.scan_result = scan_result

        self.regex = {
            'java': {
                'functions': r'(?:public|protected|private|static|\s) +[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\) *(?:\{?|[^;])',
                'string': r"(?:[\"])(.*)(?:[\"])",
                'assign_string': r"String\s{0}\s=\s\"(.*)\";",
                'annotation': r"(\\\*|\/\/|\*)+"
            },
            'php': {
                'functions': r'(?:function\s+)(\w+)\s*\(',
                'string': r"(?:['\"])(.*)(?:[\"'])",
                'assign_string': r"({0}\s?=\s?[\"'](.*)(?:['\"]))",
                'annotation': r"(#|\\\*|\/\/|\*)+",
                'variable': r'(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)',
                # Need match
                #    $url = $_GET['test'];
                #    $url = $_POST['test'];
                #    $url = $_REQUEST['test'];
                #    $url = $_SERVER['user_agent'];
                #    $v = trim($_GET['t']);
                # Don't match
                #    $url = $_SERVER
                #    $url = $testsdf;
                'assign_out_input': r'({0}\s?=\s?.*\$_[GET|POST|REQUEST|SERVER|COOKIE]+(?:\[))'
            }
        }

    def main(self):

        print self.scan_result
        return self.scan_result
