# -*- coding: utf-8 -*-

"""
    filters
    ~~~~~~~

    漏洞文件前置过滤

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import re

from core.cast import CAST
from Kunlun_M.const import ext_dict


class VulnerabilityFilter:
    """漏洞文件前置过滤"""

    def __init__(self, target_directory, white_list, language, rule_match_mode):
        self.target_directory = os.path.normpath(target_directory)
        self.white_list = white_list
        self.language = language.lower()
        self.rule_match_mode = rule_match_mode

    def is_white_list(self, file_path):
        """
        Is white-list file
        :return: boolean
        """
        target_directory = self.target_directory.replace('\\', '/')
        file_path = file_path.replace('\\', '/')
        return file_path.split(target_directory, 1)[-1] in self.white_list

    def is_special_file(self, file_path):
        """
        Is special file
        :method: According to the file name to determine whether the special file
        :return: boolean
        """
        special_paths = [
            '/node_modules/',
            '/bower_components/',
            '.min.js',
            'jquery',
        ]
        for path in special_paths:
            if path in file_path:
                return True
        return False

    def is_test_file(self, file_path):
        """
        Is test case file
        :method: file name
        :return: boolean
        """
        test_paths = [
            '/test/',
            '/tests/',
            '/unitTests/'
        ]
        for path in test_paths:
            if path in file_path:
                return True
        return False

    def is_match_only_rule(self):
        """
        Whether only match the rules, do not parameter controllable processing
        :method: It is determined by judging whether the left and right sides of the regex_location are brackets
        :return: boolean
        """
        if self.rule_match_mode == 'regex-only-match':
            return True
        else:
            return False

    def is_annotation(self, code_content):
        """
        Is annotation
        :method: Judgment by matching comment symbols (skipped when self.is_match_only_rule condition is met)
               - PHP:  `#` `//` `\\*` `*`
                    //asdfasdf
                    \\*asdfasdf
                    #asdfasdf
                    *asdfasdf
               - Java:
        :return: boolean
        """
        match_result = re.findall(r"^(#|\\\*|\/\/)+", code_content)
        # Skip detection only on match
        if self.is_match_only_rule():
            return False
        else:
            return len(match_result) > 0

    def is_can_parse(self, file_path):
        """
        Whether to parse the parameter is controllable operation
        :return:
        """
        for language in CAST.languages:
            if file_path[-len(language):].lower() == language:
                return True
        return False

    def is_target(self, file_path):
        """
        try to find ext for target file and check it wheater target or not
        :return:
        """
        # get ext for file
        fileext = "." + file_path.split(".")[-1]

        if self.language in ext_dict and fileext is not None:
            if fileext in ext_dict[self.language]:
                return True

        return False

    def check(self, file_path, code_content):
        """组合判断是否跳过此漏洞。返回 (should_skip, reason_string)"""
        if self.is_white_list(file_path):
            return True, 'Whitelists(白名单)'
        if self.is_special_file(file_path):
            return True, 'Special File(特殊文件)'
        # test_file 只记录日志不跳过
        if self.is_annotation(code_content):
            return True, 'Annotation(注释)'
        return False, ''
