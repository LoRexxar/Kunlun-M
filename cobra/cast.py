# -*- coding: utf-8 -*-

"""
    ast
    ~~~

    Implements CAST(Cross Abstract Syntax Tree)

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import re
import traceback
import codecs
from .log import logger
from .rule import block
from .file import File
from .file import FileParseAll
from .parser import is_controllable
from .parser import anlysis_params


class CAST(object):
    languages = ['php', 'java', 'sol']

    def __init__(self, rule, target_directory, file_path, line, code, files=None, rule_class=None, repair_functions=[]):
        self.target_directory = target_directory
        self.data = []
        self.rule = rule
        self.file_path = file_path
        self.line = line
        self.code = code
        self.files = files
        self.param_name = None
        self.param_value = None
        self.language = None
        self.sr = rule_class
        self.repair_functions = repair_functions
        for language in self.languages:
            if self.file_path[-len(language):].lower() == language:
                self.language = language

        os.chdir(self.target_directory)
        # Parse rule
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
        logger.debug("[AST] [LANGUAGE] {language}".format(language=self.language))

    def functions(self):
        """
        get all functions in this file
        :return:
        """
        # grep = Tool().grep
        if self.language not in self.regex:
            logger.info("[AST] Undefined language's functions regex {0}".format(self.language))
            return False
        regex_functions = self.regex[self.language]['functions']
        f = FileParseAll(self.files, self.target_directory)
        result = f.grep(regex_functions)
        try:
            result = result.decode('utf-8')
        except AttributeError as e:
            pass
        if len(result):
            functions = {}
            lines = result
            prev_function_name = ''
            for index, line in enumerate(lines):
                if line == ():
                    logger.info('[AST] Empty')
                    continue

                if len(line) < 2:
                    logger.info("[AST] Not found(:)")

                regex_annotation = self.regex[self.language]['annotation']
                string = re.findall(regex_annotation, line[1])
                if len(string) >= 1 and string[0] != '':
                    logger.info("[AST] This function is annotation")

                function_name = re.findall(regex_functions, line[2])
                if len(function_name) >= 1:
                    if len(function_name) == 2:
                        if function_name[0] != '':
                            function_name = function_name[0]
                        elif function_name[1] != '':
                            function_name = function_name[1]
                    else:
                        function_name = function_name[0]
                    if index > 0 and prev_function_name in functions:
                        functions[prev_function_name]['end'] = line[1]
                    prev_function_name = function_name
                    functions[function_name] = {
                        'start': line[1],
                        'end': None  # next function's start
                    }
                else:
                    logger.warning("[AST] Can't get function name: {0}".format(line))
            end = sum(1 for l in open(self.file_path))
            for name, value in functions.items():
                if value['end'] is None:
                    functions[name]['end'] = end
            return functions
        else:
            return False

    def block_code(self, block_position):
        """
        Get code block
        :param block_position:
                0:up
                1:down
                2:line
                3:in-function
        :return:
        """
        if block_position == 2:
            if self.line is None or self.line == 0:
                logger.critical("[AST] Line exception: {0}".format(self.line))
                return False
            line_rule = '{0}p'.format(self.line)
            code = File(self.file_path).lines(line_rule)
            if code is not False:
                code = code.strip()
            return code
        else:
            block_start = 1
            block_end = 0
            functions = self.functions()
            if functions:
                for function_name, function_value in functions.items():
                    if int(function_value['start']) < int(self.line) < int(function_value['end']):
                        in_this_function = '<---- {0}'.format(self.line)
                        if block_position == 0:
                            block_start = function_value['start']
                            block_end = int(self.line) - 1
                        elif block_position == 1:
                            block_start = int(self.line)
                            block_end = int(function_value['end']) - 1
                        elif block_position == 3:
                            block_start = function_value['start']
                            block_end = function_value['end']
                        logger.debug(
                            "[AST] [FUNCTION] {0} ({1} - {2}) {3}".format(function_name, function_value['start'],
                                                                          function_value['end'], in_this_function))
            else:
                if block_position == 0:
                    block_start = 1
                    block_end = int(self.line) - 1
                elif block_position == 1:
                    block_start = int(self.line) + 1
                    block_end = sum(1 for l in open(self.file_path))
                elif block_position == 3:
                    block_start = 1
                    block_end = sum(1 for l in open(self.file_path))
                logger.debug("[AST] Not function anything `function`, will split file")
            # get param block code
            line_rule = "{0},{1}p".format(block_start, block_end)
            code = File(self.file_path).lines(line_rule)
            logger.debug('[AST] [BLOCK-CODE-LINES] {0} - {1}p'.format(block_start, block_end))
            return code

    def is_controllable_param(self):
        """
        is controllable param
        :return:
        """
        param_name = re.findall(self.rule, self.code)

        if self.sr is not None:
            params = self.sr.main(param_name)

        if params is None:
            logger.debug("[AST] Not matching variables...")
            return False, self.data

        for param_name in params:
            try:
                self.param_name = param_name
                logger.debug('[AST] Param: `{0}`'.format(param_name))
                # all is string
                regex_string = self.regex[self.language]['string']
                string = re.findall(regex_string, param_name)
                if len(string) >= 1 and string[0] != '':
                    regex_get_variable_result = re.findall(self.regex[self.language]['variable'], param_name)
                    len_regex_get_variable_result = len(regex_get_variable_result)
                    if len_regex_get_variable_result >= 1:
                        # TODO
                        # 'ping $v1 $v2'
                        # foreach $vn
                        param_name = regex_get_variable_result[0]
                        logger.info("[AST] String's variables: `{variables}`".format(
                            variables=','.join(regex_get_variable_result)))
                    else:
                        logger.debug("[AST] String have variables: `No`")
                        return False, self.data
                logger.debug("[AST] String have variables: `Yes`")

                # variable
                if param_name[:1] == '$':
                    logger.debug("[AST] Is variable: `Yes`")

                    # Get assign code block
                    # param_block_code = self.block_code(0)
                    fi = codecs.open(self.file_path, "r", encoding='utf-8', errors='ignore')
                    param_content = fi.read()

                    if param_content is False:
                        logger.debug("[AST] Can't get assign code block")
                        return True, self.data

                    logger.debug("[Deep AST] Start AST for param {param_name}".format(param_name=param_name))

                    _is_co, _cp, expr_lineno = anlysis_params(param_name, param_content, self.file_path, self.line, self.sr.vul_function, self.repair_functions)

                    if _is_co == 1:
                        logger.debug("[AST] Is assign string: `Yes`")
                        return True, _cp
                    elif _is_co == 3:
                        logger.info("[AST] can't find this param, something error..")
                        continue
                    elif _is_co == 4:
                        logger.info("[AST] New vul function {}()".format(_cp[0].name))
                        return False, tuple([_is_co, _cp])
                    else:
                        continue

                else:
                    if self.language == 'java':
                        # Java variable didn't have `$`
                        param_block_code = self.block_code(0)
                        if param_block_code is False:
                            logger.debug("Can't get block code")
                            return True, self.data
                        logger.debug("[AST] Block code: ```{language}\r\n{code}```".format(language=self.language,
                                                                                           code=param_block_code))
                        regex_assign_string = self.regex[self.language]['assign_string'].format(re.escape(param_name))
                        string = re.findall(regex_assign_string, param_block_code)
                        if len(string) >= 1 and string[0] != '':
                            logger.debug("[AST] Is assign string: `Yes`")
                            continue
                            # return False, self.data
                        logger.debug("[AST] Is assign string: `No`")

                        # Is assign out data
                        regex_get_param = r'String\s{0}\s=\s\w+\.getParameter(.*)'.format(re.escape(param_name))
                        get_param = re.findall(regex_get_param, param_block_code)
                        if len(get_param) >= 1 and get_param[0] != '':
                            logger.debug("[AST] Is assign out data: `Yes`")
                            continue
                            # False, self.data
                        logger.debug("[AST] Is assign out data: `No`")
                        return True, self.data
                    logger.debug("[AST] Not Java/PHP, can't parse ({l})".format(l=self.language))
                    continue
                    # return False, self.data

            except KeyboardInterrupt as e:
                raise

            except:
                logger.warning("[AST] Can't get `param`, check built-in rule")
                traceback.print_exc()
                return False, self.data

        # if no variable can modify
        return False, self.data

    def match(self, rule, block_id):
        """
        Is repair
        :param rule:
        :param block_id:
        :return:
        """
        self.data = []
        logger.debug('[REPAIR-RULE-BLOCK] {b} {r}'.format(r=rule, b=block(block_id)))
        code = self.block_code(block_id)
        if code is False:
            logger.debug("[AST] Can't get match block code")
            return False, self.data
        # replace repair {{PARAM}} const
        if '{{PARAM}}' in rule:
            rule = rule.replace('{{PARAM}}', self.param_name)
        logger.debug("[AST] [BLOCK-CODE] `{code}`".format(code=code.strip()))
        repair_result = re.findall(rule, code, re.I)
        logger.debug("[AST] [MATCH-RESULT] {0}".format(repair_result))
        if len(repair_result) >= 1:
            return True, self.data
        else:
            return False, self.data
