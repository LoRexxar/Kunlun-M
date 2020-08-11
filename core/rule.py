# -*- coding: utf-8 -*-

"""
    rule
    ~~~~

    import rule py

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import os
from Kunlun_M.settings import rules_path
from utils.log import logger


def block(index):
    default_index_reverse = 'in-function'
    default_index = 0
    blocks = {
        'in-function-up': 0,
        'in-function-down': 1,
        'in-current-line': 2,
        'in-function': 3,
        'in-class': 4,
        'in-class-up': 5,
        'in-class-down': 6,
        'in-file': 7,
        'in-file-up': 8,
        'in-file-down': 9
    }
    if isinstance(index, int):
        blocks_reverse = dict((v, k) for k, v in blocks.items())
        if index in blocks_reverse:
            return blocks_reverse[index]
        else:
            return default_index_reverse
    else:
        if index in blocks:
            return blocks[index]
        else:
            return default_index


class Rule(object):
    def __init__(self, lans=["php"]):
        if not lans:
            lans = ["php"]

        self.rule_dict = {}

        # 逐个处理每一种lan
        for lan in lans:
            self.rules_path = rules_path + "/" + lan
            if not os.path.exists(self.rules_path):
                logger.error("[INIT][RULE] language {} can't found rules".format(self.rules_path))
                os.mkdir(self.rules_path)

            self.rule_list = self.list_parse()

            # import function from rule
            for rule in self.rule_list:
                rulename = rule.split('.')[0]
                rulefile = "rules." + lan + "." + rulename
                self.rule_dict[rulename] = __import__(rulefile, fromlist=rulename)

        self.vulnerabilities = self.vul_init()

    def rules(self, special_rules=None):

        rules = {}

        if special_rules is None:
            return self.rule_dict
        else:
            for rulename in self.rule_dict:
                if rulename+".py" in special_rules:
                    rules[rulename] = self.rule_dict[rulename]

            return rules

    def list_parse(self):

        files = os.listdir(self.rules_path)
        result = []

        for f in files:
            if f.startswith("CVI_"):
                result.append(f)

        return result

    def vul_init(self):

        vul_list = []

        for rulename in self.rule_dict:
            p = getattr(self.rule_dict[rulename], rulename)

            ruleclass = p()
            vul_list.append(ruleclass.vulnerability)

        return vul_list


class RuleCheck:
    """
    规则检查，并读取所有的规则
    """

    def __init__(self):
        self.rule_dict = {}

        self.rule_base_path = rules_path

    def list_parse(self, rules_path, istamp=False):

        files = os.listdir(rules_path)
        result = []

        for f in files:

            if f.startswith("_") or f.endswith("pyc"):
                continue

            if os.path.isdir(os.path.join(rules_path, f)):
                if f not in ['test', 'tamper']:
                    result.append(f)

            if f.startswith("CVI_"):
                result.append(f)

            if istamp:
                if f not in ['test.py', 'demo.py', 'none.py']:
                    result.append(f)

        return result

    def run(self):
        print(self.list_parse(self.rule_base_path))

        return True
