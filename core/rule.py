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
import inspect
import codecs
from Kunlun_M.settings import RULES_PATH

from utils.log import logger
from utils.utils import file_output_format

from web.index.models import Rules, Tampers


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
    def __init__(self, lans=[]):
        origin_lans = ["base"]
        origin_lans.extend(lans)

        self.rule_dict = {}

        # 逐个处理每一种lan
        for lan in origin_lans:
            self.rules_path = RULES_PATH + "/" + lan
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


def list_parse(rules_path, istamp=False):

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


class RuleCheck:
    """
    规则检查，并读取所有的规则
    """

    def __init__(self):
        self.rule_dict = {}

        self.rule_base_path = RULES_PATH

        self.CONFIG_LIST = ["vulnerability", "language", "level", "author", "description", "status", "match_mode",
                            "match", "vul_function", "main_function"]

        self.SOLIDITY_CONFIG_LIST = ['match_name', 'black_list', 'unmatch']
        self.REGEX_CONFIG_LIST = ['unmatch']
        self.CHROME_CONFIG_LIST = ['keyword', 'unmatch']

    def get_all_rules(self):
        rule_lan_list = list_parse(self.rule_base_path)

        for lan in rule_lan_list:
            self.rule_dict[lan] = []
            rule_lan_path = os.path.join(self.rule_base_path, lan)

            self.rule_dict[lan] = list_parse(rule_lan_path)

    def load_rules(self, ruleclass):

        main_function_content = inspect.getsource(ruleclass.main)
        match_name = ""
        black_list = ""
        unmatch = ""
        keyword = ""

        if ruleclass.match_mode == "regex-return-regex":
            match_name = ruleclass.match_name
            black_list = ruleclass.black_list
            unmatch = ruleclass.unmatch
        elif ruleclass.match_mode == "only-regex":
            unmatch = ruleclass.unmatch
        elif ruleclass.match_mode == "special-crx-keyword-match":
            unmatch = ruleclass.unmatch
            keyword = ruleclass.keyword

        r = Rules(rule_name=ruleclass.vulnerability, svid=ruleclass.svid,
                  language=ruleclass.language.lower(), author=ruleclass.author,
                  description=ruleclass.description, status=ruleclass.status,
                  match_mode=ruleclass.match_mode, match=ruleclass.match,
                  match_name=match_name, black_list=black_list, unmatch=unmatch, keyword=keyword,
                  vul_function=ruleclass.vul_function, main_function=main_function_content)

        r.save()

        return True

    def check_and_update_rule_database(self, ruleconfig_content, nowrule, config):

        svid = nowrule.svid
        ruleconfig_content = str(ruleconfig_content)

        if ruleconfig_content.lower() != str(getattr(nowrule, config)).lower():
            logger.warning("[INIT][Rule Check] CVI_{} config {} has changed:".format(svid, config))
            logger.warning("[INIT][Rule Check] {} in Rule File is {}".format(config, ruleconfig_content))
            logger.warning("[INIT][Rule Check] {} in Database is {}".format(config, getattr(nowrule, config)))

            logger.warning("[INIT][Rule Check] whether load new {} from Rule File(Y/N):".format(config))
            if input().lower() != 'n':
                setattr(nowrule, config, ruleconfig_content)
                return True

        return False

    def check_rules(self, ruleclass, nowrule):
        is_changed = False

        for config in self.CONFIG_LIST:
            if config != "main_function":
                if config == "vulnerability":
                    config1 = "rule_name"
                else:
                    config1 = config

                ruleconfig_content = str(getattr(ruleclass, config)).replace(r'\"', '"')

                is_changed = self.check_and_update_rule_database(ruleconfig_content, nowrule, config1)

            else:
                main_function_content = inspect.getsource(ruleclass.main)
                config1 = "main_function"

                is_changed = self.check_and_update_rule_database(main_function_content, nowrule, config1)

        # for special match_mode
        if ruleclass.match_mode == "regex-return-regex":
            for config in self.SOLIDITY_CONFIG_LIST:
                is_changed = self.check_and_update_rule_database(getattr(ruleclass, config), nowrule, config)
        elif ruleclass.match_mode == "only-regex":
            for config in self.REGEX_CONFIG_LIST:
                is_changed = self.check_and_update_rule_database(getattr(ruleclass, config), nowrule, config)
        elif ruleclass.match_mode == "special-crx-keyword-match":
            for config in self.CHROME_CONFIG_LIST:
                is_changed = self.check_and_update_rule_database(getattr(ruleclass, config), nowrule, config)

        if is_changed:
            nowrule.save()
        return True

    def load(self):
        """
        load rule from file to database
        :return:
        """

        self.get_all_rules()
        i = 0

        for lan in self.rule_dict:
            for rule in self.rule_dict[lan]:
                i += 1
                rulename = rule.split('.')[0]
                rulefile = "rules." + lan + "." + rulename

                rule_obj = __import__(rulefile, fromlist=rulename)
                p = getattr(rule_obj, rulename)

                ruleclass = p()

                r = Rules.objects.filter(svid=ruleclass.svid).first()

                if not r:

                    logger.info("[INIT][Load Rules] New Rule CVI_{} {}".format(ruleclass.svid, ruleclass.vulnerability))
                    self.load_rules(ruleclass)

                else:
                    logger.info("[INIT][Load Rules] Check Rule CVI_{} {}".format(ruleclass.svid, ruleclass.vulnerability))

                    self.check_rules(ruleclass, r)

        return True

    def recover(self):
        """
        recover rule from database to file
        :return:
        """
        rules = Rules.objects.all()

        for rule in rules:
            lan = rule.language

            if not os.path.isdir(os.path.join(RULES_PATH, lan)):
                os.mkdir(os.path.join(RULES_PATH, lan))

            rule_lan_path = os.path.join(RULES_PATH, lan)
            svid = rule.svid

            rule_path = os.path.join(rule_lan_path, "CVI_{}.py".format(svid))

            if os.path.exists(rule_path):
                logger.warning("[INIT][Recover] Rule file CVI_{}.py exist. whether overwrite file? (Y/N)".format(svid))

                if input().lower() == 'n':
                    continue

            logger.info("[INIT][Recover] Recover new Rule file CVI_{}.py".format(svid))

            template_file = codecs.open(os.path.join(RULES_PATH, 'rule.template'), 'rb+', encoding='utf-8', errors='ignore')
            template_file_content = template_file.read()
            template_file.close()

            rule_file = codecs.open(rule_path, "wb+", encoding='utf-8', errors='ignore')

            rule_name = rule.rule_name
            svid = rule.svid
            language = rule.language
            author = rule.author
            description = rule.description
            level = rule.level
            status = "True" if rule.status else "False"
            match_mode = rule.match_mode
            match = file_output_format(rule.match)
            match_name = file_output_format(rule.match_name)
            black_list = file_output_format(rule.black_list)
            keyword = file_output_format(rule.keyword)
            unmatch = file_output_format(rule.unmatch)
            vul_function = file_output_format(rule.vul_function)
            main_function = rule.main_function

            rule_file.write(template_file_content.format(rule_name=rule_name, svid=svid, language=language,
                                                         author=author, description=description, level=level, status=status,
                                                         match_mode=match_mode, match=match, match_name=match_name,
                                                         black_list=black_list, keyword=keyword, unmatch=unmatch,
                                                         vul_function=vul_function, main_function=main_function))

            rule_file.close()


class TamperCheck:
    """
    tamper检查
    """
    def __init__(self):
        self.tamper_list = []
        self.tamper_dict = {}

        self.tamper_base_path = os.path.join(RULES_PATH, "tamper")

    def check_and_update_tamper(self, tamperclass, new_tamper_value):

        tam_name = tamperclass.tam_name
        tam_key = tamperclass.tam_key
        tam_value = tamperclass.tam_value

        if str(tam_value) != str(new_tamper_value):
            logger.warning("[INIT][Tamper Check] Tamper for {} function {} has changed:".format(tam_name, tam_key))
            logger.warning("[INIT][Tamper Check] {} in Tamper File is {}".format(tam_key, tam_value))
            logger.warning("[INIT][Tamper Check] {} in Database is {}".format(tam_key, new_tamper_value))

            logger.warning("[INIT][Tamper Check] whether load new {} from Tamper File(Y/N):".format(tam_key))
            if input().lower() != 'n':
                tamperclass.tam_value = new_tamper_value

        tamperclass.save()
        return True

    def load(self):

        self.tamper_list = list_parse(self.tamper_base_path, True)

        for tamper in self.tamper_list:
            tamper_name = tamper.split('.')[0]
            tamper_file = "rules.tamper." + tamper_name

            tamper_obj = __import__(tamper_file, fromlist=tamper_name)

            filter_func = getattr(tamper_obj, tamper_name)
            input_control = getattr(tamper_obj, tamper_name + "_controlled")

            if filter_func:
                for function in filter_func:
                    t = Tampers.objects.filter(tam_name=tamper_name, tam_type="Filter-Function",
                                               tam_key=function).first()

                    if not t:
                        logger.info("[INIT][Load Tamper] New Tamper for {} function {}.".format(tamper_name, function))

                        t1 = Tampers(tam_name=tamper_name, tam_type="Filter-Function",
                                     tam_key=function, tam_value=filter_func[function])

                        t1.save()

                    else:
                        logger.info("[INIT][Load Tamper] Check Tamper for {} function {}.".format(tamper_name, function))

                        self.check_and_update_tamper(t, filter_func[function])

            if input_control:
                for input in input_control:
                    t = Tampers.objects.filter(tam_name=tamper_name, tam_type="Input-Control",
                                               tam_key=tamper_name, tam_value=input).first()

                    if not t:
                        logger.info("[INIT][Load Tamper] New Tamper for {} Input {}.".format(tamper_name, input))

                        t1 = Tampers(tam_name=tamper_name, tam_type="Input-Control",
                                     tam_key=tamper_name, tam_value=input)

                        t1.save()

                    else:
                        logger.info("[INIT][Load Tamper] Check Tamper for {} Input {}.".format(tamper_name, input))

                        self.check_and_update_tamper(t, input)

        return True

    def recover(self):

        self.tamper_dict = {}
        tampers = Tampers.objects.all()

        for tamper in tampers:
            if tamper.tam_name not in self.tamper_dict:
                self.tamper_dict[tamper.tam_name] = {"Input-Control": [], "Filter-Function": {}}

            if tamper.tam_type == "Input-Control":
                self.tamper_dict[tamper.tam_name][tamper.tam_type].append(tamper.tam_value)

            if tamper.tam_type == "Filter-Function":
                self.tamper_dict[tamper.tam_name][tamper.tam_type][tamper.tam_key] = tamper.tam_value

        # mkdir tamper
        if not os.path.isdir(os.path.join(RULES_PATH, 'tamper')):
            os.mkdir(os.path.join(RULES_PATH, "tamper"))

        tampers_path = os.path.join(RULES_PATH, "tamper")

        for tamper_name in self.tamper_dict:

            tamper_path = os.path.join(tampers_path, "{}.py".format(tamper_name))

            if os.path.exists(tamper_path):
                logger.warning("[INIT][Recover] Tamper file {}.py exist. whether overwrite file? (Y/N)".format(tamper_name))

                if input().lower() == 'n':
                    continue

            logger.info("[INIT][Recover] Recover new Tamper file {}.py".format(tamper_name))

            template_file = codecs.open(os.path.join(RULES_PATH, 'tamper.template'), 'rb+', encoding='utf-8',
                                        errors='ignore')
            template_file_content = template_file.read()
            template_file.close()

            tamper_file = codecs.open(tamper_path, "wb+", encoding='utf-8', errors='ignore')

            tam_name = tamper_name
            filter_function = self.tamper_dict[tamper_name]["Filter-Function"]
            input_control = self.tamper_dict[tamper_name]["Input-Control"]

            tamper_file.write(template_file_content.format(tam_name=tam_name,
                                                           filter_function=filter_function,
                                                           input_control=input_control))

            tamper_file.close()

        return True
