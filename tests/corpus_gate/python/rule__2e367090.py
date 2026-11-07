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
import sys
import importlib
import inspect
import codecs
from Kunlun_M.settings import RULES_PATH

from utils.log import logger
from utils.utils import file_output_format

from web.index.models import Rules, FrameworkTamper


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
    def __init__(self, lans=None):
        if lans is None:
            lans = []
        elif isinstance(lans, str):
            lans = [lans]
        else:
            lans = list(lans)

        self.lans = list(lans)
        origin_lans = ["base"]
        origin_lans.extend(self.lans)

        # 语言别名映射：javascript 同时扫描 rules/nodejs/ 目录
        _lan_aliases = {
            "javascript": ["nodejs"],
        }

        self.rule_dict = {}

        # 逐个处理每一种lan
        for lan in origin_lans:
            # 主目录
            dirs_to_scan = [lan]
            # 别名目录
            dirs_to_scan.extend(_lan_aliases.get(lan, []))

            for dir_name in dirs_to_scan:
                self.rules_path = RULES_PATH + "/" + dir_name
                if not os.path.exists(self.rules_path):
                    if dir_name == lan:
                        logger.error("[INIT][RULE] language {} can't found rules".format(self.rules_path))
                        os.mkdir(self.rules_path)
                    continue

                self.rule_list = self.list_parse()

                for rule in self.rule_list:
                    rulename = rule.split('.')[0]
                    rulefile = "rules." + dir_name + "." + rulename

                    try:
                        self.rule_dict[rulename] = __import__(rulefile, fromlist=rulename)
                    except Exception as e:
                        logger.error("[INIT][RULE] Failed to load rule {}: {}".format(rulename, e))

        self.vulnerabilities = self.vul_init()

    def reload(self):
        """热加载规则文件，无需重启扫描进程。

        对已导入的规则模块调用 importlib.reload() 获取最新代码，
        同时扫描目录以支持新增或删除的规则文件。
        如果某个规则文件存在语法错误，会记录日志并跳过，不影响其他规则的加载。

        :return: 重新加载的规则数量
        :rtype: int

        用法::

            r = Rule(["php"])
            # ... 修改了规则文件 ...
            count = r.reload()
            print(f"已重新加载 {count} 条规则")
        """
        # 语言别名映射：javascript 同时扫描 rules/nodejs/ 目录
        _lan_aliases = {
            "javascript": ["nodejs"],
        }

        origin_lans = ["base"]
        origin_lans.extend(self.lans)

        old_rule_dict = self.rule_dict
        self.rule_dict = {}
        count = 0

        for lan in origin_lans:
            # 主目录
            dirs_to_scan = [lan]
            # 别名目录
            dirs_to_scan.extend(_lan_aliases.get(lan, []))

            for dir_name in dirs_to_scan:
                self.rules_path = RULES_PATH + "/" + dir_name
                if not os.path.exists(self.rules_path):
                    if dir_name == lan:
                        logger.error("[RELOAD][RULE] language {} can't found rules".format(self.rules_path))
                    continue

                self.rule_list = self.list_parse()

                for rule in self.rule_list:
                    rulename = rule.split('.')[0]
                    rulefile = "rules." + dir_name + "." + rulename

                    try:
                        # 对已导入的模块执行 reload，新模块直接 import
                        if rulename in old_rule_dict:
                            module = old_rule_dict[rulename]
                            module = importlib.reload(module)
                            self.rule_dict[rulename] = module
                        else:
                            self.rule_dict[rulename] = __import__(rulefile, fromlist=rulename)

                        count += 1
                    except Exception as e:
                        logger.error("[RELOAD][RULE] Failed to load rule {}: {}".format(rulename, e))
                        # 如果 reload 失败，尝试保留旧版本
                        if rulename in old_rule_dict:
                            self.rule_dict[rulename] = old_rule_dict[rulename]
                            logger.warning("[RELOAD][RULE] Keeping previous version of rule {}".format(rulename))

        self.vulnerabilities = self.vul_init()
        logger.info("[RELOAD][RULE] Reloaded {} rules, total {} rules loaded".format(count, len(self.rule_dict)))
        return count

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
            if f.startswith("CVI_") and f.endswith(".py"):
                result.append(f)

        return sorted(result)

    def vul_init(self):

        vul_list = []

        for rulename in self.rule_dict:
            p = getattr(self.rule_dict[rulename], rulename)

            ruleclass = p()
            vul_list.append(ruleclass.vulnerability)

        return sorted(list(set(vul_list)))


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
        main_function_content = ""
        _main = getattr(ruleclass, "main", None)
        if callable(_main):
            try:
                main_function_content = inspect.getsource(_main)
            except Exception:
                main_function_content = ""
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

        match = getattr(ruleclass, 'match', '') or ''
        r = Rules(rule_name=ruleclass.vulnerability, svid=ruleclass.svid,
                  language=ruleclass.language.lower(), author=ruleclass.author,
                  description=ruleclass.description, level=ruleclass.level, status=ruleclass.status,
                  match_mode=ruleclass.match_mode, match=match,
                  match_name=match_name, black_list=black_list, unmatch=unmatch, keyword=keyword,
                  vul_function=ruleclass.vul_function, main_function=main_function_content)

        r.save()

        return True

    def check_and_update_rule_database(self, ruleconfig_content, nowrule, config):

        svid = nowrule.svid
        ruleconfig_content = str(ruleconfig_content)

        if ruleconfig_content.lower() != str(getattr(nowrule, config)).lower():
            # 无感同步：文件内容自动覆盖数据库
            logger.debug("[INIT][Rule Check] Sync CVI_{} config {} from file".format(svid, config))
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

                is_changed = self.check_and_update_rule_database(ruleconfig_content, nowrule, config1) or is_changed

            else:
                main_function_content = ""
                _main = getattr(ruleclass, "main", None)
                if callable(_main):
                    try:
                        main_function_content = inspect.getsource(_main)
                    except Exception:
                        main_function_content = ""
                config1 = "main_function"

                is_changed = self.check_and_update_rule_database(main_function_content, nowrule, config1) or is_changed

        # for special match_mode
        if ruleclass.match_mode == "regex-return-regex":
            for config in self.SOLIDITY_CONFIG_LIST:
                is_changed = self.check_and_update_rule_database(getattr(ruleclass, config), nowrule, config) or is_changed
        elif ruleclass.match_mode == "only-regex":
            for config in self.REGEX_CONFIG_LIST:
                is_changed = self.check_and_update_rule_database(getattr(ruleclass, config), nowrule, config) or is_changed
        elif ruleclass.match_mode == "special-crx-keyword-match":
            for config in self.CHROME_CONFIG_LIST:
                is_changed = self.check_and_update_rule_database(getattr(ruleclass, config), nowrule, config) or is_changed

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
                    logger.debug("[INIT][Load Rules] Check Rule CVI_{} {}".format(ruleclass.svid, ruleclass.vulnerability))

                    self.check_rules(ruleclass, r)

        return True

    def export(self):
        """
        export rules from database to files
        """
        from core.scaffold import render_rule

        rules = Rules.objects.all()
        for rule in rules:
            lan = rule.language
            lan_dir = os.path.join(self.rule_base_path, lan)
            if not os.path.isdir(lan_dir):
                os.makedirs(lan_dir, exist_ok=True)

            svid = rule.svid
            rule_path = os.path.join(lan_dir, "CVI_{}.py".format(svid))

            if os.path.exists(rule_path):
                logger.info("[INIT][Export] Rule CVI_{}.py already exists, skipped.".format(svid))
                continue

            logger.info("[INIT][Export] Export rule CVI_{} {} (language: {})".format(svid, rule.rule_name, lan))

            content = render_rule(
                svid=int(svid),
                language=lan,
                rule_name=rule.rule_name,
                author=rule.author,
                description=rule.description,
                level=rule.level,
                status=rule.status,
                match_mode=rule.match_mode,
                match=rule.match,
                match_name=rule.match_name,
                black_list=rule.black_list,
                keyword=rule.keyword,
                unmatch=rule.unmatch,
                vul_function=rule.vul_function,
                main_function=rule.main_function,
            )

            with codecs.open(rule_path, "w", encoding="utf-8") as f:
                f.write(content)


class TamperCheck:
    """
    tamper检查
    """
    def __init__(self):
        self.tamper_list = []
        self.tamper_dict = {}

        self.tamper_base_path = os.path.join(RULES_PATH, "tamper")

    def _migrate_legacy_files(self):
        """
        兼容迁移：将根目录下的旧版扁平 tamper 文件自动迁移到对应语言子目录。
        旧版文件格式：flask = {...} / flask_controlled = []（Format-1）
        迁移规则：
        - 目标子目录已有同名新版文件时：直接删除根目录旧文件
        - 目标子目录无同名文件时：将旧数据转换为新版格式写入子目录，再删除根目录旧文件
        """
        from rules.tamper._compat import (is_legacy_tamper_file, _infer_language_from_svids,
                                           _infer_language_from_controlled, wrap_legacy_module)
        import importlib.util

        for fname in sorted(os.listdir(self.tamper_base_path)):
            filepath = os.path.join(self.tamper_base_path, fname)
            if not os.path.isfile(filepath) or not fname.endswith('.py'):
                continue
            if fname.startswith('_') or fname.startswith('demo'):
                continue

            is_legacy, name = is_legacy_tamper_file(filepath)
            if not is_legacy:
                continue

            # 加载并包装旧版模块
            try:
                spec = importlib.util.spec_from_file_location('_legacy_{}'.format(name), filepath)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                repair_dict = getattr(mod, name, {})
                all_svids = []
                for svids in repair_dict.values():
                    if isinstance(svids, (list, tuple)):
                        all_svids.extend(svids)

                language = _infer_language_from_svids(all_svids)
                if not language:
                    controlled = getattr(mod, name + '_controlled', [])
                    language = _infer_language_from_controlled(controlled)
                if not language:
                    language = 'php'

                wrapped = wrap_legacy_module(mod, name, language, filepath)
            except Exception as e:
                logger.warning("[INIT][Tamper Migrate] Failed to process legacy {}: {}".format(fname, e))
                continue

            target_dir = os.path.join(self.tamper_base_path, language)
            target_path = os.path.join(target_dir, fname)

            if os.path.exists(target_path):
                # 新版文件已存在，直接删除旧文件
                logger.info("[INIT][Tamper Migrate] New file exists at {}/{}, removing legacy {}".format(language, fname, fname))
                os.remove(filepath)
            else:
                # 将旧数据转换为新版格式写入子目录
                os.makedirs(target_dir, exist_ok=True)

                lines = [
                    "# -*- coding: utf-8 -*-",
                    "# Auto-migrated from legacy tamper format",
                    "import os",
                    "",
                    "FRAMEWORK_NAME = '{}'".format(wrapped.FRAMEWORK_NAME),
                    "DEPENDENCIES = {}",
                    "",
                    "def detect(project_dir, language='{}'):".format(language),
                    '    """检测是否为 {} 项目"""'.format(wrapped.FRAMEWORK_NAME),
                    "    return False",
                    "",
                ]

                if wrapped.FILTER_FUNCTIONS:
                    lines.append("")
                    lines.append("FILTER_FUNCTIONS = {")
                    for func_name, func_value in sorted(wrapped.FILTER_FUNCTIONS.items()):
                        lines.append("    {}: {},".format(repr(func_name), repr(func_value)))
                    lines.append("}")

                if wrapped.EXTRA_SINKS:
                    lines.append("")
                    lines.append("EXTRA_SINKS = [")
                    for item in wrapped.EXTRA_SINKS:
                        lines.append("    ({}, {}),".format(repr(item[0]), repr(item[1])))
                    lines.append("]")

                if wrapped.CONTROLLED_SOURCES:
                    lines.append("")
                    lines.append("CONTROLLED_SOURCES = [")
                    for source in wrapped.CONTROLLED_SOURCES:
                        lines.append("    {},".format(repr(source)))
                    lines.append("]")
                else:
                    lines.append("")
                    lines.append("CONTROLLED_SOURCES = []")

                content = "\n".join(lines) + "\n"
                with codecs.open(target_path, "w", encoding="utf-8") as f:
                    f.write(content)

                os.remove(filepath)
                logger.info("[INIT][Tamper Migrate] Converted & migrated {} -> {}/{}".format(fname, language, fname))

    def load(self):
        """
        加载 tamper 文件到数据库（FrameworkTamper 表）。
        扫描 rules/tamper/<language>/<framework>.py 子目录结构。
        同时兼容旧版：自动迁移根目录下的扁平旧文件到对应语言子目录。
        """
        import inspect

        # === 兼容迁移：将根目录旧版扁平 tamper 文件迁移到语言子目录 ===
        self._migrate_legacy_files()

        language_dirs = [d for d in os.listdir(self.tamper_base_path)
                         if os.path.isdir(os.path.join(self.tamper_base_path, d))
                         and not d.startswith('_') and d != '__pycache__']

        active_names = set()

        for lang in sorted(language_dirs):
            lang_dir = os.path.join(self.tamper_base_path, lang)
            if not os.path.isdir(lang_dir):
                continue

            for fname in sorted(os.listdir(lang_dir)):
                if not fname.endswith('.py') or fname.startswith('_'):
                    continue

                tamper_name = fname[:-3]
                module_path = "rules.tamper.{}.{}".format(lang, tamper_name)

                try:
                    tamper_obj = __import__(module_path, fromlist=[tamper_name])
                except Exception as e:
                    logger.warning("[INIT][Load Tamper] Failed to import {}: {}".format(module_path, e))
                    continue

                active_names.add(tamper_name)

                framework_name = getattr(tamper_obj, 'FRAMEWORK_NAME', tamper_name)
                dependencies = getattr(tamper_obj, 'DEPENDENCIES', {})
                filter_functions = getattr(tamper_obj, 'FILTER_FUNCTIONS', {})
                extra_sinks = getattr(tamper_obj, 'EXTRA_SINKS', [])
                controlled_sources = getattr(tamper_obj, 'CONTROLLED_SOURCES', [])

                # 提取 detect 函数源码
                detect_code = ''
                detect_fn = getattr(tamper_obj, 'detect', None)
                if detect_fn:
                    try:
                        detect_code = inspect.getsource(detect_fn)
                    except Exception:
                        pass

                FrameworkTamper.objects.update_or_create(
                    name=tamper_name,
                    defaults={
                        'language': lang,
                        'framework_name': framework_name,
                        'dependencies': dependencies,
                        'filter_functions': filter_functions,
                        'extra_sinks': extra_sinks,
                        'controlled_sources': controlled_sources,
                        'detect_code': detect_code,
                    }
                )

        # 注意：不做 stale 清理，与 RuleCheck.load() 保持一致。
        # 如果用户删除了 tamper 文件但 DB 中仍存在，可通过手动操作清理。

        return True

    def export(self):
        """
        export tampers from database to files (new format: rules/tamper/<language>/<name>.py)
        """
        tampers_path = os.path.join(RULES_PATH, "tamper")
        if not os.path.isdir(tampers_path):
            os.makedirs(tampers_path, exist_ok=True)

        for ft in FrameworkTamper.objects.all().order_by("name"):
            language = ft.language
            lang_dir = os.path.join(tampers_path, language)
            if not os.path.isdir(lang_dir):
                os.makedirs(lang_dir, exist_ok=True)

            tamper_path = os.path.join(lang_dir, "{}.py".format(ft.name))

            if os.path.exists(tamper_path):
                logger.info("[INIT][Export] Tamper {}.py already exists in {}/, skipped.".format(ft.name, language))
                continue

            logger.info("[INIT][Export] Export tamper {} (language: {})".format(ft.name, language))

            # 生成新版格式文件
            lines = [
                "# -*- coding: utf-8 -*-",
                "import os",
                "",
                "FRAMEWORK_NAME = '{}'".format(ft.framework_name or ft.name.capitalize()),
                "DEPENDENCIES = {}".format(repr(ft.dependencies) if ft.dependencies else '{}'),
                "",
            ]

            # detect 函数
            if ft.detect_code:
                lines.append("")
                lines.append(ft.detect_code.rstrip())
            else:
                lines.append("")
                lines.append("def detect(project_dir, language='{}'):".format(language))
                lines.append('    """检测是否为 {} 项目"""'.format(ft.framework_name or ft.name.capitalize()))
                lines.append("    return False")

            # Filter-Functions
            if ft.filter_functions:
                lines.append("")
                lines.append("FILTER_FUNCTIONS = {")
                for func_name, func_value in sorted(ft.filter_functions.items()):
                    lines.append("    {}: {},".format(repr(func_name), repr(func_value)))
                lines.append("}")

            # Extra-Sinks
            if ft.extra_sinks:
                lines.append("")
                lines.append("EXTRA_SINKS = [")
                for item in ft.extra_sinks:
                    lines.append("    ({}, {}),".format(repr(item[0]), repr(item[1])))
                lines.append("]")

            # Controlled-Sources
            if ft.controlled_sources:
                lines.append("")
                lines.append("CONTROLLED_SOURCES = [")
                for source in ft.controlled_sources:
                    lines.append("    {},".format(repr(source)))
                lines.append("]")
            else:
                lines.append("")
                lines.append("CONTROLLED_SOURCES = []")

            content = "\n".join(lines) + "\n"

            with codecs.open(tamper_path, "w", encoding="utf-8") as f:
                f.write(content)
