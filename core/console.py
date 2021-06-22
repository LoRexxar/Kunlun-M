#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: console.py
@time: 2020/8/25 11:32
@desc:

'''

import os
import sys
import ast
import glob
import time
import codecs
import atexit
import pprint
import traceback
import logging
from functools import wraps
from prettytable import PrettyTable

from django.db.models import Q, QuerySet
from django.db.models.aggregates import Max

from utils.log import logger, logger_console, log, log_add
from utils import readlineng as readline
from utils.utils import get_mainstr_from_filename, get_scan_id, file_output_format, show_context

from Kunlun_M.settings import HISTORY_FILE_PATH, MAX_HISTORY_LENGTH
from Kunlun_M.settings import RULES_PATH, PROJECT_DIRECTORY, LOGS_PATH

from core.__version__ import __introduction__
from core import cli
from core.engine import Running

from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc
from web.index.models import get_resultflow_class, get_dataflow_class


def readline_available():
    """
    Check if the readline is available. By default
    it is not in Python default installation on Windows
    """

    return readline._readline is not None



def clear_history():
    if not readline_available():
        return

    readline.clear_history()


def save_history():
    if not readline_available():
        return

    history_path = HISTORY_FILE_PATH

    try:
        with open(history_path, "w+"):
            pass
    except Exception:
        pass

    readline.set_history_length(MAX_HISTORY_LENGTH)
    try:
        readline.write_history_file(history_path)
    except IOError as msg:
        warn_msg = "there was a problem writing the history file '{0}' ({1})".format(history_path, msg)
        logger.warn(warn_msg)


def load_history():
    if not readline_available():
        return

    clear_history()

    history_path = HISTORY_FILE_PATH

    if os.path.exists(history_path):
        try:
            readline.read_history_file(history_path)
        except IOError as msg:
            warn_msg = "there was a problem loading the history file '{0}' ({1})".format(history_path, msg)
            logger.warn(warn_msg)


def auto_completion(completion=None, console=None):
    if not readline_available():
        return

    readline.set_completer_delims(" ")
    readline.set_completer(console)
    readline.parse_and_bind("tab: complete")

    load_history()
    atexit.register(save_history)


def stop_after(space_number):
    """ Decorator that determines when to stop tab-completion
    Decorator that tells command specific complete function
    (ex. "complete_use") when to stop tab-completion.
    Decorator counts number of spaces (' ') in line in order
    to determine when to stop.
        ex. "use exploits/dlink/specific_module " -> stop complete after 2 spaces
        "set rhost " -> stop completing after 2 spaces
        "run " -> stop after 1 space
    :param space_number: number of spaces (' ') after which tab-completion should stop
    :return:
    """

    def _outer_wrapper(wrapped_function):
        @wraps(wrapped_function)
        def _wrapper(self, *args, **kwargs):
            try:
                if args[1].count(" ") == space_number:
                    return []
            except Exception as err:
                logger.error(err)
            return wrapped_function(self, *args, **kwargs)

        return _wrapper

    return _outer_wrapper


class BaseInterpreter(object):
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""
        self.complete = None
        self.subcommand_list = []

    def setup(self):
        """ Initialization of third-party libraries
        Setting interpreter history.
        Setting appropriate completer function.
        :return:
        """
        auto_completion(completion=4, console=self.complete)

    def parse_line(self, line):
        """ Split line into command and argument.
        :param line: line to parse
        :return: (command, argument)
        """
        command, _, arg = line.strip().partition(" ")
        return command, arg.strip()

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.
        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            logger.error("Unknown command: '{}'".format(command))
            return False

        return command_handler

    def start(self):
        """ Routersploit main entry point. Starting interpreter loop. """

        logger_console.info(self.global_help)
        while True:
            try:
                command, args = self.parse_line(input(self.prompt))
                command = command.lower()
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args)
            except EOFError:
                logger.info("KunLun-M Console mode stopped")
                break
            except KeyboardInterrupt:
                logger.info("Console Exit")
                break
            except:
                logger.error("[Console] {}".format(traceback.format_exc()))

    def complete(self, text, state):
        """Return the next possible completion for 'text'.
        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args = self.parse_line(line)
                if cmd == "":
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, "complete_" + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)
        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.
        :param ignored:
        :return: full list of interpreter commands
        """
        command_list = [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

        # command_list.extend(self.subcommand_list)
        return command_list

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return [command for command in self.suggested_commands() if command.startswith(text)]

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.
        Overwrite this method to suggest suitable commands.
        :return: list of suitable commands
        """
        return self.commands()


class KunlunInterpreter(BaseInterpreter):
    """
    console mode for kunlun-m
    """
    global_help = __introduction__.format(detail="""Global commands:
    help                                             Print this help menu
    scan                                             Enter the scan mode
    load <scan_id>                                   Load Scan task
    showt                                            Show all Scan task list
    show [rule, tamper] <key>                        Show rules or tampers
    config [rule, tamper] <rule_id> | <tamper_name>  Config mode for rule & tamper
    exit                                             Exit KunLun-M & save Config""")

    config_rule_help = """Config Rule commands:
    help                          Print this help menu
    showit                        Show All config
    set <option name> <value>     Set Rule option
    cancel                        Cancel last set
    save                          Save option
    back                          Back to the root list 
    """

    config_tamper_help = """Config Tamper commands:
    help                          Print this help menu
    showit                        Show All config
    add <option name> <value>     Add tamper option
    cancel                        Cancel last set
    save                          Save option
    back                          Back to the root list 
    """

    scan_help = """Scan commands:
    help                            Print this help menu
    set <option name> <value>       Set scan option
    status                          Get Task status
    run                             Run Task with the given options
    back                            Back to the root list 
    """

    result_help = """Result Commands:
    help                                      Print this help menu
    show [vuls, newevilfunc, options] <result_id> | <option_name> <option_value>
                                              Show result vuls/new evil func with option or show display option
    del [vuls, newevilfunc] <result_id>       Del result id
    set <option_name> <option_value>          Config for show mode
    check_log                                 Open log file
    back                                      Back to the root list 
    """

    def __init__(self):
        super(KunlunInterpreter, self).__init__()

        self.prompt_hostname = "KunLun-M"
        self.current_mode = 'root'

        self.global_commands = ['help', 'scan', 'load ', 'showt', 'show ', 'config ', 'exit']
        self.config_commands = ['help', 'set ', 'save', 'back', 'showit']
        self.scan_commands = ['help', 'set ', 'show ', 'run', 'status']
        self.result_commands = ['help', 'show ', 'del ', 'set ', 'back']

        self.subcommand_root_list = ['rule', 'tamper']
        self.subcommand_result_list = ['options', 'vuls', 'newevilfunc']
        self.subcommand_list = ['options', 'vuls', 'rule', 'tamper', 'newevilfunc']

        self.show_index = 0
        self.show_mode_list = ['showt']
        self.show_commands = ['n']
        self.show_mode = ""
        self.show_mode_list = ['rule']

        self.config_mode = ""
        self.config_keyword = ""
        self.config_dict = {}
        self.config_obj = None
        self.last_config = {}
        self.rule_filecontent = ""
        self.configurable_options = ['status', 'match_mode', 'match', 'match_name', 'black_list', 'keyword', 'unmatch', 'vul_function']

        self.result_task_id = None
        self.result_obj = None
        self.result_options = {
            "cvi_id": "all",
            "language": "all",
            "active_vul": True,
            "get_unconfirm": True,
            "result_type": "all",
        }
        self.result_option_list = {
            "cvi_id": ["all", "<CVI_id>"],
            "language": ["all", "<language>"],
            "result_type": ["all", "<result_type>"],
            "active_vul": [True, False, 'all'],
            "get_unconfirm": [True, False, 'only'],
        }

        self.scan_options = {
            "target": None,
            "format": 'csv',
            "output": None,
            "rule_id": "all",
            "tamper": None,
            "log_name": None,
            "language": None,
            "black_path": None,
            "is_debug": True,
            "is_without_precom": False,
        }
        self.scan_option_list = {
            "target": ["<target_path>"],
            "format": ['csv', 'json', 'csv', 'xml'],
            "output": ["<output>"],
            "rule_id": ["all", "<CVI_ID>"],
            "tamper": ['<tamper_name>'],
            "log_name": ['<logfile_name>'],
            "language": [None, 'php', 'javascript', 'solidity'],
            "black_path": ['<black_path>'],
            "is_debug": [False, True],
            "is_without_precom": [False, True],
        }
        self.scan_option_help = {
            "target": "file, folder",
            "format": "vulnerability output format",
            "output": "vulnerability output STREAM, FILE",
            "rule_id": "specifies rules ",
            "tamper": "tamper repair function",
            "log_name": "log file name",
            "language": "set target language",
            "black_path": "black path list",
            "is_debug": "open debug mode",
            "is_without_precom": "without Precompiled. for quick only regex scan",
        }
        self.scan_short_options = {
            "target": 't',
            "format": 'f',
            "output": 'o',
            "rule_id": 'r',
            "tamper": 'tp',
            "log_name": 'l',
            "language": 'lan',
            "black_path": 'b',
            "is_debug": 'd',
            "is_without_precom": 'upc',
        }

        self.scan_required_options_list = ["target"]

        self.__parse_prompt()

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        self.raw_prompt_template = raw_prompt_default_template
        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        self.module_prompt_template = module_prompt_default_template

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.
        Adding module prefix (module.name) if current_module attribute is set.
        :return: prompt string with appropriate module prefix.
        """
        if self.current_mode:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname,
                                                          module=self.current_mode)
            except (AttributeError, KeyError):
                return self.module_prompt_template.format(host=self.prompt_hostname, module="UnnamedModule")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def clear_args(self, args):
        new_arg_list = []
        arg_list = args.split(" ")
        temp_str = None
        temp_sign = None

        for arg in arg_list:
            if arg:
                # 如果temp_str 和 temp_sign
                if temp_str and temp_sign:
                    if arg[-1] == temp_sign:
                        arg = temp_str + " " + arg[:-1]

                        temp_str = None
                        temp_sign = None
                    else:
                        temp_str += " "
                        temp_str += arg
                        continue

                if arg[0] in ['"', "'"]:
                    temp_str = arg[1:]
                    temp_sign = arg[0]

                    # 如果剩下的字符里没有闭合该引号，那继续读取下一个
                    if temp_sign not in temp_str:
                        continue
                    else:
                        new_arg_list.append(temp_str[:-1])
                else:
                    new_arg_list.append(arg)

        return new_arg_list

    def command_help(self, *args, **kwargs):
        if self.current_mode == 'config':
            if self.config_mode == 'rule':
                logger_console.info(self.config_rule_help)
            elif self.config_mode == 'tamper':
                logger_console.info(self.config_tamper_help)
        elif self.current_mode == 'scan':
            logger_console.info(self.scan_help)
        elif self.current_mode == 'result':
            logger_console.info(self.result_help)
        else:
            self.current_mode = 'root'
            logger_console.info(self.global_help)

    def command_back(self, *args, **kwargs):
        self.current_mode = 'root'

        self.show_mode = ""
        self.config_mode = ""
        self.config_keyword = ""
        self.last_config = {}

        logger_console.info(self.global_help)

    def command_scan(self, *args, **kwargs):
        self.current_mode = 'scan'
        os.chdir(PROJECT_DIRECTORY)

        # set log
        self.scan_options['log_name'] = self.check_scan_log_file()

        logger_console.info(self.scan_help)

    def command_exit(self, *args, **kwargs):
        raise EOFError

    def show_task(self, count=10):
        sts = ScanTask.objects.all().order_by('-id')

        # self.show_index = 0
        index = 0
        sts_table = PrettyTable(
            ['id', 'TaskName', 'Parameter', 'Scan_Time', 'Is_finished'])
        sts_table.align = 'l'

        if sts:
            for st in sts:

                if st:
                    if self.show_index <= index < count:
                        self.show_index += 1
                        parameter_config = " ".join(ast.literal_eval(st.parameter_config)).replace('\\', '/')

                        sts_table.add_row(
                            [st.id, st.task_name, parameter_config, str(st.last_scan_time)[:19], st.is_finished])

                    index += 1

            logger.info("[Console] Show Scan Task list:\n{}".format(sts_table))

            logger.warn("[Console] Now You can Enter N show Next 10 Tasks.")
        else:
            logger.warn("[Console] Now have no Scan Task.")

    def command_showt(self, *args, **kwargs):
        self.current_mode = 'showt'
        self.show_index = 0
        self.show_task(10)

    def command_n(self, *args, **kwargs):
        if self.current_mode not in self.show_mode_list:
            logger.warn("[Console] Command N only for show mode.")
            return

        if self.current_mode == 'showt':
            self.show_task(self.show_index + 10)

    def show_rule_by_id(self, rule_id):
        rule = Rules.objects.filter(svid=rule_id).first()

        if rule:
            template_file = codecs.open(os.path.join(RULES_PATH, 'rule.template'), 'rb+', encoding='utf-8',
                                        errors='ignore')
            template_file_content = template_file.read()
            template_file.close()

            rule_name = rule.rule_name
            svid = rule.svid
            language = rule.language
            author = rule.author
            description = rule.description
            status = "True" if rule.status else "False"
            match_mode = rule.match_mode
            match = file_output_format(rule.match)
            match_name = file_output_format(rule.match_name)
            black_list = file_output_format(rule.black_list)
            keyword = file_output_format(rule.keyword)
            unmatch = file_output_format(rule.unmatch)
            vul_function = file_output_format(rule.vul_function)
            main_function = rule.main_function

            logger.info("[Console] Rule CVI_{} Detail:\n{}".format(svid, template_file_content.format(
                rule_name=rule_name, svid=svid, language=language,
                author=author, description=description, status=status,
                match_mode=match_mode, match=match,
                match_name=match_name,
                black_list=black_list, keyword=keyword,
                unmatch=unmatch,
                vul_function=vul_function,
                main_function=main_function)))

            logger.warn("[Console] You can edit the Rule by command 'config rule <rule_id>'")
            return

        else:
            logger.error("[Console] Please check Rule id or or use the command 'show rule' to view")

    def load_rule_dict_by_id(self, rule_id):
        rule = Rules.objects.filter(svid=rule_id).first()
        # rule_dict = {}

        if not rule:
            logger.error("[Console] Please check Rule id or or use the command 'show rule' to view")
            return False

        return rule

    def show_rule_by_dict(self, rule):
        if rule:
            template_file = codecs.open(os.path.join(RULES_PATH, 'rule.template'), 'rb+', encoding='utf-8',
                                        errors='ignore')
            template_file_content = template_file.read()
            template_file.close()
            # for rule
            rule_dict = {}

            rule_dict['rule_name'] = rule.rule_name
            rule_dict['svid'] = rule.svid
            rule_dict['language'] = rule.language
            rule_dict['author'] = rule.author
            rule_dict['description'] = rule.description
            rule_dict['status'] = "True" if rule.status else "False"
            rule_dict['match_mode'] = rule.match_mode
            rule_dict['match'] = file_output_format(rule.match)
            rule_dict['match_name'] = file_output_format(rule.match_name)
            rule_dict['black_list'] = file_output_format(rule.black_list)
            rule_dict['keyword'] = file_output_format(rule.keyword)
            rule_dict['unmatch'] = file_output_format(rule.unmatch)
            rule_dict['vul_function'] = file_output_format(rule.vul_function)
            rule_dict['main_function'] = rule.main_function

            self.rule_filecontent = template_file_content.format(
                rule_name=rule_dict['rule_name'], svid=rule_dict['svid'], language=rule_dict['language'],
                author=rule_dict['author'], description=rule_dict['description'], status=rule_dict['status'],
                match_mode=rule_dict['match_mode'], match=rule_dict['match'],
                match_name=rule_dict['match_name'],
                black_list=rule_dict['black_list'], keyword=rule_dict['keyword'],
                unmatch=rule_dict['unmatch'],
                vul_function=rule_dict['vul_function'],
                main_function=rule_dict['main_function'])

            logger.info("[Console] Rule CVI_{} Detail:\n{}".format(rule_dict['svid'], self.rule_filecontent))

            logger.warn("[Console] This is currently a temporary file, you must use Command 'save' to save")
            return

        else:
            logger.error("[Console] Please check Rule id or or use the command 'show rule' to view")

    def show_tamper_by_dict(self, tamper_dict):
        if tamper_dict:

            filter_func = self.config_dict['filter_func']
            input_control = self.config_dict['input_control']

            logger.info("""\nTamper Name:
    {}

Filter Func:
{}

Input Control:
{}
""".format(self.config_keyword, pprint.pformat(filter_func, indent=4), pprint.pformat(input_control, indent=4)))

            logger.warn("[Console] This is currently a temporary file, you must use Command 'save' to save")
            return

        else:
            logger.error("[Console] Not Found Tampers, Please check command or execute config load.")

    def save_rule_to_file(self):
        """
        save rule content info rule file
        :return:
        """
        self.show_rule_by_dict(self.config_obj)
        lan = self.config_obj.language

        if not os.path.isdir(os.path.join(RULES_PATH, lan)):
            os.mkdir(os.path.join(RULES_PATH, lan))

        rule_lan_path = os.path.join(RULES_PATH, lan)
        svid = self.config_obj.svid

        rule_path = os.path.join(rule_lan_path, "CVI_{}.py".format(svid))

        logger.info("[Console] new Rule file CVI_{}.py init.".format(svid))

        rule_file = codecs.open(rule_path, "wb+", encoding='utf-8', errors='ignore')

        rule_file.write(self.rule_filecontent)
        rule_file.close()
        return True

    def get_scan_results_by_config(self):

        srs = ScanResultTask.objects.filter(scan_task_id=self.result_task_id)
        orm_limit = {}

        if srs:
            for option_name in self.result_options:
                if option_name in ['language', 'result_type', 'active_vul', 'cvi_id']:
                    if self.result_options[option_name] == 'all':
                        continue

                    if option_name == 'active_vul':
                        orm_limit['is_active'] = self.result_options[option_name]

                    else:
                        orm_limit[option_name] = self.result_options[option_name]

                elif option_name == 'get_unconfirm':
                    if self.result_options[option_name] == True:
                        continue
                    elif self.result_options[option_name] == 'only':
                        orm_limit['is_unconfirm'] = True
                    else:
                        orm_limit['is_unconfirm'] = False

            q = Q()
            for i in orm_limit:
                q.add(Q(**{i: orm_limit[i]}), Q.AND)

            # scan_task_id
            q.add(Q(**{"scan_task_id": self.result_task_id}), Q.AND)

            srs = ScanResultTask.objects.filter(q).annotate(max_id=Max('id'))
            return srs

        else:
            return False

    def get_new_evil_func(self, option_name=None, option_value=None):

        nfs = NewEvilFunc.objects.filter(scan_task_id=self.result_task_id)
        orm_limit = {}
        result_list = []

        if nfs:
            if self.result_options['active_vul'] != 'all':
                orm_limit['is_active'] = self.result_options['active_vul']

            q = Q()
            for i in orm_limit:
                q.add(Q(**{i: orm_limit[i]}), Q.AND)

            # scan_task_id
            q.add(Q(**{"scan_task_id": self.result_task_id}), Q.AND)

            nfs = NewEvilFunc.objects.filter(q).annotate(max_id=Max('id'))

            if option_name and option_value:
                for nf in nfs:
                    if option_value in str(getattr(nf, option_name)):
                        result_list.append(nf)

                return result_list
            else:
                return nfs
        else:
            return False

    def check_scan_options(self):
        for option_name in self.scan_options:
            if option_name in self.scan_required_options_list:
                if not self.scan_options[option_name]:
                    logger.error("[Console] Option {} is a required option.You must set it before scanning.".format(option_name))
                    return False

                if option_name == 'target':
                    target = self.scan_options[option_name]

                    if not os.path.exists(target):
                        logger.error("[Console] Target {} is not exist.".format(target))
                        return False

            # all不需要专门限制
            if self.scan_options[option_name] == "all":
                self.scan_options[option_name] = None

        return True

    def check_scan_log_file(self):
        last_scantask = ScanTask.objects.all().order_by('-id').first()

        if last_scantask:
            logfile_name = 'ScanTask_{}'.format(last_scantask.id+1)
        else:
            logfile_name = 'ScanTask_1'

        i = 1
        while os.path.exists(os.path.join(LOGS_PATH, logfile_name+'.log')):
            if '-' not in logfile_name:
                logfile_name += '-{}'.format(i)
            else:
                logfile_name = logfile_name[:-2] + '-{}'.format(i)

        return logfile_name

    def get_sacn_parameters(self):
        parameter_config = ["./kunlun.py"]

        for option_name in self.scan_options:
            if self.scan_options[option_name] is None or self.scan_options[option_name] == 'all' or self.scan_options[option_name] is False:
                continue
            if self.scan_options[option_name] is True:
                parameter_config.append(" -" + self.scan_short_options[option_name])
                continue

            parameter_config.append(" -" + self.scan_short_options[option_name])
            parameter_config.append(" {}".format(self.scan_options[option_name]))

        return parameter_config

    def command_get(self, *args, **kwargs):
        if self.show_mode not in self.show_mode_list:
            logger.warn("[Console] Command Show only for show mode")
            return

        if self.show_mode == 'rule':
            param = self.clear_args(args[0])

            if param:
                key = param[0]
                self.show_rule_by_id(key)
            else:
                logger.error("[Console] You must specify the rule id. e.g.: get 1001")

    def command_set(self, *args, **kwargs):
        if self.current_mode not in ['config', 'result', 'scan']:
            logger.warn("[Console] Command set only for config/result/scan mode")
            return

        if self.current_mode == 'config':
            if self.config_mode == 'rule':
                param = self.clear_args(args[0])

                if len(param) < 2:
                    logger.error("[Console] you must set option name and value. e.g.: set status False")
                    return

                option_name = param[0]
                option_value = param[1]

                option_value = ast.literal_eval(option_value) if option_value in ['True', 'False', 'None'] else option_value

                if option_name not in self.configurable_options:
                    logger.warn("[Console] You can't edit option {}.".format(option_name))
                    return

                # load last profile
                if getattr(self.config_obj, option_name) == option_value:
                    logger.warn("[Console] The options you set have not been changed.")
                    return

                self.last_config[option_name] = getattr(self.config_obj, option_name)
                # self.config_dict[option_name] = option_value
                setattr(self.config_obj, option_name, option_value)

                logger.info("[Console] Update {}={}. Use 'showit' to view Detail.".format(option_name, option_value))
                logger.warn("[Console] Use Command 'cancel' to cancel last set or Command 'save' to save rule." )

                return
        elif self.current_mode == 'result':
            param = self.clear_args(args[0])

            if len(param) < 2:
                logger.error("[Console] you must set option name and value. e.g.: set active_vul all")
                return

            option_name = param[0]
            option_value = param[1]

            option_list = list(self.result_option_list)

            if option_name not in option_list:
                logger.error("[Console] you can only set option in {}.".format(option_list))
                return

            option_value = ast.literal_eval(option_value) if option_value in ['True', 'False'] else option_value

            if option_value in self.result_option_list[option_name]:
                self.result_options[option_name] = option_value
                logger.info("[Console] Change Show options {}={}".format(option_name, option_value))

            elif "<" in str(self.result_option_list[option_name]):
                self.result_options[option_name] = option_value
                logger.info("[Console] Change Show options {}={}".format(option_name, option_value))

            else:
                logger.info("[Console] Only accept option from {}".format(self.result_option_list[option_name]))
                return

        elif self.current_mode == 'scan':
            param = self.clear_args(args[0])

            if len(param) < 2:
                logger.error("[Console] you must set option name and value. e.g.: set is_debug True")
                return

            option_name = param[0]
            option_value = param[1]

            if option_name not in list(self.scan_options):
                logger.error("[Console] you can only set option in {}.".format(list(self.scan_options)))
                return

            option_value = ast.literal_eval(option_value) if option_value in ['True', 'False', 'None'] else option_value

            if option_value in self.scan_option_list[option_name]:
                self.scan_options[option_name] = option_value
                logger.info("[Console] Change Show options {}={}".format(option_name, option_value))

            elif "<" in str(self.scan_option_list[option_name]):
                self.scan_options[option_name] = option_value
                logger.info("[Console] Change Show options {}={}".format(option_name, option_value))

            else:
                logger.info("[Console] Only accept option from {}".format(self.scan_option_list[option_name]))
                return

    def command_add(self, *args, **kwargs):
        if self.current_mode not in ['config']:
            logger.warn("[Console] Command add only for config mode")
            return

        if self.current_mode == 'config':
            if self.config_mode == 'tamper':
                param = self.clear_args(args[0])

                if len(param) < 2:
                    logger.error("[Console] you must set option name and value. e.g.: set status False")
                    return

                option_name = param[0]
                option_value = param[1]

                # 如果option_name 和tamper_name相同，那么为Input-Control
                # 如果不是，那么为Filter-Function
                if option_name == self.config_keyword:
                    self.config_dict['input_control'].append(option_value)
                    self.last_config['input_control'].append(option_value)

                    logger.info("[Console] Add New Tamper for {} New Input-Control {}".format(self.config_keyword, option_value))
                else:
                    if option_name in self.config_dict['filter_func']:

                        # check exist
                        if int(option_value) in self.config_dict['filter_func'][option_name]:
                            logger.error("[Console] New Tamper for {} New filter_function exists.".format(self.config_keyword))
                            return
                        else:
                            self.config_dict['filter_func'][option_name].append(int(option_value))
                    else:
                        self.config_dict['filter_func'][option_name] = [int(option_value)]

                    # record last change
                    if option_name in self.last_config['filter_func']:
                        self.last_config['filter_func'][option_name].append(int(option_value))
                    else:
                        self.last_config['filter_func'][option_name] = [int(option_value)]

                    logger.info("[Console] Add New Tamper for {} New filter_func {} for {}".format(self.config_keyword, option_name, option_value))
                return

    def command_cancel(self, *args, **kwargs):
        if self.current_mode not in ['config']:
            logger.warn("[Console] Command cancel only for config mode")
            return

        if self.current_mode == 'config':
            if self.config_mode == 'rule':
                if not self.last_config:
                    logger.error("[Console] No saved last configuration found.")

                for option_name in self.last_config:
                    logger.info("[Console] Restore config {}={}".format(option_name, self.last_config[option_name]))
                    # self.config_dict[option_name] = self.last_config[option_name]
                    setattr(self.config_obj, option_name, self.last_config[option_name])

                self.last_config = {}
                return

            elif self.config_mode == 'tamper':
                if not self.last_config:
                    logger.error("[Console] No saved last configuration found.")

                for option_name in self.last_config['filter_func']:
                    for option_value in self.last_config['filter_func'][option_name]:

                        logger.info("[Console] Restore filter_func tamper {} for {}".format(option_name, option_value))
                        self.config_dict['filter_func'][option_name].remove(int(option_value))

                for option_value in self.last_config['input_control']:
                    logger.info("[Console] Restore Input-Control tamper {}".format(option_value))
                    self.config_dict['input_control'].remove(option_value)

                self.last_config['filter_func'] = {}
                self.last_config['input_control'] = []
                return

    def command_save(self, *args, **kwargs):
        if self.current_mode not in ['config']:
            logger.warn("[Console] Command set only for config mode")
            return

        if self.current_mode == 'config':
            if self.config_mode == 'rule':

                # rule = Rules.objects.filter(svid=self.config_dict['svid']).first()
                #
                # for option_name in self.configurable_options:
                #     setattr(rule, option_name, self.config_dict[option_name])

                self.config_obj.save()
                self.save_rule_to_file()

                logger.info("[Console] Rule CVI_{} change has be saved.".format(self.config_obj.svid))
                return

            elif self.config_mode == 'tamper':
                for option_value in self.last_config['input_control']:

                    t = Tampers(tam_name=self.config_keyword, tam_key=self.config_keyword, tam_value=option_value, tam_type='Input-Control')
                    t.save()

                for option_name in self.last_config['filter_func']:

                    t2 = Tampers.objects.filter(tam_name=self.config_keyword, tam_key=option_name, tam_type='Filter-Function').first()
                    if t2:
                        t2.tam_value = self.config_dict['filter_func'][option_name]
                        t2.save()
                    else:
                        # 没有的话就要新加
                        t2 = Tampers(tam_name=self.config_keyword, tam_key=option_name, tam_value=self.config_dict['filter_func'][option_name], tam_type='Filter-Function')
                        t2.save()
                logger.info("[Console] New Tamper {} has be saved.".format(self.config_keyword))
                return

    def command_del(self, *args, **kwargs):
        if self.current_mode not in ['result']:
            logger.warn("[Console] Command del only for result mode")
            return

        param = self.clear_args(args[0])
        if len(param) < 2:
            logger.error("[Console] Command Del need to set 'mod' and 'result_id'.e.g.: del vuls 1")

        mod = param[0]

        if mod not in ['vuls', 'newevilfunc']:
            logger.error("[Console] Command Show need to set in ['vuls', 'newevilfunc'].")
            return

        result_id = param[1]
        if mod == 'vuls':

            sr = ScanResultTask.objects.filter(scan_task_id=self.result_task_id, result_id=result_id, is_active=True).first()
            if sr:
                logger.info("[Console] Delete ScanTask {} id {}.".format(self.result_task_id, result_id))

                sr.is_active=False
                sr.save()
            else:
                logger.error("[Console] ScanTask {} not found id {}. please check the result id by Command 'show vuls all'.".format(self.result_task_id, result_id))
                return

        elif mod == 'newevilfunc':

            nf = NewEvilFunc.objects.filter(scan_task_id=self.result_task_id, result_id=result_id, is_active=True).first()
            if nf:
                logger.info("[Console] Delete NewEvilFunc {} id {}.".format(self.result_task_id, result_id))

                nf.is_active = False
                nf.save()
            else:
                logger.error("[Console] NewEvilFunc {} not found id {}. please check the result id by Command 'show newevilfunc all'.".format(self.result_task_id, result_id))
                return

    def command_show(self, *args, **kwargs):

            param = self.clear_args(args[0])
            mod = param[0]

            key = param[1] if len(param) > 1 else 'all'

            if self.current_mode == 'root':
                if mod not in ['rule', 'tamper']:
                    logger.error("[Console] Command Show need to set in ['rule', 'tamper'].")
                    return

                if mod == 'rule':
                    languages = Rules.objects.values("language").all()
                    self.show_mode = 'rule'

                    language_list = []

                    for lan in languages:
                        language_list.append(lan['language'].lower())

                    language_list = list(set(language_list))
                    language_list.append('all')

                    # check key for language

                    if key not in language_list:
                        logger.error("[Console] You should enter the Key in {}".format(language_list))
                        return

                    rules_table = PrettyTable(
                        ['#', 'CVI', 'Lang/CVE-id', 'Rule(ID/Name)', 'Author', 'Status', 'MatchMode'])
                    rules_table.align = 'l'

                    if key == 'all':
                        rs = Rules.objects.all()
                    else:
                        rs = Rules.objects.filter(language=key)

                    if rs:
                        for r in rs:
                            rules_table.add_row([r.id, r.svid, r.language, r.rule_name, r.author, r.status, r.match_mode])

                        logger.info("[Console] Show {} Rules:\n{}".format(key, rules_table))
                        logger.warn("[Console] Use Command 'get <rule_svid>' to get detail of rule")
                    else:
                        logger.error("[Console] Not Found Rules, Please check command or execute config load.")

                if mod == 'tamper':
                    ts = Tampers.objects.values("tam_name").all()

                    tamper_name_list = []

                    for tamper_name in ts:
                        tamper_name_list.append(tamper_name['tam_name'].lower())

                    tamper_name_list = list(set(tamper_name_list))
                    tamper_name_list.append("all")

                    # check key for tamper

                    if key not in tamper_name_list:
                        logger.error("[Console] You should enter the Key in {}".format(tamper_name_list))
                        return

                    if key == 'all':

                        tamper_table = PrettyTable(['#', 'Tamper_name'])
                        tamper_table.align = 'l'
                        i = 0

                        for tamper_name in tamper_name_list:
                            tamper_table.add_row([i, tamper_name])
                            i += 1

                        logger.info("[Console] ALL Tampers:\n{}".format(tamper_table))
                        logger.warn("[Console] Use 'show tamper <tamper_name>' can get tamper detail.")
                    else:
                        ts = Tampers.objects.filter(tam_name=key)

                        if ts:
                            filter_func = {}
                            input_control = []

                            for t in ts:
                                if t.tam_type == 'Filter-Function':
                                    filter_func[t.tam_key] = ast.literal_eval(t.tam_value)
                                elif t.tam_type == 'Input-Control':
                                    input_control.append(t.tam_value)

                            logger.info("""\nTamper Name:
        {}
    
    Filter Func:
    {}
    
    Input Control:
    {}
    """.format(key, pprint.pformat(filter_func, indent=4), pprint.pformat(input_control, indent=4)))

                        else:
                            logger.error("[Console] Not Found Tampers, Please check command or execute config load.")

                    return
            elif self.current_mode == 'result':
                if mod not in ['vuls', 'newevilfunc', 'options']:
                    logger.error("[Console] Command Show need to set in ['vuls', 'newevilfunc', 'options'].")
                    return

                if mod == 'vuls':

                    srs = self.get_scan_results_by_config()
                    table = PrettyTable(
                        ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Target-File:Line-Number',
                         'Commit(Author)', 'Source Code Content', 'Analysis'])
                    table.align = 'l'

                    if srs:
                        if key == 'all':
                            for sr in srs:
                                # load rule
                                rule = Rules.objects.filter(svid=sr.cvi_id).first()
                                rule_name = rule.rule_name
                                author = rule.author

                                row = [sr.result_id, sr.cvi_id, rule_name, sr.language, sr.vulfile_path,
                                       author, sr.source_code, sr.result_type]

                                table.add_row(row)

                            logger.info("[Result] Trigger Vulnerabilities ({vn})\r\n{table}".format(vn=len(srs), table=table))
                            logger.warn("[Console] Use 'show vuls <result_id>' could get detail of vul.")
                        else:
                            sr = ScanResultTask.objects.filter(scan_task_id=self.result_task_id, result_id=key).first()
                            if sr:
                                # load rule
                                rule = Rules.objects.filter(svid=sr.cvi_id).first()
                                rule_name = rule.rule_name
                                author = rule.author

                                row = [sr.result_id, sr.cvi_id, rule_name, sr.language, sr.vulfile_path,
                                       author, sr.source_code, sr.result_type]

                                table.add_row(row)

                                logger.info("[Result] ScanResult id {}:\n{}".format(key, table))

                                # show Vuls Chain
                                ResultFlow = get_resultflow_class(int(self.result_task_id))
                                rfs = ResultFlow.objects.filter(vul_id=sr.result_id)

                                if rfs:
                                    logger.info("[Chain] Vul {}".format(sr.result_id))
                                    for rf in rfs:
                                        logger.info("[Chain] {}, {}, {}:{}".format(rf.node_type, rf.node_content,
                                                                                   rf.node_path, rf.node_lineno))
                                        show_context(rf.node_path, rf.node_lineno)
                                    logger.info("[SCAN] ending\r\n -------------------------------------------------------------------------")
                                    logger.warn("[Console] Use 'del vuls <result_id>' could delete Wrong vul.")
                                    return

                            else:
                                logger.error("[Console] ScanTask {} not found id {}. please check you result id.".format(self.result_task_id, key))

                    else:
                        logger.error("[Console] ScanTask {} has 0 result.".format(self.result_task_id))

                elif mod == 'newevilfunc':
                    nfs = NewEvilFunc.objects.filter(is_active=1, scan_task_id=self.result_task_id)
                    table2 = PrettyTable(
                        ['#', 'NewFunction', 'OriginFunction', 'Related Rules id'])

                    table2.align = 'l'
                    idy = 1

                    if nfs:
                        if key == 'all':
                            for nf in nfs:
                                row = [idy, nf.func_name, nf.origin_func_name, nf.svid]

                                table2.add_row(row)
                                idy += 1

                            logger.info(
                                "[Console] New evil Function list by NewCore:\r\n{table}".format(table=table2))
                            logger.warn("[Console] You can set option in ['func_name', 'origin_func_name', 'svid'] to limit result.")
                            return

                        elif key in ['func_name', 'origin_func_name', 'svid']:
                            if len(param) < 3:
                                logger.error("[Console] Command show for evilfunc need to set 'option_name' and "
                                             "'option_value'.e.g.: show newevilfunc svid 1001")

                            option_name = param[1]
                            option_value = param[2]

                            nfs = self.get_new_evil_func(option_name, option_value)

                            for nf in nfs:
                                row = [idy, nf.func_name, nf.origin_func_name, nf.svid]

                                table2.add_row(row)
                                idy += 1

                            logger.info(
                                "[Console] New evil Function list by NewCore:\r\n{table}".format(table=table2))
                            return

                        else:
                            logger.error("[Console] Only set option name in ['func_name', 'origin_func_name', 'svid'].")

                    else:
                        logger.error("[Console] ScanTask {} has 0 New evil Function.".format(self.result_task_id))

                elif mod == 'options':
                    logger_console.debug("Show mode Option:")
                    for option in self.result_options:
                        logger_console.debug("    {}: {} {}".format(option.ljust(20, ' '), str(self.result_options[option]).ljust(30, " "), str(self.result_option_list[option])))

            else:
                logger.error("[Console] Wrong Command. Please Check you command.")
                return

    def command_showit(self, *args, **kwargs):
        if self.current_mode != 'config':
            logger.warn("[Console] Command showit only for config mode")
            return

        if self.config_mode == 'rule':
            self.show_rule_by_dict(self.config_obj)

        elif self.config_mode == 'tamper':
            self.show_tamper_by_dict(self.config_dict)

        else:
            return

    def command_config(self, *args, **kwargs):

        param = self.clear_args(args[0])

        if len(param) < 2:
            logger.error("[Console] Command Config need to set 'mod' and 'keyword'.e.g.: config rule 1001")

        mod = param[0]
        keyword = param[1]

        if mod not in ['rule', 'tamper']:
            logger.error("[Console] Command Config need to set mod in ['rule', 'tamper'].")
            return

        if mod == 'rule':
            rule = Rules.objects.filter(svid=keyword).first()

            if rule:
                self.current_mode = "config"
                self.config_mode = "rule"
                self.config_keyword = keyword
                self.config_obj = self.load_rule_dict_by_id(keyword)

                logger_console.info(self.config_rule_help)
            else:
                logger.error("[Console] Please check Rule id or or use the command 'show rule' to view")
                return

        elif mod == 'tamper':
            ts = Tampers.objects.filter(tam_name=keyword)

            if ts:
                self.current_mode = "config"
                self.config_mode = "tamper"
                self.config_keyword = keyword
                self.config_dict['filter_func'] = {}
                self.config_dict['input_control'] = []
                self.last_config['filter_func'] = {}
                self.last_config['input_control'] = []

                for t in ts:
                    if t.tam_type == 'Filter-Function':
                        self.config_dict['filter_func'][t.tam_key] = ast.literal_eval(t.tam_value)
                    elif t.tam_type == 'Input-Control':
                        self.config_dict['input_control'].append(t.tam_value)

                logger_console.info(self.config_tamper_help)
            else:
                logger.error("[Console] Not Found Tampers, Please check command or execute config load.")
                return

    def command_load(self, *args, **kwargs):
        if self.current_mode not in ['showt', 'root']:
            logger.warn("[Console] Command Load only for root、showt mode")
            return

        param = self.clear_args(args[0])
        if len(param) < 1:
            logger.error("[Console] Command Load need to set 'scan_id'. you can use 'showt' get it.")

        scan_id = param[0]

        st = ScanTask.objects.filter(id=scan_id).first()

        if st:
            if st.is_finished:
                logger.info("[Console] Load ScanTask {} success.".format(scan_id))
                self.current_mode = 'result'
                self.result_task_id = scan_id
                self.result_obj = st

                self.scan_options['log_name'] = "ScanTask_{}".format(st.id)

                logger_console.info(self.result_help)
            else:
                logger.error("[Console] ScanTask {} is not completed, the results cannot be loaded.".format(scan_id))
        else:
            logger.error("[Console] ScanTask {} not found. Please use 'showt' check ScanTask id.".format(scan_id))
            return

    def command_status(self, *args, **kwargs):
        if self.current_mode != 'scan':
            logger.warn("[Console] Command Status only for scan mode")
            return

        logger_console.info("Scan Options Status:")
        for option_name in self.scan_options:
            if self.scan_options[option_name] is None:
                if option_name in self.scan_required_options_list:
                    logger_console.error(
                        "    {}: {} {}    e.g.:{}".format(option_name.ljust(20, ' '), str(self.scan_options[option_name]).ljust(18, ' '), self.scan_option_help[option_name].ljust(40, ' '), self.scan_option_list[option_name]))
                else:
                    logger_console.warn(
                        "    {}: {} {}    e.g.:{}".format(option_name.ljust(20, ' '), str(self.scan_options[option_name]).ljust(18, ' '), self.scan_option_help[option_name].ljust(40, ' '), self.scan_option_list[option_name]))
            else:
                logger_console.debug("    {}: {} {}    e.g.:{}".format(option_name.ljust(20, ' '), str(self.scan_options[option_name]).ljust(18, ' '), self.scan_option_help[option_name].ljust(40, ' '), self.scan_option_list[option_name]))

        logger.warn("[Console] Red Options is required. Yellow Option is Optional.")
        logger.warn("[Console] Use Command Set to set option. e.g.: set rule_id 1000,1001")
        return

    def command_run(self, *args, **kwargs):
        if self.current_mode != 'scan':
            logger.warn("[Console] Command Status only for scan mode")
            return

        if self.check_scan_options():

            if self.scan_options['log_name']:
                logger.info("[INIT] New Log file {}.log .".format(self.scan_options['log_name']))
                log_add(logging.INFO, self.scan_options['log_name'])

            if self.scan_options['is_debug']:
                logger.setLevel(logging.DEBUG)
                logger.debug('[INIT] set logging level: debug')

            logger.debug('[INIT] start scanning...')
            t1 = time.time()

            # new scan task
            task_name = get_mainstr_from_filename(self.scan_options['target'])
            s = cli.check_scantask(task_name=task_name, target_path=self.scan_options['target'], parameter_config=self.get_sacn_parameters())

            if s.is_finished:
                logger.info("[INIT] Finished Task.")
                exit()

            # 标识任务id
            sid = str(s.id)
            get_scan_id()

            data = {
                'status': 'running',
                'report': ''
            }
            Running(sid).status(data)

            cli.start(self.scan_options['target'], self.scan_options['format'], self.scan_options['output'],
                      self.scan_options['rule_id'], sid, self.scan_options['language'], self.scan_options['tamper'],
                      self.scan_options['black_path'], True, self.scan_options['is_without_precom'])

            s.is_finished = True
            s.save()
            t2 = time.time()
            logger.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))

            # back to result
            self.result_task_id = s.id
            self.current_mode = "result"
            logger_console.info(self.result_help)

    def command_check_log(self, *args, **kwargs):
        if self.current_mode != 'result':
            logger.warn("[Console] Command Status only for result mode")
            return

        log_file_path = os.path.join(LOGS_PATH, self.scan_options['log_name']+'.log')

        if os.path.exists(log_file_path):
            os.system(log_file_path)
        else:
            logger.error("[Console] Log File {} does not exist.".format(log_file_path))
            return

    @stop_after(2)
    def complete_show(self, text, *args, **kwargs):
        if text:
            if self.current_mode == 'root':
                all_possible_matches = filter(lambda x: x.startswith(text), self.subcommand_root_list)
                return list(all_possible_matches)
            elif self.current_mode == 'result':
                all_possible_matches = filter(lambda x: x.startswith(text), self.subcommand_result_list)
                return list(all_possible_matches)
            else:
                return []
        else:
            if self.current_mode == 'root':
                return self.subcommand_root_list
            elif self.current_mode == 'result':
                return self.subcommand_result_list
            else:
                return self.subcommand_list

    @stop_after(2)
    def complete_config(self, text, *args, **kwargs):
        if text:
            all_possible_matches = filter(lambda x: x.startswith(text), self.subcommand_root_list)
            return list(all_possible_matches)
        else:
            return self.subcommand_root_list

    @stop_after(2)
    def complete_del(self, text, *args, **kwargs):
        if text:
            all_possible_matches = filter(lambda x: x.startswith(text), self.subcommand_result_list)
            return list(all_possible_matches)
        else:
            return self.subcommand_result_list

    @stop_after(3)
    def complete_set(self, text, *args, **kwargs):
        if text:
            if self.current_mode == 'config':
                all_possible_matches = filter(lambda x: x.startswith(text), self.configurable_options)
                return list(all_possible_matches)
            elif self.current_mode == 'scan':
                # 特殊处理针对set target
                command = args[0]

                if "set target " in command:
                    path_list = []
                    for filename in glob.glob(text + '*'):
                        if os.path.isdir(filename):
                            filename += '/'

                        path_list.append(filename.replace('\\', '/'))
                    return path_list

                all_possible_matches = filter(lambda x: x.startswith(text), list(self.scan_option_list))
                return list(all_possible_matches)
            elif self.current_mode == 'result':
                all_possible_matches = filter(lambda x: x.startswith(text), list(self.result_option_list))
                return list(all_possible_matches)
            else:
                return []
        else:
            if self.current_mode == 'config':
                return self.configurable_options
            elif self.current_mode == 'scan':
                # 特殊处理针对set target
                if "set target " in args[0]:
                    path_list = []
                    for filename in glob.glob('./' + text + '*'):
                        if os.path.isdir(filename):
                            filename += '/'

                        path_list.append(filename.replace('\\', '/'))
                    return path_list

                return list(self.scan_option_list)
            elif self.current_mode == 'result':
                return list(self.result_option_list)
            else:
                return []
