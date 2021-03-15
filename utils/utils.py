# -*- coding: utf-8 -*-

"""
    utils
    ~~~~~

    Implements utils

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import hashlib
import os
import random
import re
import string
import sys
import time

from Kunlun_M.settings import RULES_PATH, PROJECT_DIRECTORY
from web.index.models import ScanTask

from utils.log import logger, logger_console
from utils.file import check_filepath, get_line

TARGET_MODE_GIT = 'git'
TARGET_MODE_FILE = 'file'
TARGET_MODE_FOLDER = 'folder'
TARGET_MODE_COMPRESS = 'compress'

OUTPUT_MODE_MAIL = 'mail'
OUTPUT_MODE_API = 'api'
OUTPUT_MODE_FILE = 'file'
OUTPUT_MODE_STREAM = 'stream'
PY2 = sys.version_info[0] == 2

SCAN_ID = -1


def get_scan_id():
    global SCAN_ID

    if SCAN_ID > 0:
        return SCAN_ID
    else:
        s = ScanTask.objects.order_by("-id").first()
        SCAN_ID = s.id

    return SCAN_ID


class ParseArgs(object):
    def __init__(self, target, formatter, output, special_rules=None, language=None, black_path=None, a_sid=None):
        self.target = target
        self.formatter = formatter
        self.output = output if output else ""

        if special_rules != None and special_rules != '':
            self.special_rules = []
            extension = '.py'
            start_name = 'CVI_'

            if ',' in special_rules:
                # check rule name
                s_rules = special_rules.split(',')
                for sr in s_rules:
                    if extension not in sr:
                        sr += extension
                    if start_name not in sr:
                        sr = start_name + sr

                    if self._check_rule_name(sr):
                        self.special_rules.append(sr)
                    else:
                        logger.critical('[PARSE-ARGS] Rule {sr} not exist'.format(sr=sr))
            else:
                special_rules = start_name + special_rules + extension

                if self._check_rule_name(special_rules):
                    self.special_rules = [special_rules]
                else:
                    logger.critical(
                        '[PARSE-ARGS] Exception special rule name(e.g: CVI-110001): {sr}'.format(sr=special_rules))
        else:
            self.special_rules = None

        # check black pth list
        if black_path != None and black_path != "":
            self.black_path_list = []

            if ',' in black_path:
                self.black_path_list = [x.strip() for x in black_path.split(',') if x != ""]
                logger.info("[INIT][PARSE_ARGS] Black Path list is {}".format(self.black_path_list))
            else:
                self.black_path_list = []
                logger.warning("[INIT][PARSE_ARGS] Black Path parse error.")

        else:
            self.black_path_list = []

        # check and deal language
        if language != None and language != "":
            self.language = []

            if ',' in language:
                self.language = [x.strip() for x in language.split(',') if x != ""]
                logger.info("[INIT][PARSE_ARGS] Language is {}".format(self.language))
            else:
                self.language = [language.strip()]
                logger.info("[INIT][PARSE_ARGS] Only one Language {}.".format(self.language))

        self.sid = a_sid

    @staticmethod
    def _check_rule_name(name):
        paths = os.listdir(RULES_PATH)

        for p in paths:
            try:
                if name in os.listdir(RULES_PATH + "/" + p):
                    return True
            except:
                continue

        return False


    @property
    def target_mode(self):
        """
        Parse target mode (git/file/folder/compress)
        :return: str
        """
        target_mode = None
        target_git_cases = ['http://', 'https://', 'ssh://']
        for tgc in target_git_cases:
            if self.target[0:len(tgc)] == tgc:
                target_mode = TARGET_MODE_GIT

        if os.path.isfile(self.target):
            target_mode = TARGET_MODE_FILE
        if os.path.isdir(self.target):
            target_mode = TARGET_MODE_FOLDER
        if target_mode is None:
            logger.critical('[PARSE-ARGS] [-t <target>] can\'t empty!')
            exit()
        logger.debug('[PARSE-ARGS] Target Mode: {mode}'.format(mode=target_mode))
        return target_mode

    @property
    def output_mode(self):
        """
        Parse output mode (api/mail/file/stream)
        :return: str
        """
        output_mode = None
        output_mode_api = ['http', 'https']
        output_mode_mail = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if re.match(output_mode_mail, self.output) is not None:
            output_mode = OUTPUT_MODE_MAIL
        for oma in output_mode_api:
            if self.output[0:len(oma)] == oma:
                output_mode = OUTPUT_MODE_API
        if os.path.isdir(os.path.dirname(self.output)):
            output_mode = OUTPUT_MODE_FILE
        if output_mode is None:
            output_mode = OUTPUT_MODE_STREAM
        logger.debug('[PARSE-ARGS] Output Mode: {mode}'.format(mode=output_mode))
        return output_mode

    def target_directory(self, target_mode):
        target_directory = None
        if target_mode == TARGET_MODE_FOLDER:
            target_directory = self.target
        elif target_mode == TARGET_MODE_FILE:
            target_directory = self.target
            return target_directory
        else:
            logger.critical('[PARSE-ARGS] exception target mode ({mode})'.format(mode=target_mode))
            exit()

        logger.debug('[PARSE-ARGS] target directory: {directory}'.format(directory=target_directory))
        target_directory = os.path.abspath(target_directory)
        if target_directory[-1] == '/':
            return target_directory
        else:
            return u'{t}/'.format(t=target_directory)


def to_bool(value):
    """Converts 'something' to boolean. Raises exception for invalid formats"""
    if str(value).lower() in ("on", "yes", "y", "true", "t", "1"):
        return True
    if str(value).lower() in ("off", "no", "n", "false", "f", "0", "0.0", "", "none", "[]", "{}"):
        return False
    raise Exception('Invalid value for boolean conversion: ' + str(value))


def convert_time(seconds):
    """
    Seconds to minute/second
    Ex: 61 -> 1'1"
    :param seconds:
    :return:
    :link: https://en.wikipedia.org/wiki/Prime_(symbol)
    """
    one_minute = 60
    minute = seconds / one_minute
    if minute == 0:
        return str(seconds % one_minute) + "\""
    else:
        return str(int(minute)) + "'" + str(seconds % one_minute) + "\""


def convert_number(n):
    """
    Convert number to , split
    Ex: 123456 -> 123,456
    :param n:
    :return:
    """
    if n is None:
        return '0'
    n = str(n)
    if '.' in n:
        dollars, cents = n.split('.')
    else:
        dollars, cents = n, None

    r = []
    for i, c in enumerate(str(dollars)[::-1]):
        if i and (not (i % 3)):
            r.insert(0, ',')
        r.insert(0, c)
    out = ''.join(r)
    if cents:
        out += '.' + cents
    return out


def md5(content):
    """
    MD5 Hash
    :param content:
    :return:
    """
    content = content.encode('utf8')
    return hashlib.md5(content).hexdigest()


# def allowed_file(filename):
#     """
#     Allowed upload file
#     Config Path: ./config [upload]
#     :param filename:
#     :return:
#     """
#     config_extension = Config('upload', 'extensions').value
#     if config_extension == '':
#         logger.critical('Please set config file upload->directory')
#         sys.exit(0)
#     allowed_extensions = config_extension.split('|')
#     return '.' in filename and filename.rsplit('.', 1)[1] in allowed_extensions


def path_to_short(path, max_length=36):
    """
    /impl/src/main/java/com/mogujie/service/mgs/digitalcert/utils/CertUtil.java
    /impl/src/.../utils/CertUtil.java
    :param path:
    :param max_length:
    :return:
    """
    if len(path) < max_length:
        return path
    paths = path.split('/')
    paths = filter(None, paths)
    paths = list(paths)
    tmp_path = ''
    for i in range(0, len(paths)):
        logger.debug((i, str(paths[i]), str(paths[len(paths) - i - 1])))
        tmp_path = tmp_path + str(paths[i]) + '/' + str(paths[len(paths) - i - 1])
        if len(tmp_path) > max_length:
            tmp_path = ''
            for j in range(0, i):
                tmp_path = tmp_path + '/' + str(paths[j])
            tmp_path += '/...'
            for k in range(i, 0, -1):
                tmp_path = tmp_path + '/' + str(paths[len(paths) - k])
            if tmp_path == '/...':
                return '.../{0}'.format(paths[len(paths) - 1])
            elif tmp_path[0] == '/':
                return tmp_path[1:]
            else:
                return tmp_path


def path_to_file(path):
    """
    Path to file
    /impl/src/main/java/com/mogujie/service/mgs/digitalcert/utils/CertUtil.java
    .../CertUtil.java
    :param path:
    :return:
    """
    paths = path.split('/')
    paths = list(filter(None, paths))
    length = len(paths)
    return '.../{0}'.format(paths[length - 1])


def percent(part, whole, need_per=True):
    """
    Percent
    :param part:
    :param whole:
    :param need_per:
    :return:
    """
    if need_per:
        per = '%'
    else:
        per = ''
    if part == 0 and whole == 0:
        return 0
    return '{0}{1}'.format(100 * float(part) / float(whole), per)


def timestamp():
    """Get timestamp"""
    return int(time.time())


def format_gmt(time_gmt, time_format=None):
    """
    Format GMT time
    Ex: Wed, 14 Sep 2016 17:57:41 GMT to 2016-09-14 17:57:41
    :param time_gmt:
    :param time_format:
    :return:
    """
    if time_format is None:
        time_format = '%Y-%m-%d %X'
    t = time.strptime(time_gmt, "%a, %d %b %Y %H:%M:%S GMT")
    return time.strftime(time_format, t)


def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def is_list(value):
    """
    Returns True if the given value is a list-like instance

    >>> is_list([1, 2, 3])
    True
    >>> is_list(u'2')
    False
    """

    return isinstance(value, (list, tuple, set))


def get_unicode(value, encoding=None, none_to_null=False):
    """
    Return the unicode representation of the supplied value:

    >>> get_unicode(u'test')
    u'test'
    >>> get_unicode('test')
    u'test'
    >>> get_unicode(1)
    u'1'
    """

    if none_to_null and value is None:
        return None
    if str(type(value)) == "<class 'bytes'>":
        value = value.encode('utf8')
        return value
    elif str(type(value)) == "<type 'unicode'>":
        return value
    elif is_list(value):
        value = list(get_unicode(_, encoding, none_to_null) for _ in value)
        return value
    else:
        try:
            return value.encode('utf8')
        except UnicodeDecodeError:
            return value.encode('utf8', errors="ignore")


def get_safe_ex_string(ex, encoding=None):
    """
    Safe way how to get the proper exception represtation as a string
    (Note: errors to be avoided: 1) "%s" % Exception(u'\u0161') and 2) "%s" % str(Exception(u'\u0161'))

    >>> get_safe_ex_string(Exception('foobar'))
    u'foobar'
    """

    ret = ex

    if getattr(ex, "message", None):
        ret = ex.message
    elif getattr(ex, "msg", None):
        ret = ex.msg

    return get_unicode(ret or "", encoding=encoding).strip()


def secure_filename(filename):
    _filename_utf8_strip_re = re.compile(u"[^\u4e00-\u9fa5A-Za-z0-9_.\-\+]")
    _windows_device_files = ('CON', 'AUX', 'COM1', 'COM2', 'COM3', 'COM4', 'LPT1', 'LPT2', 'LPT3', 'PRN', 'NUL')

    text_type = str      # Python 3

    if isinstance(filename, text_type):
        from unicodedata import normalize
        filename = normalize('NFKD', filename).encode('utf-8', 'ignore')
        if not PY2:
            filename = filename.decode('utf-8')
    for sep in os.path.sep, os.path.altsep:
        if sep:
            filename = filename.replace(sep, ' ')
    if PY2:
        filename = filename.decode('utf-8')
    filename = _filename_utf8_strip_re.sub('', '_'.join(filename.split()))

    # on nt a couple of special files are present in each folder.  We
    # have to ensure that the target file is not such a filename.  In
    # this case we prepend an underline
    if os.name == 'nt' and filename and filename.split('.')[0].upper() in _windows_device_files:
        filename = '_' + filename

    return filename


# def unhandled_exception_message():
#     """
#     Returns detailed message about occurred unhandled exception
#     """
#     err_msg = """Cobra version: {cv}\nPython version: {pv}\nOperating system: {os}\nCommand line: {cl}""".format(
#         cv=__version__,
#         pv=__python_version__,
#         os=__platform__,
#         cl=re.sub(r".+?\bkunlun.py\b", "kunlun.py", " ".join(sys.argv).encode('utf-8'))
#     )
#     return err_msg
#
#
# def create_github_issue(err_msg, exc_msg):
#     """
#     Automatically create a Github issue with unhandled exception information
#     """
#     issues = []
#     try:
#         with open(issue_history_path, 'r') as f:
#             for line in f.readlines():
#                 issues.append(line.strip())
#     except:
#         pass
#     finally:
#         # unique
#         issues = set(issues)
#     _ = re.sub(r"'[^']+'", "''", exc_msg)
#     _ = re.sub(r"\s+line \d+", "", _)
#     _ = re.sub(r'File ".+?/(\w+\.py)', "\g<1>", _)
#     _ = re.sub(r".+\Z", "", _)
#     key = hashlib.md5(_).hexdigest()[:8]
#
#     if key in issues:
#         logger.warning('issue already reported!')
#         return
#
#     ex = None
#
#     try:
#         url = "https://api.github.com/search/issues?q={q}".format(q=urllib.quote("repo:wufeifei/core [AUTO] Unhandled exception (#{k})".format(k=key)))
#         logger.debug(url)
#         resp = requests.get(url=url)
#         content = resp.json()
#         _ = content
#         duplicate = _["total_count"] > 0
#         closed = duplicate and _["items"][0]["state"] == "closed"
#         if duplicate:
#             warn_msg = "issue seems to be already reported"
#             if closed:
#                 warn_msg += " and resolved. Please update to the latest version from official GitHub repository at '{u}'".format(u=__url__)
#             logger.warning(warn_msg)
#             return
#     except:
#         logger.warning('search github issue failed')
#         pass
#
#     try:
#         url = "https://api.github.com/repos/wufeifei/cobra/issues"
#         data = {
#             "title": "[AUTO] Unhandled exception (#{k})".format(k=key),
#             "body": "## Environment\n```\n{err}\n```\n## Traceback\n```\n{exc}\n```\n".format(err=err_msg, exc=exc_msg)
#         }
#         headers = {"Authorization": "token {t}".format(t='48afbb61693ce187606388842ae1ccaa9a88a10a')}
#         resp = requests.post(url=url, data=json.dumps(data), headers=headers)
#         content = resp.text
#     except Exception as ex:
#         content = None
#
#     issue_url = re.search(r"https://github.com/wufeifei/cobra/issues/\d+", content or "")
#     if issue_url:
#         info_msg = "created Github issue can been found at the address '{u}'".format(u=issue_url.group(0))
#         logger.info(info_msg)
#
#         try:
#             with open(issue_history_path, "a+b") as f:
#                 f.write("{k}\n".format(k=key))
#         except:
#             pass
#     else:
#         warn_msg = "something went wrong while creating a Github issue"
#         if ex:
#             warn_msg += " ('{m}')".format(m=get_safe_ex_string(ex))
#         if "Unauthorized" in warn_msg:
#             warn_msg += ". Please update to the latest revision"
#         logger.warning(warn_msg)

def pretty_code_js(code):
    """
    美化代码使代码可读
    :param code:
    :return:
    """
    lines = code.split('\n')

    indent = 0
    formatted = []

    oldchar = '\0'
    is_comment = False
    is_function = False
    is_array = False
    is_tuple = False
    is_dict = False

    for line in lines:
        newline = []

        is_string = False
        is_regex = False

        for char in line:

            nowoldchar = oldchar
            oldchar = char

            # 处理大括号
            if nowoldchar == '{' and char == '}' and len(newline):
                newline.pop(-1)
                newline.pop(-1)
                newline.append(char)
                is_dict = False
                continue

            # 多行注释
            if char == '*' and nowoldchar == '/':
                if len(newline):
                    newline.pop(-1)
                is_comment = True
                break

            if is_comment and char == '/' and nowoldchar == '*':
                is_comment = False
                continue

            if is_comment:
                continue

            newline.append(char)

            # 一个特殊问题，正则表达式
            if not is_regex and not is_string and nowoldchar == '(' and char == '/':
                is_regex = True
                continue

            if is_regex and char == '/' and nowoldchar != '\\':
                is_regex = False
                continue

            if is_regex:
                continue

            # 处理字符串
            if not is_string and char == '`':
                is_string = '`'
                continue

            if is_string == '`' and char == '`' and nowoldchar != '\\':
                is_string = False
                continue

            if not is_string and char == '"':
                is_string = '"'
                continue

            if is_string == '"' and char == '"' and nowoldchar != '\\':
                is_string = False
                continue

            if not is_string and char == "'":
                is_string = "'"
                continue

            if is_string == "'" and char == "'" and nowoldchar != '\\':
                is_string = False
                continue

            if is_string:
                continue

            # 处理注释
            if char == '/' and nowoldchar == '/':
                # is_comment = True
                newline.append('\n')
                break

            if char == '!' and nowoldchar == '<':
                # is_comment = True
                newline.append('\n')
                break

            # 处理特殊对象
            if char == "[":
                is_array = True
                continue

            if is_array and char == ']':
                is_array = False
                continue

            if char == "(":
                is_tuple = True
                continue

            if is_tuple and char == ')':
                is_tuple = False
                continue

            if (is_dict or is_array) and not is_tuple and char == ',':
                newline.append("\n")
                newline.append("\t" * indent)

            if char == ';':
                newline.append("\n")
                newline.append("\t" * indent)

            if char == '{' and nowoldchar == 'n':
                indent += 1
                newline.append("\n")
                newline.append("\t" * indent)
                is_function = True

            if char == '{' and nowoldchar != 'n':
                indent += 1
                newline.append("\n")
                newline.append("\t" * indent)
                is_dict = True

            if char == "}":
                indent -= 1
                newline.append("\n")
                newline.append("\t" * indent)
                is_function = True if is_dict else False
                is_dict = False

        formatted.append("\t" * indent + "".join(newline))

    return "".join(formatted)


def get_mainstr_from_filename(filename):

    mainstr = filename.replace('\\', '/').split('/')
    mainstr = mainstr[-1] if mainstr[-1] else mainstr[-2]
    mainstr = mainstr.split('.')[0].strip("")

    return mainstr


def file_output_format(content):
    """
    检查输出到文件的规则格式
    :param content:
    :return:
    """
    if content:
        if "[" == content[0]:
            return content
        else:
            return 'r"{}"'.format(content.replace('"', r'\"'))
    else:
        return 'None'


def show_context(filename, line_number, show_line=3, is_back=False):
    filename = check_filepath(PROJECT_DIRECTORY, filename)

    line_number = line_number if line_number else 0
    line_start = int(line_number) - show_line if (int(line_number) - show_line) > 0 else 0
    line_start = line_start if line_start else 1
    line_end = int(line_start) + show_line + show_line

    lines = get_line(filename, "{},{}".format(line_start, line_end))

    contents = ""

    i = 0
    for line in lines:

        if line_start + i == int(line_number):
            logger_console.warning("%4d: %s" % (line_start+i, line.replace("\n", "")))
        else:
            logger_console.info("%4d: %s" % (line_start+i, line.replace("\n", "")))

        contents += "%4d: %s" % (line_start+i, line)
        i += 1

    return contents
