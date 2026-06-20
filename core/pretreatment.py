#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/4/15 14:51
# @Author  : LoRexxar
# @File    : Pretreatment.py
# @Contact : lorexxar@gmail.com


from phply.phplex import lexer  # 词法分析
from phply.phpparse import make_parser  # 语法分析
from phply import phpast as php

from bs4 import BeautifulSoup

import esprima
import jsbeautifier
import javalang

from utils.log import logger
from Kunlun_M.const import ext_dict
from utils.file import un_zip

import gc
import os
import re
import json
import codecs
import traceback
import zipfile
import queue
import asyncio
import subprocess
from collections.abc import Hashable

could_ast_pase_lans = ["php", "chromeext", "javascript", "html", "java", "python", "go", "c", "typescript",
                       "rust", "ruby", "csharp", "kotlin", "lua", "cpp"]


class Pretreatment:

    def __init__(self):
        self.file_list = []
        self.target_queue = queue.Queue()
        self.target_directory = ""
        self.lan = None
        self.is_unprecom = False

        self.pre_result = {}
        self.define_dict = {}
        self.decompiled_files = []

        # self.pre_ast_all()

    def init_pre(self, target_directory, files):
        self.file_list = files
        self.target_directory = target_directory

        self.target_directory = os.path.normpath(self.target_directory)

    def get_path(self, filepath):
        os.chdir(os.path.dirname(os.path.dirname(__file__)))

        if os.path.isfile(filepath):
            return os.path.normpath(filepath)

        # 去掉前导 /，避免 os.path.join 把它当绝对路径
        clean_filepath = filepath.lstrip('/')

        joined = os.path.normpath(os.path.join(self.target_directory, clean_filepath))
        if os.path.isfile(joined):
            return joined

        if os.path.isfile(self.target_directory):
            return os.path.normpath(self.target_directory)
        else:
            return joined

    def _normalize_define_key(self, key_node):
        """
        将 define 的第一个参数归一化为可哈希键，避免 AST 节点直接作为 dict key 导致 TypeError。
        """
        if isinstance(key_node, php.Constant):
            return key_node.name

        # 处理诸如 __NAMESPACE__ . "FOO" 的字符串拼接常量名
        if isinstance(key_node, php.BinaryOp) and key_node.op == ".":
            left = self._normalize_define_key(key_node.left)
            right = self._normalize_define_key(key_node.right)
            if left is not None and right is not None:
                return "{}{}".format(left, right)

        if isinstance(key_node, php.MagicConstant):
            return key_node.name

        if isinstance(key_node, str):
            return key_node

        if isinstance(key_node, Hashable):
            return key_node

        return repr(key_node)

    def _ensure_cfr(self):
        """确保 CFR 反编译器可用，不存在则自动下载"""
        # 先检查项目 tools 目录
        cfr_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools', 'cfr.jar')
        if os.path.isfile(cfr_path):
            return cfr_path

        # 自动下载
        try:
            import urllib.request
            cfr_url = "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar"
            os.makedirs(os.path.dirname(cfr_path), exist_ok=True)
            logger.info("[AST] [JAR] 下载 CFR 反编译器...")
            urllib.request.urlretrieve(cfr_url, cfr_path)
            return cfr_path
        except Exception as e:
            logger.warning("[AST] [JAR] CFR 下载失败: {}".format(str(e)))
            return None

    def pre_ast_all(self, lan=None, is_unprecom=False):

        if lan is not None:
            # 检查是否在可ast pasre列表中
            if not list(set(lan).intersection(set(could_ast_pase_lans))):
                logger.info("[AST][Pretreatment] Current scan target language does not require ast pretreatment...")
                return True

        for fileext in self.file_list:
            self.target_queue.put(fileext)

        # 设置公共变量用于判断是否设定了扫描语言
        self.lan = lan

        # 设置标志位标识跳过预编译阶段
        self.is_unprecom = is_unprecom

        scan_list = [self.pre_ast() for _ in range(10)]

        # Python 3.11+ recommends using asyncio.run instead of manual loop setup.
        async def _run_pretreatment(tasks):
            await asyncio.gather(*tasks)

        asyncio.run(_run_pretreatment(scan_list))

    @staticmethod
    def _repair_php_code_for_parser(code_content):
        """
        尝试修复 lphply 暂不支持的部分语法，避免整个文件 AST 预处理失败。
        当前处理：
        1. ($a)() 这类「括号包裹变量再调用」语法。

        注意：lphply >= 2.0.0 已原生支持以下语法，无需降级：
        - PHP7 null coalescing（??）— lexer 识别为 COALESCE token
        - PHP7 spaceship（<=>）— lexer 识别为 SPACESHIP token
        - PHP8 match expression
        - PHP8 named arguments
        - PHP8.2 DNF types、enum、readonly
        - PHP8.4 property hooks、new without parentheses
        - PHP8.5 pipe operator、clone with arguments
        """
        repaired_content = code_content
        token_stream = lexer.clone()
        token_stream.input(code_content)

        tokens = []
        while True:
            token = token_stream.token()
            if not token:
                break
            tokens.append(token)

        # 仅在词法级别命中特定模式时进行修复，避免正则替换误伤字符串、注释等内容。
        edits = []
        token_count = len(tokens)

        # 修复 ( VARIABLE ) ( 语法模式。
        for index in range(token_count - 3):
            token_lparen = tokens[index]
            token_var = tokens[index + 1]
            token_rparen = tokens[index + 2]
            token_call_lparen = tokens[index + 3]

            if not (token_lparen.type == 'LPAREN'
                    and token_var.type == 'VARIABLE'
                    and token_rparen.type == 'RPAREN'
                    and token_call_lparen.type == 'LPAREN'):
                continue

            # 替换 "( $a )" 片段为 "$a"，保留后续调用参数括号。
            start = token_lparen.lexpos
            end = token_rparen.lexpos + len(token_rparen.value)
            edits.append((start, end, token_var.value))

        if not edits:
            return repaired_content

        # 按位置应用替换，避免下标偏移问题。
        pieces = []
        cursor = 0
        for start, end, replacement in sorted(edits, key=lambda item: item[0]):
            if start < cursor:
                # 重叠编辑（理论上不应出现），跳过后续冲突项。
                continue
            pieces.append(repaired_content[cursor:start])
            pieces.append(replacement)
            cursor = end
        pieces.append(repaired_content[cursor:])

        return ''.join(pieces)

    async def pre_ast(self):

        while not self.target_queue.empty():

            fileext = self.target_queue.get()

            if not self.lan:
                break

            if fileext[0] in ext_dict['php'] and 'php' in self.lan:
                # 下面是对于php文件的处理逻辑
                for filepath in fileext[1]['list']:
                    all_nodes = []
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'php'
                    self.pre_result[filepath]['ast_nodes'] = []

                    fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                    code_content = fi.read()
                    fi.close()

                    # self.pre_result[filepath]['content'] = code_content

                    try:
                        if not self.is_unprecom:
                            parser = make_parser()
                            all_nodes = parser.parse(code_content, debug=False, lexer=lexer.clone(), tracking=True)
                        else:
                            all_nodes = []

                        # 合并字典
                        self.pre_result[filepath]['ast_nodes'] = all_nodes

                    except SyntaxError as e:
                        if self.is_unprecom:
                            logger.warning('[AST] [ERROR] parser {} SyntaxError'.format(filepath))
                            continue

                        repaired_code_content = self._repair_php_code_for_parser(code_content)

                        if repaired_code_content == code_content:
                            logger.warning('[AST] [ERROR] parser {} SyntaxError'.format(filepath))
                            continue

                        try:
                            parser = make_parser()
                            all_nodes = parser.parse(repaired_code_content, debug=False, lexer=lexer.clone(), tracking=True)
                            logger.warning('[AST] [INFO] parser {} fallback with callable-variable repair'.format(filepath))
                            self.pre_result[filepath]['ast_nodes'] = all_nodes
                        except Exception:
                            logger.warning('[AST] [ERROR] parser {} SyntaxError'.format(filepath))
                            continue

                    except AssertionError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))
                        continue

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
                        continue

                    # 搜索所有的常量
                    for node in all_nodes:
                        if isinstance(node, php.FunctionCall) and node.name == "define":
                            define_params = node.params

                            if define_params:
                                logger.debug(
                                    "[AST][Pretreatment] new define {}={}".format(define_params[0].node,
                                                                                  define_params[1].node))

                                key = self._normalize_define_key(define_params[0].node)
                                self.define_dict[key] = define_params[1].node

            elif fileext[0] in ext_dict['chromeext'] and 'chromeext' in self.lan:

                # 针对chrome 拓展的预处理
                # 需要提取其中的js和html？
                for filepath in fileext[1]['list']:
                    child_files = []
                    child_files_html = []

                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'chromeext'

                    # 首先想办法解压crx
                    try:
                        target_files_path = un_zip(filepath)
                        self.pre_result[filepath]['target_files_path'] = target_files_path

                    except zipfile.BadZipFile:
                        logger.warning("[Pretreatment][Chrome Ext] file {} not zip".format(filepath))
                        continue

                    except OSError:
                        logger.warning("[Pretreatment][Chrome Ext] file {} unzip error".format(filepath))
                        continue

                    # 分析manifest.json
                    manifest_path = os.path.join(target_files_path, "manifest.json")

                    # target可能是单个文件，这里需要专门处理
                    if not (self.target_directory.endswith("/") or self.target_directory.endswith("\\")) and not os.path.isdir(self.target_directory):

                        path_list = re.split(r'[\\|/]', self.target_directory)
                        relative_path = os.path.join(path_list[-1]+"_files")
                    else:
                        relative_path = target_files_path.split(self.target_directory)[-1]

                    if relative_path.startswith('\\') or relative_path.startswith("/"):
                        relative_path = relative_path[1:]

                    if os.path.isfile(manifest_path):
                        fi = codecs.open(manifest_path, "r", encoding='utf-8', errors='ignore')
                        manifest_content = fi.read()
                        fi.close()

                        try:
                            manifest = json.loads(manifest_content)

                        except json.decoder.JSONDecodeError:
                            logger.warning(
                                "[Pretreatment][Chrome Ext] File {} parse error...".format(target_files_path))
                            continue

                        self.pre_result[filepath]["manifest"] = manifest

                        # 想办法优化，如果不想深入js和html的判断，那么就跳过
                        if len(self.lan) and self.lan == 'chromeext':
                            logger.debug("[Pretreatment][Chrome Ext] pass js & html scan...")
                            continue

                        # content scripts
                        if "content_scripts" in manifest:
                            for script in manifest["content_scripts"]:
                                if "js" in script:
                                    child_files.extend([os.path.join(relative_path, js) for js in script['js']])

                        # background js
                        if "background" in manifest:
                            if "scripts" in manifest["background"]:
                                child_files.extend([os.path.join(relative_path, js) for js in manifest["background"]["scripts"]])

                            # background html
                            if "page" in manifest["background"]:
                                child_files_html.append(os.path.join(relative_path, manifest["background"]["page"]))

                        # popup.html
                        if "browser_action" in manifest:
                            if "default_popup" in manifest["browser_action"]:
                                child_files_html.append(os.path.join(relative_path, manifest["browser_action"]["default_popup"]))

                        # web_accessible_resources
                        if "web_accessible_resources" in manifest:
                            for resource in manifest["web_accessible_resources"]:
                                if ".js" in resource:
                                    child_files.append(os.path.join(relative_path, resource))

                                if ".html" in resource:
                                    child_files_html.append(os.path.join(relative_path, resource))

                        # chrome_url_overrides
                        if "chrome_url_overrides" in manifest:
                            for key in manifest["chrome_url_overrides"]:
                                child_files_html.append(os.path.join(relative_path, manifest["chrome_url_overrides"][key]))

                        self.pre_result[filepath]["child_files"] = child_files

                        if len(child_files):
                            # 将content_scripts加入到文件列表中构造
                            self.target_queue.put(('.js', {'count': len(child_files), 'list': child_files}))

                            # 通过浅复制操作外部传入的files
                            self.file_list.append(('.js', {'count': len(child_files), 'list': child_files}))

                        if len(child_files_html):
                            self.target_queue.put(('.html', {'count': len(child_files_html), 'list': child_files_html}))

                    else:
                        logger.warning("[Pretreatment][Chrome Ext] File {} parse error...".format(target_files_path))
                        continue

            elif fileext[0] in ext_dict['html'] and 'javascript' in self.lan:
                # html only found js
                for filepath in fileext[1]['list']:
                    filepath = self.get_path(filepath)
                    script_list = []

                    try:
                        fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                        code_content = fi.read()
                        fi.close()

                    except FileNotFoundError:
                        continue

                    except OSError:
                        continue

                    # tmp.js save all inline javascript code
                    tmp_path = os.path.join(os.path.dirname(filepath), "tmp.js")
                    fi2 = codecs.open(tmp_path, "a", encoding='utf-8', errors='ignore')

                    try:
                        soup = BeautifulSoup(code_content, "html.parser")

                        script_tag_list = soup.find_all('script')

                        for script_tag in script_tag_list:
                            script_attrs = script_tag.attrs

                            if 'src' in script_attrs:
                                parents_path = os.path.normpath("\\".join(re.split(r'[\\|/]', filepath)[:-1]))

                                script_path = os.path.join(parents_path, script_attrs['src'])
                                script_list.append(script_path)

                            else:
                                # 如果没有src，那么代表是内联js
                                script_content = script_tag.string

                                fi2.write(" \n{}\n ".format(script_content))

                        fi2.close()
                        if tmp_path not in script_list:
                            script_list.append(tmp_path)

                        # 将content_scripts加入到文件列表中构造
                        self.target_queue.put(('.js', {'count': len(script_list), 'list': script_list}))

                        # 通过浅复制操作外部传入的files
                        self.file_list.append(('.js', {'count': len(script_list), 'list': script_list}))

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict['javascript'] and 'javascript' in self.lan:

                # 针对javascript的预处理
                # 需要对js做语义分析
                for filepath in fileext[1]['list']:
                    filepath = self.get_path(filepath)

                    if not filepath.endswith(".js"):
                        continue

                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'javascript'
                    self.pre_result[filepath]['ast_nodes'] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding='utf-8', errors='ignore')
                        code_content = fi.read()
                        fi.close()

                    except FileNotFoundError:
                        continue

                    except OSError:
                        continue

                    # 添加代码美化并且写入新文件
                    new_filepath = filepath + ".pretty"

                    try:
                        # 基于代码格式的启发式过滤：
                        # - 跳过混淆/压缩代码（平均行长 > 500 字符）
                        # - 跳过极短文件（总行数 < 5）
                        # - 不再限制总字符数和总行数，以支持 Node.js 服务端大文件
                        line_count = code_content.count('\n') + 1
                        avg_line_len = len(code_content) / max(line_count, 1)
                        if avg_line_len > 500 or line_count < 5:
                            continue

                        if not os.path.isfile(new_filepath):
                            fi2 = codecs.open(new_filepath, "w", encoding='utf-8', errors='ignore')
                            code_content = jsbeautifier.beautify(code_content)
                            fi2.write(code_content)
                            fi2.close()

                        # self.pre_result[filepath]['content'] = code_content
                        if not self.is_unprecom:
                            all_nodes = esprima.parse(code_content, {"loc": True, "tolerant": True})
                        else:
                            all_nodes = []

                        # 合并字典
                        self.pre_result[filepath]['ast_nodes'] = all_nodes

                    except SyntaxError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))

                    except AssertionError as e:
                        logger.warning('[AST] [ERROR] parser {}: {}'.format(filepath, traceback.format_exc()))

                    except esprima.error_handler.Error:
                        logger.warning('[AST] [ERROR] Invalid regular expression in {}...'.format(filepath))

                    except KeyboardInterrupt:
                        logger.stop('[AST] stop...')
                        exit()

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
                        continue

            elif fileext[0] == '.jar' and 'java' in self.lan:
                # 针对 JAR 文件的反编译预处理
                for filepath in fileext[1]['list']:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'java'
                    self.pre_result[filepath]['ast_nodes'] = []
                    self.pre_result[filepath]['type'] = 'jar'

                    try:
                        # 1. 确保有 CFR
                        cfr_path = self._ensure_cfr()
                        if not cfr_path:
                            logger.warning("[AST] [JAR] CFR 不可用，跳过反编译: {}".format(filepath))
                            continue

                        # 2. 反编译 JAR（CFR 直接接受 .jar 文件作为输入）
                        decompiled_dir = filepath + "_decompiled/"
                        if not os.path.isdir(decompiled_dir) or not os.listdir(decompiled_dir):
                            os.makedirs(decompiled_dir, exist_ok=True)
                            subprocess.run(
                                ['java', '-jar', cfr_path, filepath, '--outputdir', decompiled_dir],
                                capture_output=True, timeout=120
                            )

                        self.pre_result[filepath]['decompiled_dir'] = decompiled_dir

                        # 3. 遍历反编译输出的 .java 文件，做 AST 解析
                        for root, dirs, java_files in os.walk(decompiled_dir):
                            for jf in java_files:
                                if jf.endswith('.java'):
                                    java_path = os.path.join(root, jf)
                                    self.pre_result[java_path] = {}
                                    self.pre_result[java_path]['language'] = 'java'
                                    self.pre_result[java_path]['ast_nodes'] = []
                                    self.pre_result[java_path]['source_jar'] = filepath

                                    try:
                                        with codecs.open(java_path, 'r', encoding='utf-8', errors='ignore') as f:
                                            code = f.read()
                                        if not self.is_unprecom:
                                            tree = javalang.parse.parse(code)
                                            self.pre_result[java_path]['ast_nodes'] = tree
                                    except javalang.parser.JavaSyntaxError:
                                        logger.warning("[AST] [JAR] 反编译文件语法错误: {}".format(java_path))
                                    except Exception:
                                        logger.warning("[AST] [JAR] 解析异常: {}".format(traceback.format_exc()))

                                    # 加入反编译文件列表，供后续扫描使用
                                    self.decompiled_files.append(java_path)

                    except Exception:
                        logger.warning("[AST] [JAR] 处理异常: {}".format(traceback.format_exc()))

            elif fileext[0] in ext_dict['java'] and 'java' in self.lan:
                # 针对 Java 的预处理
                for filepath in fileext[1]['list']:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]['language'] = 'java'
                    self.pre_result[filepath]['ast_nodes'] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            tree = javalang.parse.parse(code_content)
                            self.pre_result[filepath]['ast_nodes'] = tree
                        else:
                            self.pre_result[filepath]['ast_nodes'] = []

                    except javalang.parser.JavaSyntaxError:
                        logger.warning("[AST] [ERROR] parser {} JavaSyntaxError".format(filepath))
                        continue

                    except:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["python"] and "python" in self.lan:
                # 针对 Python 的预处理
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "python"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            import ast as python_ast
                            tree = python_ast.parse(code_content, filename=filepath)
                            self.pre_result[filepath]["ast_nodes"] = tree
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                    except SyntaxError as e:
                        logger.warning("[AST] [ERROR] parser {} SyntaxError: {}".format(filepath, str(e)))
                        continue

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["go"] and "go" in self.lan:
                # 针对 Go 的预处理
                # 使用 tree-sitter 解析 Go 源文件，生成 AST（供图引擎使用）
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "go"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_go as tsgo
                                from tree_sitter import Language, Parser
                                GO_LANG = Language(tsgo.language())
                                ts_parser = Parser(GO_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-go not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        # 存储源码行列表供老引擎 parser 使用（保持向后兼容）
                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["c"] and ("c" in self.lan or "c++" in self.lan or "cpp" in self.lan):
                # 针对 C/C++ 的预处理
                # 使用 tree-sitter 解析 C/C++ 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "c"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_c as tsc
                                from tree_sitter import Language, Parser
                                C_LANG = Language(tsc.language())
                                ts_parser = Parser(C_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-c not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        # 存储源码供 parser 使用
                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["typescript"] and "typescript" in self.lan:
                # 针对 TypeScript 的预处理
                # 使用 tree-sitter 解析 TypeScript 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "typescript"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_typescript as tsts
                                from tree_sitter import Language, Parser
                                TS_LANG = Language(tsts.language_typescript())
                                ts_parser = Parser(TS_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-typescript not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["rust"] and "rust" in self.lan:
                # 针对 Rust 的预处理
                # 使用 tree-sitter 解析 Rust 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "rust"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_rust as tsrust
                                from tree_sitter import Language, Parser
                                RUST_LANG = Language(tsrust.language())
                                ts_parser = Parser(RUST_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-rust not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["ruby"] and "ruby" in self.lan:
                # 针对 Ruby 的预处理
                # 使用 tree-sitter 解析 Ruby 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "ruby"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_ruby as tsruby
                                from tree_sitter import Language, Parser
                                RUBY_LANG = Language(tsruby.language())
                                ts_parser = Parser(RUBY_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-ruby not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["csharp"] and "csharp" in self.lan:
                # 针对 C# 的预处理
                # 使用 tree-sitter 解析 C# 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "csharp"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_c_sharp as tscs
                                from tree_sitter import Language, Parser
                                CSHARP_LANG = Language(tscs.language())
                                ts_parser = Parser(CSHARP_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-c-sharp not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["kotlin"] and "kotlin" in self.lan:
                # 针对 Kotlin 的预处理
                # 使用 tree-sitter 解析 Kotlin 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "kotlin"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_kotlin as tskt
                                from tree_sitter import Language, Parser
                                KOTLIN_LANG = Language(tskt.language())
                                ts_parser = Parser(KOTLIN_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-kotlin not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            elif fileext[0] in ext_dict["lua"] and "lua" in self.lan:
                # 针对 Lua 的预处理
                # 使用 tree-sitter 解析 Lua 源文件，生成 AST
                for filepath in fileext[1]["list"]:
                    filepath = self.get_path(filepath)
                    self.pre_result[filepath] = {}
                    self.pre_result[filepath]["language"] = "lua"
                    self.pre_result[filepath]["ast_nodes"] = []

                    try:
                        fi = codecs.open(filepath, "r", encoding="utf-8", errors="ignore")
                        code_content = fi.read()
                        fi.close()

                        if not self.is_unprecom:
                            try:
                                import tree_sitter_lua as tslua
                                from tree_sitter import Language, Parser
                                LUA_LANG = Language(tslua.language())
                                ts_parser = Parser(LUA_LANG)
                                tree = ts_parser.parse(bytes(code_content, 'utf8'))
                                self.pre_result[filepath]['ast_nodes'] = tree
                            except ImportError:
                                logger.warning("[AST] tree-sitter-lua not installed, skip AST for {}".format(filepath))
                            except Exception as e:
                                logger.warning("[AST] [ERROR] tree-sitter parse error for {}: {}".format(filepath, str(e)))
                        else:
                            self.pre_result[filepath]["ast_nodes"] = []

                        self.pre_result[filepath]["source_lines"] = code_content.splitlines()

                    except Exception:
                        logger.warning("[AST] something error, {}".format(traceback.format_exc()))
                        continue

            # 手动回收?
            gc.collect()

        return True

    def get_nodes(self, filepath, vul_lineno=None, lan=None):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            if vul_lineno:
                # 处理需求函数的问题
                # 主要应用于，函数定义之后才会调用才会触发
                if lan == 'javascript':
                    backnodes = lambda: None
                    backnodes.body = []
                    allnodes = self.pre_result[filepath]['ast_nodes'].body if self.pre_result[filepath]['ast_nodes'] else []

                    for node in allnodes:
                        if node.loc.start.line <= int(vul_lineno):
                            backnodes.body.append(node)

                    return backnodes

            return self.pre_result[filepath]['ast_nodes']

        elif os.path.join(self.target_directory, filepath) in self.pre_result:
            return self.pre_result[os.path.join(self.target_directory, filepath)]['ast_nodes']

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def get_content(self, filepath):
        filepath = os.path.normpath(self.get_path(filepath))

        if filepath in self.pre_result:
            f = codecs.open(filepath, 'r+', encoding='utf-8', errors='ignore')
            content = f.read()
            f.close()

            return content

        else:
            logger.warning("[AST] file {} parser not found...".format(filepath))
            return False

    def get_object(self, filepath):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result:
            return self.pre_result[filepath]
        else:
            logger.warning("[AST] file {} object not found...".format(filepath))
            return False

    def get_child_files(self, filepath):
        filepath = os.path.normpath(filepath)

        if filepath in self.pre_result and "child_files" in self.pre_result[filepath]:
            return self.pre_result[filepath]['child_files']

        elif os.path.join(self.target_directory, filepath) in self.pre_result and "child_files" in self.pre_result[
            os.path.join(self.target_directory, filepath)]:
            return self.pre_result[os.path.join(self.target_directory, filepath)]['child_files']

        else:
            logger.warning("[AST] file {} object or child files not found...".format(filepath))
            return False

    def get_define(self, define_name):
        if define_name in self.define_dict:
            return self.define_dict[define_name]

        else:
            logger.warning("[AST] [INCLUDE FOUND] Can't found this constart {}, pass it ".format(define_name))
            return "not_found"


ast_object = Pretreatment()
