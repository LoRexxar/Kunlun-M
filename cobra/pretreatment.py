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

from .log import logger
from .const import ext_dict

import gc
import os
import re
import json
import time
import codecs
import traceback
import zipfile
import queue
import asyncio

could_ast_pase_lans = ["php", "chromeext", "javascript", "html"]


def un_zip(target_path):
    """
    解压缩目标压缩包
    实现新需求，解压缩后相应的js文件做代码格式化
    :return: 
    """

    logger.info("[Pre][Unzip] Upzip file {}...".format(target_path))

    if not os.path.isfile(target_path):
        logger.warn("[Pre][Unzip] Target file {} is't exist...pass".format(target_path))
        return False

    zip_file = zipfile.ZipFile(target_path)
    target_file_path = target_path + "_files/"

    if os.path.isdir(target_file_path):
        logger.debug("[Pre][Unzip] Target files {} is exist...continue".format(target_file_path))
        return target_file_path
    else:
        os.mkdir(target_file_path)

    for names in zip_file.namelist():
        zip_file.extract(names, target_file_path)

        # 对其中部分文件中为js的时候，将js代码格式化便于阅读
        if names.endswith(".js"):
            file_path = os.path.join(target_file_path, names)
            file = codecs.open(file_path, 'r+', encoding='utf-8', errors='ignore')
            file_content = file.read()
            file.close()

            new_file = codecs.open(file_path, 'w+', encoding='utf-8', errors='ignore')

            opts = jsbeautifier.default_options()
            opts.indent_size = 2

            new_file.write(jsbeautifier.beautify(file_content, opts))
            new_file.close()

    zip_file.close()

    return target_file_path


class Pretreatment:

    def __init__(self):
        self.file_list = []
        self.target_queue = queue.Queue()
        self.target_directory = ""
        self.lan = None
        self.is_unprecom = False

        self.pre_result = {}
        self.define_dict = {}

        # self.pre_ast_all()

    def init_pre(self, target_directory, files):
        self.file_list = files
        self.target_directory = target_directory

        self.target_directory = os.path.normpath(self.target_directory)

    def get_path(self, filepath):
        os.chdir(os.path.dirname(os.path.dirname(__file__)))

        if os.path.isfile(filepath):
            return os.path.normpath(filepath)

        if os.path.isfile(os.path.normpath(os.path.join(self.target_directory, filepath))):
            return os.path.normpath(os.path.join(self.target_directory, filepath))

        if os.path.isfile(self.target_directory):
            return os.path.normpath(self.target_directory)
        else:
            return os.path.normpath(os.path.join(self.target_directory, filepath))

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

        loop = asyncio.get_event_loop()
        scan_list = (self.pre_ast() for i in range(10))
        loop.run_until_complete(asyncio.gather(*scan_list))

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

                                key = define_params[0].node
                                if isinstance(key, php.Constant):
                                    key = key.name

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
                            manifest = json.loads(manifest_content, encoding='utf-8')

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

                        if not os.path.isfile(new_filepath):
                            fi2 = codecs.open(new_filepath, "w", encoding='utf-8', errors='ignore')
                            code_content = jsbeautifier.beautify(code_content)
                            fi2.write(code_content)
                            fi2.close()

                        # self.pre_result[filepath]['content'] = code_content
                        if not self.is_unprecom:
                            all_nodes = esprima.parse(code_content, {"loc": True})
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
                        logger.log('[AST] stop...')
                        exit()

                    except:
                        logger.warning('[AST] something error, {}'.format(traceback.format_exc()))
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
                    allnodes = self.pre_result[filepath]['ast_nodes'].body

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

    # def get_content(self, filepath):
    #     filepath = os.path.normpath(filepath)
    #
    #     if filepath in self.pre_result:
    #         return self.pre_result[filepath]['content']
    #
    #     else:
    #         logger.warning("[AST] file {} parser not found...".format(filepath))
    #         return False

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
