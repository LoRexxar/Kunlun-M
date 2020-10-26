#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: __init__.py.py
@time: 2020/10/14 15:11
@desc:

'''


import os
import traceback

from utils.log import logger
from Kunlun_M.settings import PLUGIN_PATH

PLUGIN_DICT = {}

try:
    files = os.listdir(PLUGIN_PATH)
    plugin_path_list = []

    for file in files:
        if os.path.isdir(os.path.join(PLUGIN_PATH, file)):
            if file != '__pycache__' and file != 'baseplugin':
                plugin_path_list.append(file)

    for plugin_name in plugin_path_list:
        plugin_class = __import__('core.plugins.' + plugin_name, fromlist=plugin_name)

        if plugin_class.PLUGIN_STATUS:
            PLUGIN_DICT[plugin_class.PLUGIN_NAME] = plugin_class.PLUGIN_OBJECT

except:
    logger.error("[Plugin init] Something error...{}".format(traceback.format_exc()))

PLUGIN_LIST = list(PLUGIN_DICT)

