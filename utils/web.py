#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: web.py
@time: 2021/7/1 18:03
@desc:

'''

import os
import requests

from Kunlun_M.settings import REMOTE_URL, REMOTE_URL_APITOKEN

from utils.log import logger


def upload_log(logpath):
    """
    上传日志到远程
    :param logpath:
    :return:
    """

    remote_upload_url = "{}/backend/uploadlog?apitoken={}".format(REMOTE_URL, REMOTE_URL_APITOKEN)

    if not os.path.exists(logpath):
        logger.warning("[UPLOAD LOG] log {} not exist.".format(logpath))
        return False

    files = {
        "file": open(logpath, "rb")
    }

    r = requests.post(remote_upload_url, files=files)

    if r.status_code != 200:
        logger.warning("[UPLOAD LOG] upload log to {} error. response is {}".format(REMOTE_URL, r.text))
        return False

    logger.info("[UPLOAD LOG] upload log {} success".format(logpath))
    return True
