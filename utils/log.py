# -*- coding: utf-8 -*-

"""
    log
    ~~~

    Implements color logger

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import logging
import colorlog
from Kunlun_M.settings import LOGS_PATH

# stream handle
#
# Copyright (C) 2010-2012 Vinay Sajip. All rights reserved. Licensed under the new BSD license.
#
logger = logging.getLogger('KunlunLog')
logger_console = logging.getLogger('KunlunConsoleLog')
log_path = LOGS_PATH


def log(loglevel):
    if os.path.isdir(log_path) is not True:
        os.mkdir(log_path, 0o755)

    log_name = 'main'
    logfile = os.path.join(log_path, log_name + '.log')

    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            # fmt='%(log_color)s [%(asctime)s][%(filename)s:%(lineno)d] %(message)s',
            fmt='%(log_color)s [%(asctime)s] %(message)s',
            datefmt="%H:%M:%S",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        )
    )
    f = open(logfile, 'a+')
    handler2 = logging.StreamHandler(f)
    formatter = logging.Formatter(
        "[%(levelname)s][%(threadName)s][%(asctime)s][%(filename)s:%(lineno)d] %(message)s")
    handler2.setFormatter(formatter)
    logger.addHandler(handler2)
    logger.addHandler(handler)

    logger.setLevel(logging.INFO)


def log_add(loglevel, log_name):
    if os.path.isdir(log_path) is not True:
        os.mkdir(log_path, 0o755)

    # rm old handler
    mainlogfile = os.path.join(log_path, 'main.log')
    f = open(mainlogfile, 'a+')
    handler = logging.StreamHandler(f)
    logger.removeHandler(handler)

    # new handler
    logfile = os.path.join(log_path, log_name + '.log')
    f2 = open(logfile, 'a+')
    handler2 = logging.StreamHandler(f2)
    formatter = logging.Formatter(
        "[%(levelname)s][%(threadName)s][%(asctime)s][%(filename)s:%(lineno)d] %(message)s")
    handler2.setFormatter(formatter)
    logger.addHandler(handler2)

    logger.setLevel(logging.INFO)


def log_console():
    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            fmt='%(log_color)s %(message)s',
            datefmt="%H:%M:%S",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'white',
                'WARNING': 'bold_yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        )
    )
    logger_console.addHandler(handler)

    logger_console.setLevel(logging.DEBUG)


def log_rm():
    for handler in logger.handlers:
        if handler.__str__() == colorlog.StreamHandler().__str__():
            logger.removeHandler(handler)

    for handler in logger_console.handlers:
        if handler.__str__() == colorlog.StreamHandler().__str__():
            logger_console.removeHandler(handler)

    logger_console.setLevel(logging.ERROR)


log_console()
