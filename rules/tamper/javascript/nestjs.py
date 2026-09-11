# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'NestJS'
DEPENDENCIES = {'package': ['@nestjs/core', '@nestjs/common']}


def detect(project_dir, language='javascript'):
    """检测是否为 NestJS 项目"""
    return os.path.isfile(os.path.join(project_dir, 'nest-cli.json'))


FILTER_FUNCTIONS = {
    'class-validator': [3100, 3101, 3102, 3104],
    'ValidationPipe': [3100, 3101, 3102, 3104],
}

CONTROLLED_SOURCES = [
    '@Body',
    '@Query',
    '@Param',
    '@Headers',
    '@Req',
    '@Request',
    '@Ip',
    '@Cookies',
    '@RequestPart',
]

EXTRA_SINKS = [
    ("res.render(", [3005]),
    ("res.redirect(", [3004]),
    ("res.json(", [3100, 3110]),
    # NOTE: res.send() sends HTTP responses, NOT commands. Not CVI-3100.
    ("res.sendFile(", [3102, 3106]),
    ("@Redirect(", [3109]),
    ("TypeOrm", [3104]),
]
