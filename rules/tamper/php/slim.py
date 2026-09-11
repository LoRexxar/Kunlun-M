# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Slim'
DEPENDENCIES = {'composer': ['slim/slim']}


def detect(project_dir, language='php'):
    """检测是否为 Slim 项目"""
    return os.path.isfile(os.path.join(project_dir, 'public', 'index.php'))


FILTER_FUNCTIONS = {}
# Slim relies on _base.php standard library filter functions

CONTROLLED_SOURCES = [
    '$request->getParsedBody',
    '$request->getQueryParams',
    '$request->getParams',
    '$request->getParam',
    '$args',
    '$request->getAttribute',
    '$request->getCookieParams',
    '$request->getUploadedFiles',
]

EXTRA_SINKS = [
    ("$response->write(", [1000]),
    ("$app->render(", [1000]),
    ("$view->render(", [1000]),
    ("$response->withRedirect(", [1013]),
]
