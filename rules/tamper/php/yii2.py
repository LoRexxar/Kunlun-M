# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Yii2'
DEPENDENCIES = {'composer': ['yiisoft/yii2']}


def detect(project_dir, language='php'):
    """检测是否为 Yii2 项目"""
    return (os.path.isfile(os.path.join(project_dir, 'config', 'web.php'))
            and os.path.isdir(os.path.join(project_dir, 'vendor', 'yiisoft')))


FILTER_FUNCTIONS = {
    'Html::encode': {'safe_for': [1000, 10001, 10002]},
    'HtmlPurifier::process': {'safe_for': [1000, 10001, 10002]},
    'Html::tag': {'safe_for': [1000, 1010]},
    'Yii::$app->db->quoteValue': {'safe_for': [1004]},
    'Yii::$app->security->hashData': {'safe_for': [1008]},
}

CONTROLLED_SOURCES = [
    'Yii::$app->request->get',
    'Yii::$app->request->post',
    'Yii::$app->request->getQueryParam',
    'Yii::$app->request->getBodyParam',
    'Yii::$app->request->getQueryParams',
    'Yii::$app->request->getBodyParams',
    'Yii::$app->request->getHeaders',
    'Yii::$app->request->getCookies',
    'Yii::$app->request->getRawBody',
]

EXTRA_SINKS = [
    ("->createCommand(", [1004]),
    ("Yii::\$app->db->createCommand(", [1004]),
    ("->render(", [1000]),
    ("->renderPartial(", [1000]),
    ("->renderAjax(", [1000]),
    ("->redirect(", [1013]),
    ("Yii::\$app->response->redirect(", [1013]),
]
