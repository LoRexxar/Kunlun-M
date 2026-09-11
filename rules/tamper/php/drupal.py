# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Drupal'
DEPENDENCIES = {'composer': ['drupal/core', 'drupal/drupal']}


def detect(project_dir, language='php'):
    """检测是否为 Drupal 项目"""
    return os.path.isfile(os.path.join(project_dir, 'core', 'lib', 'Drupal.php'))


FILTER_FUNCTIONS = {
    'check_plain': {'safe_for': [1000, 10001, 10002]},
    'drupal_html_class': {'safe_for': [1000]},
    'UrlHelper::stripDangerousProtocols': {'safe_for': [1000]},
    'Xss::filter': {'safe_for': [1000, 1010]},
    'Xss::filterAdmin': {'safe_for': [1000, 1010]},
    'Html::escape': {'safe_for': [1000, 1010, 10001]},
}

CONTROLLED_SOURCES = [
    '\\Drupal::request()->get',
    '\\Drupal::requestStack()->getCurrentRequest()->get',
    '\\Drupal::request()->query->get',
    '\\Drupal::request()->request->get',
    '$form_state->getValue',
]

EXTRA_SINKS = [
    ('\\Drupal::database()->query', [1004]),
    ('\\Drupal::database()->select', [1004]),
    ('->insert(', [1004]),
    ('->update(', [1004]),
    ('->delete(', [1004]),
    ('file_save_data(', [1002]),
    ('\\Drupal::httpClient(', [1005]),
    ('->redirect(', [1013]),
]
