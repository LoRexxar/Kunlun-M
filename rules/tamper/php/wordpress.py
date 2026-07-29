# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'WordPress'
DEPENDENCIES = {}


def detect(project_dir, language='php'):
    """检测是否为 WordPress 项目"""
    return (os.path.exists(os.path.join(project_dir, 'wp-config.php'))
            or os.path.isdir(os.path.join(project_dir, 'wp-content'))
            or os.path.isdir(os.path.join(project_dir, 'wp-includes')))


FILTER_FUNCTIONS = {
    'esc_url': {'safe_for': [1000]},
    'sanitize_url': {'safe_for': [1000]},
    'sanitize_key': {'safe_for': [1000]},
    'esc_js': {'safe_for': [1000]},
    'esc_html': {'safe_for': [1000, 10001, 10002]},
    'esc_attr': {'safe_for': [1000, 10001, 10002]},
    'esc_textarea': {'safe_for': [1000, 10001, 10002]},
    'tag_escape': {'safe_for': [1000]},
    'esc_sql': {'safe_for': [1000]},
    '_real_escape': {'safe_for': [1000]},
    'wp_kses': {'safe_for': [1000, 1010]},
    'wp_kses_post': {'safe_for': [1000, 1010]},
    'sanitize_text_field': {'safe_for': [1000, 1010]},
    'sanitize_email': {'safe_for': [1000]},
    'sanitize_file_name': {'safe_for': [1006]},
    'sanitize_title': {'safe_for': [1000]},
    'absint': {'safe_for': [1004]},
    'wp_nonce_url': {'safe_for': [1009]},
}

CONTROLLED_SOURCES = [
    'get_query_var',
    '$wp_query->get',
    'filter_input',
]

EXTRA_SINKS = [
    ('$wpdb->query', [1004]),
    ('$wpdb->get_results', [1004]),
    ('$wpdb->get_var', [1004]),
    ('$wpdb->get_row', [1004]),
    ('$wpdb->prepare', []),
    ('wp_remote_get(', [1005]),
    ('wp_remote_post(', [1005]),
    ('wp_redirect(', [1009]),
    ('include(', [1003]),
    ('require(', [1003]),
    ('$wpdb->insert(', [1004]),
    ('$wpdb->update(', [1004]),
    ('$wpdb->delete(', [1004]),
    ('$wpdb->replace(', [1004]),
]
