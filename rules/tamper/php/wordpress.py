# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'WordPress'
DEPENDENCIES = {}


def detect(project_dir, language='php'):
    """检测是否为 WordPress 项目（含独立分发的 WP 插件源码树）"""
    # 标准 WP 安装
    if (os.path.exists(os.path.join(project_dir, 'wp-config.php'))
            or os.path.isdir(os.path.join(project_dir, 'wp-content'))
            or os.path.isdir(os.path.join(project_dir, 'wp-includes'))):
        return True
    # 独立分发的 WP 插件源码树（如 SVN 导出的 support-genix）：
    # 任一 php 头部含 "Plugin Name:"，或全库使用 WP 插件 API 钩子注册
    _has_plugin_header = False
    for root, dirs, fnames in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ('.svn', 'node_modules', 'vendor')]
        for fn in fnames:
            if not fn.endswith('.php'):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    head = f.read(4096)
            except OSError:
                continue
            if 'Plugin Name:' in head:
                _has_plugin_header = True
                break
        if _has_plugin_header:
            break
    if _has_plugin_header:
        # 主文件头 + 库内任一处 WP 钩子注册 → 判定 WP 插件树
        _hook_hits = 0
        for root, dirs, fnames in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in ('.svn', 'node_modules', 'vendor')]
            for fn in fnames:
                if not fn.endswith('.php'):
                    continue
                path = os.path.join(root, fn)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        body = f.read()
                except OSError:
                    continue
                for hook in ('add_action(', 'add_filter(', 'register_activation_hook('):
                    if hook in body:
                        _hook_hits += 1
                        break
            if _hook_hits >= 1:
                return True
    return False


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
    ('wp_redirect(', [1013]),
    ('include(', [1003]),
    ('require(', [1003]),
    ('$wpdb->insert(', [1004]),
    ('$wpdb->update(', [1004]),
    ('$wpdb->delete(', [1004]),
    ('$wpdb->replace(', [1004]),
    # Fix 42: WP 插件把 wpdb 存进对象属性（global $wpdb; $this->db = &$wpdb;）
    # 后经 $this->db->... 执行 SQL —— 同一 sink 的属性别名形态
    ('$this->db->query', [1004]),
    ('$this->db->get_results', [1004]),
    ('$this->db->get_var', [1004]),
    ('$this->db->get_row', [1004]),
    # Fix 42b: 查询构造器入口 —— 污点直接流入 ORDER BY 拼接
    # （order_by() 内部做 escape_key 字符级清洗，不防语义注入，见 CVE-2026-110895）
    ('->order_by(', [1004]),
    ('->SetDBOrder(', [1004]),
    ('->like(', [1004]),
    # Fix 42c: Model 查询入口（跨文件调用边缺失，参数即污点终点——
    # $orderBy 直通 ORDER BY 拼接，$likefld/$likeValue 直通 LIKE 拼接）
    ('->SelectAllGridData(', [1004]),
    ('->SelectAllWithIdentity(', [1004]),
    ('->FetchAll(', [1004]),
]
