# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'ThinkPHP'
DEPENDENCIES = {'composer': ['topthink/framework']}


def detect(project_dir, language='php'):
    """检测是否为 ThinkPHP 项目

    ThinkPHP 5/6/8 的目录结构差异:
    - TP5:  thinkphp/ 目录 或 tp5.php 入口
    - TP6+: app/ + config/app.php (标准单应用模式)
    - ShopXO 等: app/ 目录 + ThinkPHP 风格的控制器结构
              但没有 thinkphp/ 目录 (框架在 vendor 里)
    - composer.json 中有 topthink/framework
    """
    # TP5 传统结构
    if os.path.isdir(os.path.join(project_dir, 'thinkphp')):
        return True
    if os.path.isfile(os.path.join(project_dir, 'tp5.php')):
        return True

    # TP6+/8: app/ 目录 + ThinkPHP 特征文件
    app_dir = os.path.join(project_dir, 'app')
    if os.path.isdir(app_dir):
        # ThinkPHP 风格的控制器目录
        tp_controllers = [
            'app/index/controller',
            'app/admin/controller',
            'app/api/controller',
            'app/home/controller',
        ]
        if any(os.path.isdir(os.path.join(project_dir, d)) for d in tp_controllers):
            # 进一步确认: 检查是否有 ThinkPHP 的 config 结构
            config_paths = [
                'config/app.php',
                'app/config.php',
                'app/provider.php',
                'app/middleware.php',
            ]
            if any(os.path.isfile(os.path.join(project_dir, p)) for p in config_paths):
                return True

    # composer.json 检测 (fallback)
    composer_json = os.path.join(project_dir, 'composer.json')
    if os.path.isfile(composer_json):
        try:
            import json
            with open(composer_json, 'r') as f:
                data = json.load(f)
            deps = data.get('require', {})
            if 'topthink/framework' in deps or 'topthink/think' in deps:
                return True
        except (json.JSONDecodeError, OSError):
            pass

    return False


FILTER_FUNCTIONS = {
    'think\\facade\\Validate': {'safe_for': [1000, 1001, 1004]},
    'Db::where': {'safe_for': [1004]},  # param binding
    'request': {'safe': True},  # ThinkPHP request() facade — input is filtered by default
}

EXTRA_SINKS = [
    ("Db::query(", [1004]),
    ("Db::execute(", [1004]),
    ("Db::name(", [1004]),
    ("Cache::", [1004]),
    # Query Builder — raw SQL injection vectors
    ("->query(", [1004]),
    ("->execute(", [1004]),
    ("->fetchSql(", [1004]),
    # Template engine — XSS
    ("->fetch(", [1000]),
    ("->display(", [1000]),
    # Redirect
    ("redirect(", [1013]),
]

CONTROLLED_SOURCES = [
    'Input', 'request', 'I', 'input',
    '$this->request->param',
    '$this->request->get',
    '$this->request->post',
    '$this->request->header',
    'request()->param',
    'request()->get',
    'request()->post',
]
