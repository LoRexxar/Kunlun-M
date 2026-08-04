# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Laravel'
DEPENDENCIES = {'composer': ['laravel/framework']}


def detect(project_dir, language='php'):
    """检测是否为 Laravel 项目"""
    return (os.path.isfile(os.path.join(project_dir, 'app', 'Http', 'Kernel.php'))
            or os.path.isfile(os.path.join(project_dir, 'routes', 'web.php'))
            or os.path.isfile(os.path.join(project_dir, 'artisan')))


FILTER_FUNCTIONS = {
    'e()': {'safe_for': [1000, 10001, 10002]},
    'csrf_field': {'safe_for': []},
    'csrf_token': {'safe_for': []},
    # HTMLPurifier integration
    'Purifier::clean': {'safe_for': [1000, 1010]},
    'strip_tags': {'safe_for': [1000, 1010]},
    # URL encoding
    'urlencode': {'safe_for': [1005, 1006]},
    # signed redirect is safe
    'redirect()->signedRoute': {'safe_for': [1009]},
}

EXTRA_SINKS = [
    # DB facade — raw SQL methods
    ("DB::raw", [1004]),
    ("DB::select", [1004]),
    ("DB::statement", [1004]),
    ("DB::unprepared", [1004]),
    ("DB::insert", [1004]),
    ("DB::update", [1004]),
    ("DB::delete", [1004]),
    # Query Builder / Eloquent — raw SQL injection vectors
    ("->selectRaw(", [1004]),
    ("->whereRaw(", [1004]),
    ("->havingRaw(", [1004]),
    ("->orderByRaw(", [1004]),
    ("->groupByRaw(", [1004]),
    # View / Response — XSS sinks
    ("view(", [1000]),
    ("Response::json(", [1000]),
    # Redirect — Open Redirect
    ("redirect(", [1009]),
    # Storage — File operation
    ("Storage::download(", [1002]),
    ("Storage::get(", [1002]),
]

CONTROLLED_SOURCES = [
    'request()->input',
    'request()->get',
    'request()->post',
    'request()->query',
    'request()->cookie',
    '$request->input',
    '$request->query',
    '$request->post',
    '$request->cookie',
    'request()->header',
    '$request->header',
    '$request->ip',
    '$request->userAgent',
    'Request::get',
    'Request::input',
    'Request::query',
    'Request::post',
    'Request::cookie',
    'Request::header',
    'request()',
    '$request',
    'input()',
    'old()',
    'request()->all',
    'request()->file',
    'request()->bearerToken',
    '$request->all',
    '$request->files',
]
