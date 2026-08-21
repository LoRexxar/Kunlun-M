# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Chi'
DEPENDENCIES = {'gomod': ['github.com/go-chi/chi']}


def detect(project_dir, language='go'):
    """检测是否为 Chi 项目"""
    go_mod = os.path.join(project_dir, 'go.mod')
    if os.path.isfile(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'chi' in content and 'go-chi' in content:
                    return True
        except IOError:
            pass
    return False


FILTER_FUNCTIONS = {}

CONTROLLED_SOURCES = [
    'r.URL.Query',
    'chi.URLParam',
    'chi.URLParamFromCtx',
    'r.FormValue',
    'r.PostFormValue',
    'r.Header.Get',
    'r.Body',
    'r.Cookies',
    'r.Cookie',
]

EXTRA_SINKS = [
    ("http.Redirect(", [8013]),
    ("http.ServeFile(", [8004, 8006]),
    ("http.FileServer(", [8006]),
    # XSS sinks: direct text/html output
    ("w.Write(", [8003, 8008]),
    ("fmt.Fprintf(w,", [8003, 8008]),
    ("template.Execute(", [8003, 8008]),
    # NOT XSS: structured response
    ("json.NewEncoder(w).Encode(", [8008]),
]
