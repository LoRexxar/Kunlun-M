# -*- coding: utf-8 -*-

import importlib
import types

import Kunlun_M.settings as settings


def _build_fake_readline_module(with_get_output_file=True):
    module = types.ModuleType("fake_readline")
    module.parse_and_bind = lambda *args, **kwargs: None
    module.set_completer = lambda *args, **kwargs: None
    module.set_completer_delims = lambda *args, **kwargs: None
    module.read_history_file = lambda *args, **kwargs: None
    module.write_history_file = lambda *args, **kwargs: None
    module.set_history_length = lambda *args, **kwargs: None
    module.clear_history = lambda *args, **kwargs: None
    module.get_line_buffer = lambda: ""
    module.get_begidx = lambda: 0
    module.get_endidx = lambda: 0

    if with_get_output_file:
        module.GetOutputFile = lambda: None

    return module


def test_windows_backend_without_getoutputfile_still_available(monkeypatch):
    fake_backend = _build_fake_readline_module(with_get_output_file=False)
    monkeypatch.setitem(importlib.sys.modules, "readline", fake_backend)
    monkeypatch.setattr(settings, "PLATFORM", "windows")

    import utils.readlineng as readlineng

    importlib.reload(readlineng)

    assert readlineng._readline is fake_backend


def test_fallback_to_pyreadline3_when_others_unavailable(monkeypatch):
    fake_backend = _build_fake_readline_module()
    original_import_module = importlib.import_module

    def _fake_import_module(name, package=None):
        if name in ("readline", "pyreadline"):
            raise ImportError
        if name == "pyreadline3":
            return fake_backend
        return original_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", _fake_import_module)
    monkeypatch.setattr(settings, "PLATFORM", "windows")

    import utils.readlineng as readlineng

    importlib.reload(readlineng)

    assert readlineng._readline is fake_backend
