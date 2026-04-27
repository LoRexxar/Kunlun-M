# -*- coding: utf-8 -*-

import os
import subprocess
import sys


def _run_kunlun_command(*args):
    project_root = os.path.dirname(os.path.dirname(__file__))
    script = os.path.join(project_root, "kunlun.py")

    return subprocess.run(
        [sys.executable, script, *args],
        cwd=project_root,
        capture_output=True,
        text=True,
    )


def test_cli_help_works():
    result = _run_kunlun_command("-h")
    assert result.returncode == 0
    assert "Main Program" in result.stdout


def test_console_subcommand_help_works():
    result = _run_kunlun_command("console", "-h")
    assert result.returncode == 0
    assert "enter console mode" in result.stdout
