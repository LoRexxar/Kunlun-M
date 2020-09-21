#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: readlineng.py
@time: 2020/8/25 15:27
@desc:

'''

from .utils import logger

from Kunlun_M.settings import PLATFORM

_readline = None

try:
    from readline import *
    import readline as _readline
except ImportError:
    try:
        from pyreadline import *
        import pyreadline as _readline
    except ImportError:
        # raise PocsuiteSystemException("Import pyreadline faild,try pip3 install pyreadline")
        pass

if PLATFORM == 'windows' and _readline:
    try:
        _outputfile = _readline.GetOutputFile()
    except AttributeError:
        debugMsg = "Failed GetOutputFile when using platform's "
        debugMsg += "readline library"
        logger.debug(debugMsg)

        _readline = None

# Test to see if libedit is being used instead of GNU readline.
# Thanks to Boyd Waters for this patch.
uses_libedit = False

if PLATFORM == 'mac' and _readline:
    import subprocess

    (status, result) = subprocess.getstatusoutput("otool -L %s | grep libedit" % _readline.__file__)

    if status == 0 and len(result) > 0:
        # We are bound to libedit - new in Leopard
        _readline.parse_and_bind("bind ^I rl_complete")

        debug_msg = "Leopard libedit detected when using platform's "
        debug_msg += "readline library"
        logger.debug(debug_msg)

        uses_libedit = True

# the clear_history() function was only introduced in Python 2.4 and is
# actually optional in the readline API, so we must explicitly check for its
# existence.  Some known platforms actually don't have it.  This thread:
# http://mail.python.org/pipermail/python-dev/2003-August/037845.html
# has the original discussion.
if _readline:
    try:
        _readline.clear_history()
    except AttributeError:
        def clear_history():
            pass


        _readline.clear_history = clear_history
