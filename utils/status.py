#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: status.py
@time: 2021/8/11 15:31
@desc:

'''

from web.index.models import ScanTask


SCAN_ID = -1


def get_scan_id():
    global SCAN_ID

    if SCAN_ID > 0:
        return SCAN_ID
    else:
        s = ScanTask.objects.order_by("-id").first()
        SCAN_ID = s.id

    return SCAN_ID
