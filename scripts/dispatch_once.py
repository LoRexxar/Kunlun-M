#!/usr/bin/env python3
"""扫描调度器：回收死进程 + 触发新扫描"""
import os
import sys
import django

os.environ['DJANGO_SETTINGS_MODULE'] = 'Kunlun_M.settings'
sys.path.insert(0, '/home/ubuntu/.hermes/hermes-agent/Kunlun-M')
django.setup()

from web.index.scan_dispatcher import try_dispatch
from web.index.models import ScanTask

result = try_dispatch()
running = ScanTask.objects.filter(is_finished=2).count()
pending = ScanTask.objects.filter(is_finished=3).count()
success = ScanTask.objects.filter(is_finished=1, id__gte=286).count()
failed = ScanTask.objects.filter(is_finished=0, id__gte=286).count()

if result > 0 or running > 0 or pending > 0:
    print(f'started={result} running={running} pending={pending} done={success} failed={failed}')
if pending == 0 and running == 0 and (success > 0 or failed > 0):
    print(f'ALL DONE - {success} completed, {failed} failed')
