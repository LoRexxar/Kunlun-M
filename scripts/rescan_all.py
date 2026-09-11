#!/usr/bin/env python3
"""重新扫描 realworld_scan_new 中所有有源码的项目"""

import os
import sys
import json
import requests
import time

# Django 环境
os.environ['DJANGO_SETTINGS_MODULE'] = 'Kunlun_M.settings'
sys.path.insert(0, '/home/ubuntu/.hermes/hermes-agent/Kunlun-M')

import django
django.setup()

from web.index.models import ScanTask

BASE_DIR = '/home/ubuntu/realworld_scan_new'
API_URL = 'http://127.0.0.1:9999/api/task/create'
TOKEN = 'secret_api_token'

# 收集所有项目
projects = []
for lang in ['java', 'php', 'python', 'go', 'rust', 'lua', 'javascript', 'c', 'cpp', 'ruby', 'csharp', 'kotlin']:
    lang_dir = os.path.join(BASE_DIR, lang)
    if not os.path.exists(lang_dir):
        continue
    for name in os.listdir(lang_dir):
        full_path = os.path.join(lang_dir, name)
        if os.path.isdir(full_path):
            projects.append((lang, name, full_path))

print(f"找到 {len(projects)} 个项目")

# 检查哪些已经扫描过（最近的任务）
scanned = set()
for t in ScanTask.objects.filter(is_finished__in=[1, 2]).order_by('-id')[:200]:
    target = str(t.target_path)
    scanned.add(target)

# 创建新的扫描任务
created = 0
skipped = 0
for lang, name, path in projects:
    if path in scanned:
        skipped += 1
        continue
    
    # 通过 API 创建任务
    resp = requests.post(API_URL, data={
        'task_name': name,
        'target_path': path,
        'apitoken': TOKEN,
    })
    
    if resp.status_code == 200:
        data = resp.json()
        if data.get('status'):
            created += 1
            msg = data.get('message', {})
            if isinstance(msg, dict):
                print(f"  [OK] {lang}/{name} -> Task {msg.get('task_id', '?')}")
            else:
                print(f"  [OK] {lang}/{name} -> {msg}")
        else:
            print(f"  [ERR] {lang}/{name}: {data}")
    else:
        print(f"  [ERR] {lang}/{name}: HTTP {resp.status_code}")
    
    time.sleep(0.1)

print(f"\n创建: {created}个, 跳过(已扫描): {skipped}个")
