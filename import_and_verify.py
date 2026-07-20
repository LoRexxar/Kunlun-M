#!/usr/bin/env python3
"""
批量导入CSV结果并标记验证状态
用法:
  python import_and_verify.py import <csv_file> [task_id]  # 导入CSV
  python import_and_verify.py mark <task_id> <status>      # 批量标记任务
  python import_verify.py mark-all <status>                # 标记所有为指定状态
"""

import os
import sys
import csv
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from web.index.models import ScanResultTask, ScanTask
from django.utils import timezone


def import_csv(csv_file, task_id=None):
    """导入CSV文件到数据库"""
    if not os.path.exists(csv_file):
        print(f"文件不存在: {csv_file}")
        return
    
    # 尝试从文件名推断task_id
    if task_id is None:
        basename = os.path.basename(csv_file).replace('.csv', '')
        task = ScanTask.objects.filter(task_name=basename).first()
        if task:
            task_id = task.id
            print(f"从文件名推断任务: {task.task_name} (ID: {task_id})")
        else:
            print(f"无法推断任务ID，请手动指定")
            return
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            try:
                # 创建或更新结果
                result = ScanResultTask(
                    scan_task_id=task_id,
                    cvi_id=row.get('id', ''),
                    language=row.get('language', ''),
                    vulfile_path=row.get('location', ''),
                    source_code=row.get('analysis', '')[:200],
                    result_type=row.get('rule_name', ''),
                    is_unconfirm=row.get('is_unconfirm', 'False') == 'True',
                )
                result.save()
                count += 1
            except Exception as e:
                print(f"导入失败: {e}")
        
        print(f"成功导入 {count} 条结果")


def mark_task(task_id, status):
    """批量标记任务的所有结果"""
    valid_statuses = ['pending', 'tp', 'fp', 'unknown']
    if status not in valid_statuses:
        print(f"无效状态: {status}，可选: {valid_statuses}")
        return
    
    task = ScanTask.objects.filter(id=task_id).first()
    if not task:
        print(f"任务 {task_id} 不存在")
        return
    
    count = ScanResultTask.objects.filter(
        scan_task_id=task_id
    ).update(
        verification_status=status,
        verified_by='batch_mark',
        verified_at=timezone.now()
    )
    
    print(f"已将任务 [{task_id}] {task.task_name} 的 {count} 条结果标记为: {status}")


def mark_all(status):
    """批量标记所有结果"""
    valid_statuses = ['pending', 'tp', 'fp', 'unknown']
    if status not in valid_statuses:
        print(f"无效状态: {status}，可选: {valid_statuses}")
        return
    
    count = ScanResultTask.objects.all().update(
        verification_status=status,
        verified_by='batch_mark',
        verified_at=timezone.now()
    )
    
    print(f"已将所有 {count} 条结果标记为: {status}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    
    action = sys.argv[1]
    
    if action == 'import' and len(sys.argv) >= 3:
        csv_file = sys.argv[2]
        task_id = int(sys.argv[3]) if len(sys.argv) > 3 else None
        import_csv(csv_file, task_id)
    elif action == 'mark' and len(sys.argv) >= 4:
        task_id = int(sys.argv[2])
        status = sys.argv[3]
        mark_task(task_id, status)
    elif action == 'mark-all' and len(sys.argv) >= 3:
        status = sys.argv[2]
        mark_all(status)
    else:
        print(__doc__)
