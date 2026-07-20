#!/usr/bin/env python3
"""
扫描结果验证脚本 - 逐条验证 TP/FP
用法:
  python verify_results.py [task_id]     # 验证指定任务的所有结果
  python verify_results.py --all         # 验证所有任务
  python verify_results.py --stats       # 显示统计信息
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from web.index.models import ScanResultTask, ScanTask, TaintChain
from django.utils import timezone


def get_stats():
    """显示验证统计"""
    total = ScanResultTask.objects.count()
    by_status = {}
    for status, label in ScanResultTask.VERIFICATION_CHOICES:
        count = ScanResultTask.objects.filter(verification_status=status).count()
        by_status[label] = count
    
    print(f"\n{'='*60}")
    print(f"扫描结果验证统计")
    print(f"{'='*60}")
    print(f"总计: {total} 条结果")
    print(f"-"*60)
    for label, count in by_status.items():
        pct = (count / total * 100) if total > 0 else 0
        print(f"  {label}: {count} ({pct:.1f}%)")
    print(f"-"*60)
    
    # 按项目统计
    print(f"\n按项目统计 (待验证):")
    print(f"-"*60)
    tasks = ScanTask.objects.all().order_by('-id')
    for task in tasks:
        pending = ScanResultTask.objects.filter(
            scan_task_id=task.id,
            verification_status='pending'
        ).count()
        if pending > 0:
            total_task = ScanResultTask.objects.filter(scan_task_id=task.id).count()
            print(f"  [{task.id}] {task.task_name}: {pending}/{total_task} 待验证")


def show_chain(vul_result_id):
    """显示传播链"""
    chains = TaintChain.objects.filter(vul_result=vul_result_id).order_by('chain_index', 'step_order')
    if not chains:
        return "  (无传播链)"
    
    lines = []
    current_chain = -1
    for chain in chains:
        if chain.chain_index != current_chain:
            current_chain = chain.chain_index
            lines.append(f"  Chain {chain.chain_index}:")
        
        # 简化显示
        name = chain.node_name
        if len(name) > 60:
            name = name[:57] + "..."
        file_info = f"{os.path.basename(chain.file_path)}:{chain.lineno}" if chain.file_path else ""
        lines.append(f"    [{chain.step_order}] {chain.node_label}: {name} @ {file_info}")
    
    return "\n".join(lines)


def verify_result(result, auto_status=None):
    """验证单条结果"""
    print(f"\n{'='*60}")
    print(f"ID: {result.id} | CVI: {result.cvi_id} | 类型: {result.result_type}")
    print(f"语言: {result.language}")
    print(f"文件: {result.vulfile_path}")
    print(f"代码: {result.source_code[:80]}...")
    print(f"当前状态: {result.get_verification_status_display()}")
    
    # 显示传播链
    print(f"\n传播链:")
    print(show_chain(result.id))
    
    if auto_status:
        status = auto_status
        print(f"\n>> 自动标记为: {status}")
    else:
        print(f"\n验证选项:")
        print(f"  [t] TP (True Positive - 真阳性)")
        print(f"  [f] FP (False Positive - 误报)")
        print(f"  [u] Unknown (无法判断)")
        print(f"  [s] Skip (跳过)")
        print(f"  [q] Quit (退出)")
        
        choice = input("\n请选择: ").strip().lower()
        
        status_map = {'t': 'tp', 'f': 'fp', 'u': 'unknown'}
        if choice == 'q':
            return False
        elif choice == 's':
            return True
        elif choice in status_map:
            status = status_map[choice]
        else:
            print("无效选择，跳过")
            return True
    
    # 更新数据库
    result.verification_status = status
    result.verified_by = 'manual_review'
    result.verified_at = timezone.now()
    result.save()
    
    print(f">> 已更新为: {status}")
    return True


def verify_task(task_id, auto_status=None):
    """验证指定任务的所有结果"""
    task = ScanTask.objects.filter(id=task_id).first()
    if not task:
        print(f"任务 {task_id} 不存在")
        return
    
    results = ScanResultTask.objects.filter(
        scan_task_id=task_id
    ).order_by('id')
    
    print(f"\n开始验证任务: [{task.id}] {task.task_name}")
    print(f"共 {results.count()} 条结果")
    
    for i, result in enumerate(results, 1):
        print(f"\n--- [{i}/{results.count()}] ---")
        if not verify_result(result, auto_status):
            break
    
    print(f"\n验证完成!")


def verify_all(auto_status=None):
    """验证所有任务"""
    tasks = ScanTask.objects.all().order_by('-id')
    
    for task in tasks:
        count = ScanResultTask.objects.filter(
            scan_task_id=task.id,
            verification_status='pending'
        ).count()
        if count > 0:
            verify_task(task.id, auto_status)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        get_stats()
        sys.exit(0)
    
    if sys.argv[1] == '--stats':
        get_stats()
    elif sys.argv[1] == '--all':
        verify_all()
    elif sys.argv[1] == '--auto-fp':
        # 自动标记所有为 FP（用于批量初筛）
        verify_all(auto_status='fp')
    elif sys.argv[1] == '--auto-tp':
        # 自动标记所有为 TP
        verify_all(auto_status='tp')
    else:
        try:
            task_id = int(sys.argv[1])
            verify_task(task_id)
        except ValueError:
            print(f"无效参数: {sys.argv[1]}")
            print(__doc__)
