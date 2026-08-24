#!/bin/bash
# 清理 datax 僵尸记录并补扫
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

# 等 priority 脚本完成（simple-login-app 在跑）
while kill -0 983763 2>/dev/null; do sleep 20; done

sqlite3 db/kunlun.db "DELETE FROM index_scanresulttask WHERE scan_task_id IN (SELECT id FROM index_scantask WHERE task_name='datax' AND id>=2690 AND is_finished=2); DELETE FROM index_scantask WHERE task_name='datax' AND id>=2690 AND is_finished=2;"

echo "[$(date +%H:%M:%S)] === datax 补扫 ==="
find . -name __pycache__ -exec rm -rf {} + 2>/dev/null
python3 kunlun.py scan -t "/home/ubuntu/realworld_scan_new/java/datax" --yes -lan java --no-cache 2>&1 | tail -3
echo "DATAX DONE"
