#!/bin/bash
set -e
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

for entry in "chartjs-Chart.js-9c5cf9f:javascript" "highlightjs-highlight.js-15d3b62:javascript" "ggml-org-llama.cpp-7be099f:c"; do
    name="${entry%%:*}"
    lang="${entry##*:}"
    echo "[$(date)] === Scanning $name ($lang) ==="
    timeout 1800 python3 kunlun.py scan -t "/home/ubuntu/realworld_scan_redownload/$name" --yes -lan "$lang" --no-cache 2>/tmp/scan_${name}.log
    rc=$?
    echo "[$(date)] $name done rc=$rc"
    # 删除源码节省磁盘
    rm -rf "/home/ubuntu/realworld_scan_redownload/$name"
    echo "[$(date)] $name source deleted"
done
echo "ALL DONE"