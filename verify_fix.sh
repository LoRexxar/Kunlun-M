#!/bin/bash
# 验证 request.url 修复：重扫 simple-login-app
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DL_DIR="/home/ubuntu/realworld_scan_redownload"
T="$DL_DIR/simple-login-app"
rm -rf "$T" "$T.tar.gz" 2>/dev/null
curl -sL "https://ghfast.top/https://github.com/simple-login/app/archive/refs/heads/master.tar.gz" -o "$T.tar.gz"
mkdir -p "$T" && tar xzf "$T.tar.gz" -C "$T" --strip-components=1 && rm -f "$T.tar.gz"

echo "[$(date +%H:%M:%S)] rescanning simple-login/app with fix"
find . -name __pycache__ -exec rm -rf {} + 2>/dev/null
python3 kunlun.py scan -t "$T" --yes -lan python --no-cache 2>&1 | tail -3
rm -rf "$T"
echo "VERIFY DONE"
