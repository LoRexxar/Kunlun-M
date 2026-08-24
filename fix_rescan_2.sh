#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"

PROJECTS="pion/webrtc|v3.0.6|go
shirou/gopsutil|v3.24.4|go
denoland/deno|v1.45.4|typescript
fastify/fastify|v5.0.2|javascript
gofiber/fiber|v2.52.6|go
kataras/iris|v12.2.11|go
rethinkdb/rethinkdb|v2.4.3|javascript
expressjs/morgan|1.10.0|javascript
lodash/lodash|4.17.21|javascript
axios/axios|v1.7.5|javascript
request/request|v2.88.0|javascript
chaijs/chai|v4.5.0|javascript
socketio/socket.io-client|v4.7.5|javascript
hapijs/hapi|v21.3.10|javascript
siyuan-note/siyuan|v3.1.8|javascript
codeigniter4/framework|v4.5.4|php
cakephp/cakephp|5.0.10|php
slimphp/Slim|4.12.0|php
wordpress/wordpress|6.6.1|php
jesseduffield/lazygit|v0.43.1|go"

while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"
    if [ -d "$outdir" ] && [ -n "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SKIP_DL $dir_name"
    else
        mkdir -p "$outdir"
        echo "[$(date)] DL $dir_name ($lang)"
        curl -sL --max-time 300 "$PROXY/https://github.com/$repo/archive/$ref.tar.gz" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null
            curl -sL --max-time 300 "$FALLBACK/https://github.com/$repo/archive/$ref.tar.gz" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        fi
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            echo "[$(date)] DL_FAIL $dir_name"; rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
        fi
        tar xzf "/tmp/${dir_name}.tar.gz" -C "$outdir" --strip-components=1 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[$(date)] EXTRACT_FAIL $dir_name"; rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
        fi
        rm -f "/tmp/${dir_name}.tar.gz"
        fcount=$(find "$outdir" -type f | wc -l)
        echo "[$(date)] DL_OK $dir_name ($fcount files)"
        if [ "$fcount" -gt 5000 ]; then
            echo "[$(date)] TOO_BIG $dir_name"; rm -rf "$outdir"; continue
        fi
    fi
done <<< "$PROJECTS"
echo "=== DOWNLOAD DONE ==="

cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
find . -name __pycache__ -exec rm -rf {}+ 2>/dev/null

count=0; fail=0
while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"
    if [ ! -d "$outdir" ] || [ -z "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SCAN_SKIP $dir_name"; continue
    fi
    echo "[$(date)] === SCAN $dir_name ($lang) ==="
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>/tmp/fix_r2_${dir_name}.log
    rc=$?
    echo "[$(date)] $dir_name done rc=$rc"
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
