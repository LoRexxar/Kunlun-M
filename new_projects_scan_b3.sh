#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"

PROJECTS="nodejs/node|v22.7.0|javascript
lodash/lodash|4.17.21|javascript
axios/axios|v1.7.4|javascript
request/request|v2.88.0|javascript
moment/moment|3.0.0|javascript
chaijs/chai|v4.5.0|javascript
socketio/socket.io-client|4.7.5|javascript
hapijs/hapi|v21.3.9|javascript
koa-js/koa|v2.15.3|javascript
marcj/marshal|v2.5.12|typescript
nest-land/axios|main|typescript
siyuan-note/siyuan|v3.1.15|javascript
codeigniter4/framework|v4.5.4|php
laravel/laravel|v11.20.0|php
cakephp/cakephp|5.0.8|php
slimphp/Slim|4.14.0|php
symfony/symfony|v7.1.3|php
dolibarr/dolibarr|develop|php
wordpress/wordpress|6.6.1|php"

while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"

    if [ -d "$outdir" ] && [ -n "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SKIP_DL $dir_name (exists)"
    else
        mkdir -p "$outdir"
        echo "[$(date)] DL $dir_name ($lang)"
        url="$PROXY/https://github.com/$repo/archive/$ref.tar.gz"
        curl -sL --max-time 300 "$url" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null
            curl -sL --max-time 300 "$FALLBACK/https://github.com/$repo/archive/$ref.tar.gz" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        fi
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            echo "[$(date)] DL_FAIL $dir_name"
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null
            rm -rf "$outdir"
            continue
        fi
        tar xzf "/tmp/${dir_name}.tar.gz" -C "$outdir" --strip-components=1
        if [ $? -ne 0 ]; then
            echo "[$(date)] EXTRACT_FAIL $dir_name"
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null
            rm -rf "$outdir"
            continue
        fi
        rm -f "/tmp/${dir_name}.tar.gz"
        fcount=$(find "$outdir" -type f | wc -l)
        echo "[$(date)] DL_OK $dir_name ($fcount files)"
        if [ "$fcount" -gt 5000 ]; then
            echo "[$(date)] TOO_BIG $dir_name, skipping"
            rm -rf "$outdir"
            continue
        fi
    fi
done <<< "$PROJECTS"
echo "=== DOWNLOAD DONE ==="

cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
find . -name __pycache__ -exec rm -rf {}+ 2>/dev/null

count=0
fail=0
while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"

    if [ ! -d "$outdir" ] || [ -z "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SCAN_SKIP $dir_name (no source)"
        continue
    fi

    echo "[$(date)] === SCAN $dir_name ($lang) ==="
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>/tmp/new_scan_b3_${dir_name}.log
    rc=$?
    echo "[$(date)] $dir_name scan done rc=$rc"
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
    echo "[$(date)] $dir_name source deleted"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
