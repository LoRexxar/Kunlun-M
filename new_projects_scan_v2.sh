#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"
LOG_PREFIX=/tmp/new_scan

# 项目列表：repo|ref|lang
PROJECTS="expressjs/express|4.21.0|javascript
socketio/socket.io|4.7.5|javascript
sequelize/sequelize|v7.0.0-alpha.4|javascript
nestjs/nest|v10.4.0|typescript
prisma/prisma|5.20.0|typescript
typegoose/typegoose|v12.0.0|typescript
gin-gonic/gin|v1.10.0|go
golang/crypto|v0.25.0|go
urfave/cli|v2.27.2|go
tokio-rs/tokio|tokio-1.39.0|rust
Kotlin/kotlinx.coroutines|1.8.1|kotlin
ktorio/ktor|2.3.12|kotlin
sinatra/sinatra|v4.0.0|ruby
jekyll/jekyll|v4.4.0|ruby
OpenResty/lua-nginx-module|v0.10.27|lua
jellyfin/jellyfin|v10.9.6|csharp
pallets/flask|3.0.3|python
pallets/click|8.1.7|python"

while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"
    
    # 跳过已下载的
    if [ -d "$outdir" ] && [ -n "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SKIP_DL $dir_name (exists)"
    else
        mkdir -p "$outdir"
        echo "[$(date)] DL $dir_name ($lang)"
        url="$PROXY/https://github.com/$repo/archive/$ref.tar.gz"
        curl -sL --max-time 300 "$url" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        # 验证
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            echo "[$(date)] RETRY $dir_name via fallback"
            rm -f "/tmp/${dir_name}.tar.gz"
            url2="$FALLBACK/https://github.com/$repo/archive/$ref.tar.gz"
            curl -sL --max-time 300 "$url2" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
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

echo "=== DOWNLOAD PHASE DONE ==="

# 扫描阶段
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
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>"${LOG_PREFIX}_${dir_name}.log"
    rc=$?
    echo "[$(date)] $dir_name scan done rc=$rc"
    
    if [ $rc -eq 0 ]; then
        count=$((count+1))
    else
        fail=$((fail+1))
    fi
    
    rm -rf "$outdir"
    echo "[$(date)] $dir_name source deleted"
done <<< "$PROJECTS"

echo "ALL DONE: scanned=$count failed=$fail"
