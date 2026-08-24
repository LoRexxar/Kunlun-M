#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"

PROJECTS="expressjs/express|4.21.0|javascript
socketio/socket.io|4.7.5|javascript
sequelize/sequelize|v7.0.0-alpha.1|javascript
nestjs/nest|v10.4.2|typescript
prisma/prisma|5.20.0|typescript
typegoose/typegoose|v12.5.0|typescript
gin-gonic/gin|v1.10.0|go
golang/crypto|v0.25.0|go
urfave/cli|v2.27.4|go
tokio-rs/tokio|tokio-1.39.2|rust
Kotlin/kotlinx.coroutines|1.9.0-RC|kotlin
sinatra/sinatra|v4.1.1|ruby
jekyll/jekyll|v4.3.0|ruby
OpenResty/lua-nginx-module|v0.10.26|lua
jellyfin/jellyfin|v10.9.6|csharp
pallets/flask|3.0.3|python
pallets/click|8.1.7|python
strapi/strapi|v4.25.1|javascript
labstack/echo|v4.12.0|go
go-chi/chi|v5.1.0|go"

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
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>/tmp/fix_r1_${dir_name}.log
    rc=$?
    echo "[$(date)] $dir_name done rc=$rc"
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
