#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"
LOG_PREFIX=/tmp/new_scan_b2

PROJECTS="strapi/strapi|v4.25.1|javascript
adonisjs/core|v6.5.0|javascript
gatsbyjs/gatsby|v5.13.7|typescript
vercel/next.js|canary|javascript
ejs模板/ejs|v3.1.10|javascript
labstack/echo|v4.12.0|go
go-chi/chi|v5.1.0|go
pion/webrtc|v3.3.4|go
shirou/gopsutil|v3.24.3|go
denoland/deno|v1.40.3|typescript
fastify/fastify|v4.28.0|javascript
molnarmark/colly|v1.2.0|go
gofiber/fiber|v2.52.4|go
kataras/iris|v12.2.10|go
rethinkdb/rethinkdb|v2.4.4|javascript
expressjs/morgan|1.10.0|javascript
kenanbek/validator.go|main|go"

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
            echo "[$(date)] RETRY $dir_name via fallback"
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

# 扫描
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
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
    echo "[$(date)] $dir_name source deleted"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
