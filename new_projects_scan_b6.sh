#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"

# 侧重PHP（规则最成熟）+ Java + JS Web框架
PROJECTS="fuelphp/fuelphp|2.0.2|php
phalcon/cphalcon|v5.0.0|php
twigphp/Twig|v3.10.3|php
stripe/stripe-php|v14.6.0|php
guzzlehttp/streams|3.0.0|php
php-amqplib/php-amqplib|v3.2.3|php
briannesbitt/Carbon|v3.8.0|php
box-project/box|4.6.1|php
composer/composer|2.7.8|php
phpmyadmin/phpmyadmin|RELEASE_5_2_1|php
nextcloud/server|v30.0.2|php
wallabag/wallabag|2.6.5|php
julien-c/epub.js|v0.3.93|javascript
artillery/artillery|v2.0.8|javascript
pinojs/pino|v9.4.0|javascript
winstonjs/winston|v3.14.2|javascript
mozilla/pdf.js|v4.6.82|javascript
houndci/hound|v3.3.2|javascript
petamoriken/float16|v4.0.1|javascript"

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
            echo "[$(date)] DL_FAIL $dir_name"
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
        fi
        tar xzf "/tmp/${dir_name}.tar.gz" -C "$outdir" --strip-components=1
        if [ $? -ne 0 ]; then
            echo "[$(date)] EXTRACT_FAIL $dir_name"
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
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
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>/tmp/new_b6_${dir_name}.log
    rc=$?
    echo "[$(date)] $dir_name done rc=$rc"
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
